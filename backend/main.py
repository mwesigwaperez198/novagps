import hashlib
import logging
import re
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import requests as http_requests
from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator
from sqlalchemy import delete, or_, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from auth import Principal, get_current_principal, require_roles
from broadcast_auth import token_allowed
from command_registry import CommandRegistryError, execute_registered_command
from config import get_settings
from db import get_db, init_db
from eventbus import bus
from jose import jwt
from kafka_producer import publish_location_event
from models import (
    AuditLog,
    BroadcastSession,
    Consent,
    ConsentStatus,
    Device,
    ImportedUser,
    Location,
    utcnow,
)
from schemas import (
    BroadcastRequest,
    ConsentRequest,
    ConsentRevokeRequest,
    DeleteDataRequest,
    DeviceRegisterRequest,
    DeviceResponse,
    DiagnoseRequest,
    DiagnoseResponse,
    ExternalSourceType,
    ImportUsersRequest,
    LocationUpdateRequest,
)
from tool_registry import TOOL_REGISTRY, tool_available

import camera
import vpn
import ids
import osint
from worker.geofence import list_geofences_as_dicts


settings = get_settings()
app = FastAPI(
    title="NOVA GPS Tracking System",
    version="0.1.0",
    description="Consent-first GPS tracking API for vehicles, motorcycles, phones, laptops, and other devices.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Instrumentator().instrument(app).expose(app)


@app.on_event("startup")
def startup_event() -> None:
    init_db()
    import asyncio

    bus.attach_loop(asyncio.get_running_loop())


IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9_.:@-]{3,160}$")
SQL_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,119}$")
RATE_BUCKET: dict[str, list[datetime]] = {}
logger = logging.getLogger("nova.main")


def reverse_geocode(latitude: float, longitude: float) -> str | None:
    try:
        resp = http_requests.get(
            "https://nominatim.openstreetmap.org/reverse",
            params={"lat": latitude, "lon": longitude, "format": "json"},
            headers={"User-Agent": "NOVA-GPS/1.0"},
            timeout=4,
        )
        logger.info("geocode status=%s lat=%s lon=%s", resp.status_code, latitude, longitude)
        if resp.ok:
            name = resp.json().get("display_name")
            logger.info("geocode result=%s", name)
            return name
    except Exception as exc:
        logger.warning("geocode failed: %s", exc)
    return None


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    if settings.environment == "development":
        return await call_next(request)
    key = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown").split(",")[0]
    now = utcnow()
    window_start = now - timedelta(minutes=1)
    RATE_BUCKET[key] = [item for item in RATE_BUCKET.get(key, []) if item > window_start]
    if len(RATE_BUCKET[key]) >= settings.rate_limit_per_minute:
        return JSONResponse(status_code=status.HTTP_429_TOO_MANY_REQUESTS, content={"detail": "Rate limit exceeded"})
    RATE_BUCKET[key].append(now)
    return await call_next(request)


@app.post("/auth/login")
def auth_login(
    request_body: dict[str, str] = {},
) -> dict[str, str]:
    email = request_body.get("email", "")
    password = request_body.get("password", "")
    if not email or not password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email and password are required")
    settings = get_settings()
    if settings.environment == "development":
        token = jwt.encode(
            {"sub": email, "role": "admin"},
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )
        return {"access_token": token, "token_type": "bearer", "role": "admin", "email": email}
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


def hash_text(value: str | None) -> str | None:
    if value is None:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def latest_location_dict(db: Session, device_id: str) -> dict[str, Any] | None:
    location = (
        db.query(Location)
        .filter(Location.device_id == device_id)
        .order_by(Location.recorded_at.desc())
        .first()
    )
    if not location:
        return None
    return {
        "id": location.id,
        "latitude": location.latitude,
        "longitude": location.longitude,
        "altitude": location.altitude,
        "speed": location.speed,
        "heading": location.heading,
        "accuracy": location.accuracy,
        "place_name": location.place_name,
        "source": location.source,
        "recorded_at": location.recorded_at,
        "received_at": location.received_at,
    }


def device_response(db: Session, device: Device) -> DeviceResponse:
    return DeviceResponse.model_validate(
        {
            "id": device.id,
            "name": device.name,
            "email": device.email,
            "phone": device.phone,
            "identifier": device.identifier,
            "serial": device.serial,
            "imei": device.imei,
            "model": device.model,
            "manufacturer": device.manufacturer,
            "os_type": device.os_type,
            "os_version": device.os_version,
            "device_type": device.device_type,
            "is_active": device.is_active,
            "created_at": device.created_at,
            "latest_location": latest_location_dict(db, device.id),
        }
    )


def create_audit(
    db: Session,
    principal: Principal,
    action: str,
    metadata: dict[str, Any] | None = None,
    **kwargs,
) -> None:
    db.add(
        AuditLog(
            actor=principal.subject,
            role=principal.role,
            action=action,
            metadata_json=metadata or {},
            **kwargs,
        )
    )


def require_active_consent(db: Session, device: Device) -> None:
    consent = (
        db.query(Consent)
        .filter(
            Consent.device_id == device.id,
            Consent.status == ConsentStatus.active,
        )
        .order_by(Consent.consented_at.desc())
        .first()
    )
    if not consent:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Active consent is required before accepting location updates",
        )


def resolve_device(db: Session, payload: LocationUpdateRequest) -> Device:
    query = db.query(Device)
    if payload.device_id:
        device = query.filter(Device.id == payload.device_id).first()
    else:
        device = query.filter(Device.identifier == payload.identifier).first()
    if not device or not device.is_active:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return device


def safe_sql_identifier(value: str) -> str:
    if not SQL_IDENTIFIER_PATTERN.fullmatch(value):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unsafe SQL identifier: {value}")
    return value


@app.get("/health")
def health(db: Session = Depends(get_db)) -> dict[str, str]:
    db.execute(text("SELECT 1"))
    return {"status": "ok", "service": "nova-gps-api"}


@app.post("/register", response_model=DeviceResponse, status_code=status.HTTP_201_CREATED)
def register_device(
    payload: DeviceRegisterRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> DeviceResponse:
    identifier = payload.identifier or str(uuid4())
    if not IDENTIFIER_PATTERN.fullmatch(identifier):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid identifier format")
    device = Device(
        name=payload.name,
        email=str(payload.email),
        phone=payload.phone,
        identifier=identifier,
        serial=payload.serial,
        imei=payload.imei,
        model=payload.model,
        manufacturer=payload.manufacturer,
        os_type=payload.os_type,
        os_version=payload.os_version,
        device_type=payload.device_type,
    )
    db.add(device)
    try:
        db.flush()
        if payload.consent_source and payload.consent_scope:
            db.add(
                Consent(
                    device_id=device.id,
                    user_email=device.email,
                    source=payload.consent_source,
                    scope=payload.consent_scope,
                    proof_hash=hash_text(f"{device.email}:{payload.consent_source}:{payload.consent_scope}"),
                )
            )
        create_audit(db, principal, "device.register", {"device_id": device.id, "device_type": device.device_type.value})
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Identifier already registered") from exc
    db.refresh(device)
    return device_response(db, device)


@app.post("/consent", status_code=status.HTTP_201_CREATED)
def capture_consent(
    payload: ConsentRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict[str, str]:
    device = db.get(Device, payload.device_id)
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    consent = Consent(
        device_id=device.id,
        user_email=device.email,
        source=payload.source,
        scope=payload.scope,
        proof_hash=hash_text(payload.proof or f"{device.email}:{payload.source}:{payload.scope}"),
    )
    db.add(consent)
    create_audit(db, principal, "consent.capture", {"device_id": device.id, "scope": payload.scope})
    db.commit()
    return {"status": "accepted", "consent_id": consent.id}


@app.post("/consent/revoke")
def revoke_consent(
    payload: ConsentRevokeRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict[str, int]:
    result = (
        db.query(Consent)
        .filter(Consent.device_id == payload.device_id, Consent.status == ConsentStatus.active)
        .update({"status": ConsentStatus.revoked, "revoked_at": utcnow()}, synchronize_session=False)
    )
    create_audit(db, principal, "consent.revoke", {"device_id": payload.device_id, "reason": payload.reason})
    db.commit()
    return {"revoked": result}


@app.post("/update-location", status_code=status.HTTP_202_ACCEPTED)
def update_location(
    payload: LocationUpdateRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> dict[str, Any]:
    device = resolve_device(db, payload)
    require_active_consent(db, device)
    recorded_at = payload.recorded_at or utcnow()
    place_name = payload.place_name or reverse_geocode(payload.latitude, payload.longitude)
    location = Location(
        device_id=device.id,
        latitude=payload.latitude,
        longitude=payload.longitude,
        altitude=payload.altitude,
        speed=payload.speed,
        heading=payload.heading,
        accuracy=payload.accuracy,
        place_name=place_name,
        source=payload.source,
        geom=f"POINT({payload.longitude} {payload.latitude})",
        recorded_at=recorded_at,
        raw_payload=payload.raw_payload,
    )
    db.add(location)
    create_audit(db, principal, "location.ingest", {"device_id": device.id, "source": payload.source})
    db.commit()
    db.refresh(location)
    event = {
        "event": "location.updated",
        "device_id": device.id,
        "device_type": device.device_type.value,
        "latitude": location.latitude,
        "longitude": location.longitude,
        "altitude": location.altitude,
        "speed": location.speed,
        "heading": location.heading,
        "accuracy": location.accuracy,
        "place_name": place_name,
        "source": location.source,
        "recorded_at": location.recorded_at.isoformat(),
        "received_at": location.received_at.isoformat(),
    }
    kafka_published = publish_location_event(event)
    if settings.database_is_sqlite:
        from worker.geofence import check_event_against_geofences_local

        logger.info(
            "geofence matches=%s",
            check_event_against_geofences_local(device.id, payload.longitude, payload.latitude),
        )
    return {"status": "accepted", "location_id": location.id, "place_name": place_name, "kafka_published": kafka_published}


@app.post("/device/locate", status_code=status.HTTP_202_ACCEPTED)
def device_self_locate(
    identifier: str = Query(..., min_length=3, max_length=160),
    latitude: float = Query(..., ge=-90, le=90),
    longitude: float = Query(..., ge=-180, le=180),
    altitude: float | None = Query(None),
    speed: float | None = Query(None, ge=0),
    heading: float | None = Query(None, ge=0, le=360),
    accuracy: float | None = Query(None, ge=0),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    device = db.query(Device).filter(Device.identifier == identifier, Device.is_active.is_(True)).first()
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found or inactive")
    require_active_consent(db, device)
    place_name = reverse_geocode(latitude, longitude)
    location = Location(
        device_id=device.id,
        latitude=latitude,
        longitude=longitude,
        altitude=altitude,
        speed=speed,
        heading=heading,
        accuracy=accuracy,
        place_name=place_name,
        source="mobile",
        geom=f"POINT({longitude} {latitude})",
        recorded_at=utcnow(),
    )
    db.add(location)
    db.commit()
    db.refresh(location)
    return {
        "status": "accepted",
        "location_id": location.id,
        "device_name": device.name,
        "place_name": place_name,
        "latitude": latitude,
        "longitude": longitude,
    }


@app.get("/traccar", status_code=status.HTTP_202_ACCEPTED)
def traccar_compatible_update(
    id: str = Query(..., min_length=3, max_length=160),
    lat: float = Query(..., ge=-90, le=90),
    lon: float = Query(..., ge=-180, le=180),
    speed: float | None = Query(None, ge=0),
    bearing: float | None = Query(None, ge=0, le=360),
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> dict[str, Any]:
    payload = LocationUpdateRequest(
        identifier=id,
        latitude=lat,
        longitude=lon,
        speed=speed,
        heading=bearing,
        source="traccar",
        raw_payload={"id": id, "lat": lat, "lon": lon, "speed": speed, "bearing": bearing},
    )
    return update_location(payload, db, principal)


@app.get("/devices", response_model=list[DeviceResponse])
def list_devices(
    db: Session = Depends(get_db),
    _: Principal = Depends(require_roles("viewer", "operator", "admin")),
) -> list[DeviceResponse]:
    devices = db.query(Device).order_by(Device.created_at.desc()).limit(500).all()
    return [device_response(db, device) for device in devices]


@app.get("/devices/{device_id}", response_model=DeviceResponse)
def get_device(
    device_id: str,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_roles("viewer", "operator", "admin")),
) -> DeviceResponse:
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return device_response(db, device)


@app.get("/devices/{device_id}/locations")
def get_device_locations(
    device_id: str,
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
    _: Principal = Depends(require_roles("viewer", "operator", "admin")),
) -> list[dict[str, Any]]:
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    locations = (
        db.query(Location)
        .filter(Location.device_id == device_id)
        .order_by(Location.recorded_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": item.id,
            "latitude": item.latitude,
            "longitude": item.longitude,
            "altitude": item.altitude,
            "speed": item.speed,
            "heading": item.heading,
            "accuracy": item.accuracy,
            "source": item.source,
            "recorded_at": item.recorded_at,
            "received_at": item.received_at,
        }
        for item in locations
    ]


@app.get("/search", response_model=list[DeviceResponse])
def search_devices(
    q: str = Query(..., min_length=2, max_length=120),
    db: Session = Depends(get_db),
    _: Principal = Depends(require_roles("viewer", "operator", "admin")),
) -> list[DeviceResponse]:
    like = f"%{q}%"
    devices = (
        db.query(Device)
        .filter(
            or_(
                Device.name.ilike(like),
                Device.email.ilike(like),
                Device.phone.ilike(like),
                Device.identifier.ilike(like),
                Device.serial.ilike(like),
            )
        )
        .limit(100)
        .all()
    )
    return [device_response(db, device) for device in devices]


@app.get("/audit-logs")
def audit_logs(
    limit: int = Query(100, ge=1, le=1000),
    action: str | None = Query(None, max_length=120),
    db: Session = Depends(get_db),
    _: Principal = Depends(require_roles("auditor", "admin")),
) -> list[dict[str, Any]]:
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action == action)
    rows = query.order_by(AuditLog.created_at.desc()).limit(limit).all()
    return [
        {
            "id": row.id,
            "actor": row.actor,
            "role": row.role,
            "action": row.action,
            "command_id": row.command_id,
            "args_hash": row.args_hash,
            "output_hash": row.output_hash,
            "exit_code": row.exit_code,
            "started_at": row.started_at,
            "ended_at": row.ended_at,
            "metadata": row.metadata_json,
            "created_at": row.created_at,
        }
        for row in rows
    ]


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    query = parse_qs(urlparse(str(websocket.url)).query)
    channel = query.get("channel", ["map"])[0]
    token = query.get("token", [None])[0]
    if not token_allowed(token, channel):
        await websocket.close(code=4403, reason="invalid broadcast token")
        return
    await websocket.accept()
    await websocket.send_json({"event": "connected", "channel": channel})
    queue = bus.subscribe()
    import asyncio

    async def sender() -> None:
        while True:
            event = await queue.get()
            await websocket.send_json(event)

    sender_task = asyncio.create_task(sender())
    try:
        while True:
            await websocket.receive_text()
    except Exception:
        pass
    finally:
        sender_task.cancel()
        bus.unsubscribe(queue)
        try:
            await websocket.close()
        except Exception:
            pass


@app.get("/diagnose/tools")
def diagnose_tools(
    _: Principal = Depends(require_roles("viewer", "operator", "admin", "auditor")),
) -> dict[str, Any]:
    entries = []
    for command_id, spec in TOOL_REGISTRY.items():
        entries.append(
            {
                "command_id": command_id,
                "description": spec.description,
                "kind": spec.kind,
                "allowed_roles": list(spec.allowed_roles),
                "host_binaries": list(spec.host_binaries),
                "available": tool_available(spec),
            }
        )
    return {"mode": settings.sandbox_executor_mode, "tools": entries}


@app.post("/diagnose", response_model=DiagnoseResponse)
def diagnose(
    payload: DiagnoseRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("auditor", "operator", "admin")),
) -> DiagnoseResponse:
    try:
        result = execute_registered_command(payload.command_id, payload.args, principal.role)
    except CommandRegistryError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    create_audit(
        db,
        principal,
        "diagnose.execute",
        command_id=payload.command_id,
        args_hash=result["args_hash"],
        output_hash=result["output_hash"],
        exit_code=result["exit_code"],
        started_at=result["started_at"],
        ended_at=result["ended_at"],
        metadata={"mode": settings.sandbox_executor_mode},
    )
    db.commit()
    return DiagnoseResponse.model_validate(result)


@app.post("/broadcast", status_code=status.HTTP_201_CREATED)
def create_broadcast_session(
    payload: BroadcastRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict[str, Any]:
    token = secrets.token_urlsafe(32)
    session = BroadcastSession(
        channel=payload.channel,
        scope=payload.scope,
        created_by=principal.subject,
        token_hash=hash_text(token),
        expires_at=utcnow() + timedelta(minutes=payload.expires_in_minutes),
    )
    db.add(session)
    create_audit(db, principal, "broadcast.create", {"channel": payload.channel, "scope": payload.scope})
    db.commit()
    return {
        "channel": payload.channel,
        "scope": payload.scope,
        "token": token,
        "expires_at": session.expires_at,
    }


@app.post("/delete-data")
def delete_data(
    payload: DeleteDataRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("admin")),
) -> dict[str, Any]:
    query = db.query(Device)
    if payload.device_id:
        query = query.filter(Device.id == payload.device_id)
    if payload.email:
        query = query.filter(Device.email == str(payload.email))
    devices = query.all()
    device_ids = [device.id for device in devices]
    if device_ids:
        db.execute(delete(Location).where(Location.device_id.in_(device_ids)))
        db.execute(delete(Consent).where(Consent.device_id.in_(device_ids)))
        db.execute(delete(Device).where(Device.id.in_(device_ids)))
    if payload.email:
        db.execute(delete(ImportedUser).where(ImportedUser.email == str(payload.email)))
    create_audit(db, principal, "gdpr.delete_data", {"device_ids": device_ids, "email": str(payload.email) if payload.email else None, "reason": payload.reason})
    db.commit()
    return {"deleted_devices": len(device_ids), "email": payload.email}


@app.post("/admin/import-users")
def import_users(
    payload: ImportUsersRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("admin")),
) -> dict[str, Any]:
    if payload.source_type in {ExternalSourceType.firebase, ExternalSourceType.supabase}:
        create_audit(db, principal, "users.import.adapter_required", {"source": payload.source_name, "source_type": payload.source_type.value})
        db.commit()
        return {
            "status": "adapter_required",
            "message": "Firebase and Supabase imports are scaffolded; wire service credentials through Vault or your cloud secret manager.",
            "imported": 0,
        }
    if not payload.connection_url:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="connection_url is required")
    table = safe_sql_identifier(payload.table_name)
    columns = [
        safe_sql_identifier(payload.name_column),
        safe_sql_identifier(payload.email_column),
        safe_sql_identifier(payload.phone_column),
    ]
    external_id_column = safe_sql_identifier(payload.external_id_column) if payload.external_id_column else None
    select_columns = [external_id_column or "NULL AS external_id", *columns]
    source_engine_url = payload.connection_url.get_secret_value()
    if payload.source_type == ExternalSourceType.mariadb and source_engine_url.startswith("mariadb://"):
        source_engine_url = source_engine_url.replace("mariadb://", "mysql+pymysql://", 1)
    from sqlalchemy import create_engine

    source_engine = create_engine(source_engine_url, pool_pre_ping=True, future=True)
    imported = 0
    with source_engine.connect() as connection:
        rows = connection.execute(text(f"SELECT {', '.join(select_columns)} FROM {table} LIMIT :limit"), {"limit": payload.limit}).mappings()
        for row in rows:
            email = row[payload.email_column]
            if not email:
                continue
            existing = db.query(ImportedUser).filter(ImportedUser.source == payload.source_name, ImportedUser.email == email).first()
            if existing:
                continue
            db.add(
                ImportedUser(
                    source=payload.source_name,
                    external_id=str(row.get(payload.external_id_column)) if payload.external_id_column and row.get(payload.external_id_column) else None,
                    name=str(row[payload.name_column]),
                    email=str(email),
                    phone=str(row.get(payload.phone_column) or ""),
                )
            )
            imported += 1
    create_audit(db, principal, "users.import", {"source": payload.source_name, "source_type": payload.source_type.value, "imported": imported})
    db.commit()
    return {"status": "completed", "imported": imported}


@app.post("/admin/retention/run")
def run_retention(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("admin")),
) -> dict[str, Any]:
    cutoff = utcnow() - timedelta(days=settings.retention_days)
    result = db.execute(delete(Location).where(Location.recorded_at < cutoff))
    create_audit(db, principal, "retention.run", {"cutoff": cutoff.isoformat(), "deleted": result.rowcount})
    db.commit()
    return {"deleted_locations": result.rowcount, "cutoff": cutoff}


@app.get("/camera/discover")
def camera_discover(
    subnet: str = Query("192.168.1.0/24", max_length=60),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    create_audit(db := next(get_db()), principal, "camera.discover", {"subnet": subnet})
    db.close()
    return {"cameras": camera.discover_cameras(subnet)}


@app.post("/camera/screenshot")
def camera_screenshot(
    rtsp_url: str = Query(..., max_length=200),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    return camera.capture_screenshot(rtsp_url)


@app.post("/camera/record")
def camera_record(
    rtsp_url: str = Query(..., max_length=200),
    duration: int = Query(30, ge=1, le=300),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    return camera.start_recording(rtsp_url, duration)


@app.get("/vpn/status")
def vpn_status(
    principal: Principal = Depends(require_roles("viewer", "operator", "admin")),
) -> dict:
    return vpn.get_vpn_status()


@app.post("/vpn/connect")
def vpn_connect(
    config_path: str = Query(..., max_length=200),
    vpn_type: str = Query("wireguard", max_length=20),
    principal: Principal = Depends(require_roles("admin")),
) -> dict:
    return vpn.connect_vpn(config_path, vpn_type)


@app.post("/vpn/disconnect")
def vpn_disconnect(
    interface: str = Query(..., max_length=30),
    vpn_type: str = Query("wireguard", max_length=20),
    principal: Principal = Depends(require_roles("admin")),
) -> dict:
    return vpn.disconnect_vpn(interface, vpn_type)


@app.get("/ids/status")
def ids_status(
    principal: Principal = Depends(require_roles("viewer", "operator", "admin")),
) -> dict:
    return ids.get_ids_status()


@app.get("/ids/alerts")
def ids_alerts(
    limit: int = Query(50, ge=1, le=500),
    principal: Principal = Depends(require_roles("auditor", "operator", "admin")),
) -> dict:
    return {"alerts": ids.get_recent_alerts(limit)}


@app.post("/ids/update-rules")
def ids_update_rules(
    principal: Principal = Depends(require_roles("admin")),
) -> dict:
    return ids.update_rules()


@app.get("/osint/whois")
def osint_whois(
    domain: str = Query(..., max_length=120),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    return osint.whois_lookup(domain)


@app.get("/osint/dns-brute")
def osint_dns_brute(
    domain: str = Query(..., max_length=120),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    return osint.dns_bruteforce(domain)


@app.get("/osint/reverse-dns")
def osint_reverse_dns(
    ip: str = Query(..., max_length=45),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    return osint.reverse_dns(ip)


@app.get("/osint/http-headers")
def osint_http_headers(
    url: str = Query(..., max_length=500),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    return osint.http_headers(url)


@app.get("/osint/nikto")
def osint_nikto(
    target: str = Query(..., max_length=120),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    return osint.scan_nikto(target)


@app.get("/osint/sqlmap")
def osint_sqlmap(
    url: str = Query(..., max_length=500),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    return osint.scan_sqlmap(url)


@app.get("/osint/theharvester")
def osint_theharvester(
    domain: str = Query(..., max_length=120),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    return osint.scan_theharvester(domain)


@app.get("/osint/phone-lookup")
def osint_phone_lookup(
    phone: str = Query(..., max_length=30),
    country_code: str = Query("", max_length=5),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    return osint.phone_lookup(phone, country_code)


@app.get("/osint/email-lookup")
def osint_email_lookup(
    email: str = Query(..., max_length=120),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    return osint.email_lookup(email)


@app.get("/osint/whatweb")
def osint_whatweb(
    url: str = Query(..., max_length=500),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    return osint.scan_whatweb(url)


@app.get("/osint/wpscan")
def osint_wpscan(
    url: str = Query(..., max_length=500),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    return osint.scan_wpscan(url)


@app.get("/osint/dirb")
def osint_dirb(
    url: str = Query(..., max_length=500),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    return osint.scan_dirb(url)


@app.get("/osint/sublist3r")
def osint_sublist3r(
    domain: str = Query(..., max_length=120),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    return osint.scan_sublist3r(domain)


@app.get("/pentest/vuln-scan")
def pentest_vuln_scan(
    target: str = Query(..., max_length=120),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    return osint.scan_nmap_vuln(target)


@app.get("/pentest/auth-scan")
def pentest_auth_scan(
    target: str = Query(..., max_length=120),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    return osint.scan_nmap_auth(target)


@app.post("/tool/run")
def run_tool(
    command_id: str = Query(..., max_length=120),
    target: str = Query("", max_length=200),
    url: str = Query("", max_length=500),
    domain: str = Query("", max_length=120),
    path: str = Query("", max_length=240),
    interface: str = Query("", max_length=32),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    args = {}
    if target:
        args["target"] = target
    if url:
        args["url"] = url
    if domain:
        args["domain"] = domain
    if path:
        args["path"] = path
    if interface:
        args["interface"] = interface
    create_audit(db := next(get_db()), principal, "tool.run", {"command_id": command_id, "args": args})
    db.close()
    return osint.run_tool_command(command_id, args)


@app.get("/geofences")
def geofences_list(
    principal: Principal = Depends(require_roles("viewer", "operator", "admin")),
) -> dict:
    return {"geofences": list_geofences_as_dicts()}


_frontend_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if _frontend_dist.is_dir():
    from fastapi.staticfiles import StaticFiles

    app.mount("/", StaticFiles(directory=str(_frontend_dist), html=True), name="frontend")

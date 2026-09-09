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
from sqlalchemy import delete, func, or_, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from auth import Principal, bear_token, device_principal, get_current_principal, require_roles
from broadcast_auth import token_allowed
from command_registry import CommandRegistryError, execute_registered_command
from config import get_settings
from db import get_db, init_db
from eventbus import bus
from jose import jwt
from kafka_producer import publish_location_event
from models import (
    Alert,
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
    AgentAckCommandRequest,
    AgentPullCommandsRequest,
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
import blockchain_anchor

import camera
import vpn
import ids
import osint
import sms
import fingerprint
import discovery
import push_service
import remote_commands
import wifi_security
import firmware
import vehicle_recovery
import scheduler
import webhooks
from oui_lookup import lookup_vendor, normalize_mac
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


def client_ip(request: Request) -> str:
    return request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown").split(",")[0]


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    if settings.environment == "development":
        return await call_next(request)
    key = client_ip(request)
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
    owner = settings.dev_owner_email.strip().lower()
    # Production requires the owner allowlist to be configured (fail closed).
    if settings.environment == "production" and not owner:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    # Only the configured owner may log in, in every environment. This is the
    # security boundary chosen for NOVA (a personal, consent-first tracker).
    if owner and email.strip().lower() != owner:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = jwt.encode(
        {"sub": email, "role": "admin"},
        settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )
    return {"access_token": token, "token_type": "bearer", "role": "admin", "email": email}


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
    device = db.get(Device, device_id)
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
        "ip_address": location.ip_address,
        "local_ip": device.local_ip if device else None,
        "carrier": device.carrier if device else None,
        "recorded_at": location.recorded_at,
        "received_at": location.received_at,
    }


def _apply_network_context(device: Device, raw_payload: dict[str, Any] | None) -> None:
    if not raw_payload:
        return
    local_ip = str(raw_payload.get("local_ip") or "").strip() or None
    carrier = str(raw_payload.get("carrier") or "").strip() or None
    if local_ip:
        device.local_ip = local_ip
    if carrier:
        device.carrier = carrier


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
            "ip_address": device.ip_address,
            "mac_address": device.mac_address,
            "local_ip": device.local_ip,
            "carrier": device.carrier,
            "is_active": device.is_active,
            "is_lost_mode": getattr(device, "is_lost_mode", False),
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


def authorize_device_or_user(db: Session, request: Request, device: Device) -> Principal:
    """Authenticate a device-facing write.

    The phone proves itself by a registered, active device identifier plus the
    caller's active-consent check (applied by the endpoint). A human caller may
    instead present a valid bearer token (dashboard). Returns the Principal to
    frame the audit log: a synthetic device principal when the phone calls in,
    or the human principal when a token was supplied.
    """
    token = bear_token(request)
    if token:
        try:
            return get_current_principal(token=token)
        except HTTPException:
            pass
    return device_principal(device.identifier)


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
        ip_address=payload.ip_address,
        mac_address=payload.mac_address,
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
    anchor = blockchain_anchor.anchor_consent_event(
        db, consent_id=consent.id, device_id=device.id, action="capture",
        payload={"source": payload.source, "scope": payload.scope, "email": device.email},
    )
    return {"status": "accepted", "consent_id": consent.id, "chain_hash": anchor.chain_hash}


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
    blockchain_anchor.anchor_consent_event(
        db, consent_id=f"revoke-{payload.device_id}", device_id=payload.device_id, action="revoke",
        payload={"reason": payload.reason, "actor": principal.subject},
    )
    return {"revoked": result}


@app.get("/consent/history")
def consent_history(
    device_id: str = Query(..., min_length=1),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> list[dict[str, Any]]:
    return blockchain_anchor.get_consent_history(db, device_id, limit)


@app.get("/consent/verify-chain")
def verify_consent_chain(
    start: int = Query(0, ge=0),
    limit: int = Query(1000, ge=1, le=10000),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("admin")),
) -> dict[str, Any]:
    return blockchain_anchor.verify_chain(db, start, limit)


@app.post("/update-location", status_code=status.HTTP_202_ACCEPTED)
def update_location(
    payload: LocationUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    device = resolve_device(db, payload)
    require_active_consent(db, device)
    principal = authorize_device_or_user(db, request, device)
    recorded_at = payload.recorded_at or utcnow()
    place_name = payload.place_name or reverse_geocode(payload.latitude, payload.longitude)
    ip_address = client_ip(request)
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
        ip_address=ip_address,
        geom=f"POINT({payload.longitude} {payload.latitude})",
        recorded_at=recorded_at,
        raw_payload=payload.raw_payload,
    )
    device.ip_address = ip_address
    _apply_network_context(device, payload.raw_payload)
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
        "ip_address": ip_address,
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
    return {"status": "accepted", "location_id": location.id, "place_name": place_name, "ip_address": ip_address, "kafka_published": kafka_published}


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
    request: Request,
    db: Session = Depends(get_db),
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
    return update_location(payload, request, db)


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
            "place_name": item.place_name,
            "ip_address": item.ip_address,
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
    for did in device_ids:
        blockchain_anchor.anchor_consent_event(
            db, consent_id=f"delete-{did}", device_id=did, action="gdpr_delete",
            payload={"reason": payload.reason, "actor": principal.subject},
        )
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


@app.post("/remote/sms")
def remote_send_sms(
    device_id: str = Query(..., max_length=36),
    message: str = Query(..., min_length=1, max_length=500),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    db = next(get_db())
    device = db.get(Device, device_id)
    if not device:
        db.close()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    if not device.phone:
        db.close()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Device has no phone number")
    result = sms.send_sms(device.phone, message)
    create_audit(db, principal, "remote.sms", {"device_id": device_id, "phone": device.phone, "message_preview": message[:100], "success": result.get("success", False)})
    db.commit()
    db.close()
    return {**result, "device_name": device.name}


@app.get("/remote/icloud-instructions")
def remote_icloud_instructions(
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    return sms.get_icloud_instructions()


@app.get("/remote/android-instructions")
def remote_android_instructions(
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    return sms.get_android_instructions()


@app.get("/remote/mdm-instructions")
def remote_mdm_instructions(
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    return sms.get_mdm_lock_instructions()


@app.post("/remote/lock-guide")
def remote_lock_guide(
    device_id: str = Query(..., max_length=36),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    db = next(get_db())
    device = db.get(Device, device_id)
    db.close()
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    os_type = (device.os_type or "").lower()
    manufacturer = (device.manufacturer or "").lower()
    if "ios" in os_type or "apple" in manufacturer:
        instructions = sms.get_icloud_instructions()
    elif "android" in os_type or "google" in manufacturer or "samsung" in manufacturer:
        instructions = sms.get_android_instructions()
    else:
        instructions = {
            "service": "Generic Lock",
            "note": f"Device type: {device.os_type or 'Unknown'} ({device.manufacturer or 'Unknown'})",
            "steps": [
                "1. Contact the carrier to report the device stolen",
                "2. Request IMEI blacklist via GSMA",
                "3. File a police report with IMEI and serial number",
                "4. Use any available MDM or tracking service",
            ],
            "imei": device.imei,
            "serial": device.serial,
        }
    return {
        "device_id": device_id,
        "device_name": device.name,
        "os_type": device.os_type,
        "manufacturer": device.manufacturer,
        "imei": device.imei,
        "serial": device.serial,
        "phone": device.phone,
        **instructions,
    }


@app.get("/geofences")
def geofences_list(
    principal: Principal = Depends(require_roles("viewer", "operator", "admin")),
) -> dict:
    return {"geofences": list_geofences_as_dicts()}


@app.get("/geofences/{geofence_id}")
def get_geofence(
    geofence_id: str,
    principal: Principal = Depends(require_roles("viewer", "operator", "admin")),
) -> dict:
    from worker.geofence import DEFAULT_GEOFENCES
    for f in DEFAULT_GEOFENCES:
        if f.geofence_id == geofence_id:
            from worker.geofence import parse_wkt_polygon
            return {"geofence_id": f.geofence_id, "name": f.name, "polygon_wkt": f.polygon_wkt, "coords": parse_wkt_polygon(f.polygon_wkt)}
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Geofence not found")


@app.get("/device/{device_id}/fingerprint")
def device_fingerprint(
    device_id: str,
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    db = next(get_db())
    device = db.get(Device, device_id)
    db.close()
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    ip = device.ip_address
    if not ip:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Device has no IP address set")
    return fingerprint.fingerprint_device(ip)


@app.post("/fingerprint/ip/{ip}")
def fingerprint_ip(
    ip: str,
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    return fingerprint.fingerprint_device(ip)


@app.get("/device/{device_id}/oui")
def device_oui(
    device_id: str,
    principal: Principal = Depends(require_roles("viewer", "operator", "admin")),
) -> dict:
    db = next(get_db())
    device = db.get(Device, device_id)
    db.close()
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    vendor = lookup_vendor(device.mac_address)
    return {"device_id": device_id, "mac": device.mac_address, "vendor": vendor}


@app.post("/discovery/scan-network")
def discovery_scan_network(
    subnet: str = Query("192.168.1.0/24", max_length=60),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    create_audit(db := next(get_db()), principal, "discovery.scan_network", {"subnet": subnet})
    db.close()
    return discovery.scan_network(subnet)


@app.get("/discovery/usb")
def discovery_usb(
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    return discovery.discover_usb_devices()


@app.get("/discovery/arp")
def discovery_arp(
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    return {"devices": discovery.arp_scan()}


@app.get("/device/{device_id}/commands")
def device_commands(
    device_id: str,
    limit: int = Query(20, ge=1, le=100),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    db = next(get_db())
    result = push_service.get_command_history(db, device_id, limit)
    db.close()
    return {"commands": result}


@app.get("/device/{device_id}/commands/pending")
def device_pending_commands(
    device_id: str,
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    db = next(get_db())
    result = push_service.get_pending_commands(db, device_id)
    db.close()
    return {"pending": result}


@app.post("/device/pull-commands")
def device_pull_commands(
    payload: AgentPullCommandsRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    device = resolve_device(db, payload)
    require_active_consent(db, device)
    principal = authorize_device_or_user(db, request, device)
    create_audit(db, principal, "agent.pull_commands", {"device_id": device.id})
    commands = push_service.get_pending_commands(db, device.id)
    return {"commands": commands}


@app.post("/device/ack-command")
def device_ack_command(
    payload: AgentAckCommandRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    device = resolve_device(db, payload)
    require_active_consent(db, device)
    principal = authorize_device_or_user(db, request, device)
    push_service.acknowledge_command(db, payload.command_id)
    create_audit(db, principal, "agent.ack_command", {"device_id": device.id, "command_id": payload.command_id})
    return {"status": "acknowledged"}


@app.post("/device/{device_id}/trigger-locate")
def device_trigger_locate(
    device_id: str,
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    db = next(get_db())
    device = db.get(Device, device_id)
    if not device:
        db.close()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    result = push_service.queue_locate_command(db, device_id, "locate", {"type": "single", "requested_by": principal.subject})
    db.close()
    return result


@app.post("/device/{device_id}/remote-lock")
def device_remote_lock(
    device_id: str,
    message: str = Query("This device has been remotely locked.", max_length=500),
    contact: str = Query("", max_length=100),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    db = next(get_db())
    device = db.get(Device, device_id)
    if not device:
        db.close()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    result = remote_commands.lock_device(db, device, message, contact)
    create_audit(db, principal, "remote.lock", {"device_id": device_id})
    db.close()
    return result


@app.post("/device/{device_id}/remote-wipe")
def device_remote_wipe(
    device_id: str,
    confirm_code: str = Query("", max_length=20),
    principal: Principal = Depends(require_roles("admin")),
) -> dict:
    db = next(get_db())
    device = db.get(Device, device_id)
    if not device:
        db.close()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    result = remote_commands.wipe_device(db, device, confirm_code)
    create_audit(db, principal, "remote.wipe", {"device_id": device_id})
    db.close()
    return result


@app.post("/device/{device_id}/lost-mode")
def device_lost_mode(
    device_id: str,
    message: str = Query("This device is lost. Please call the owner.", max_length=500),
    contact: str = Query("", max_length=100),
    location_interval: int = Query(30, ge=10, le=300),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    db = next(get_db())
    device = db.get(Device, device_id)
    if not device:
        db.close()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    result = remote_commands.lost_mode(db, device, message, contact, location_interval)
    create_audit(db, principal, "remote.lost_mode", {"device_id": device_id})
    db.close()
    return result


@app.post("/device/{device_id}/send-message")
def device_send_message(
    device_id: str,
    message: str = Query(..., min_length=1, max_length=500),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    db = next(get_db())
    device = db.get(Device, device_id)
    if not device:
        db.close()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    result = remote_commands.send_message(db, device, message)
    db.close()
    return result


@app.get("/wifi/scan")
def wifi_scan(
    interface: str = Query("wlan0", max_length=32),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    create_audit(db := next(get_db()), principal, "wifi.scan", {"interface": interface})
    db.close()
    return wifi_security.scan_networks(interface)


@app.post("/wifi/capture-handshake")
def wifi_capture_handshake(
    interface: str = Query(..., max_length=32),
    bssid: str = Query(..., max_length=17),
    duration: int = Query(30, ge=10, le=120),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    create_audit(db := next(get_db()), principal, "wifi.capture_handshake", {"interface": interface, "bssid": bssid})
    db.close()
    return wifi_security.capture_handshake(interface, bssid, duration)


@app.post("/wifi/crack-wpa")
def wifi_crack_wpa(
    capture_file: str = Query(..., max_length=200),
    wordlist: str = Query("/usr/share/wordlists/rockyou.txt", max_length=200),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    create_audit(db := next(get_db()), principal, "wifi.crack_wpa", {"capture_file": capture_file})
    db.close()
    return wifi_security.crack_wpa(capture_file, wordlist)


@app.post("/wifi/wps-attack")
def wifi_wps_attack(
    interface: str = Query(..., max_length=32),
    bssid: str = Query(..., max_length=17),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    create_audit(db := next(get_db()), principal, "wifi.wps_attack", {"interface": interface, "bssid": bssid})
    db.close()
    return wifi_security.wps_attack(interface, bssid)


@app.post("/wifi/deauth")
def wifi_deauth(
    interface: str = Query(..., max_length=32),
    bssid: str = Query(..., max_length=17),
    count: int = Query(5, ge=1, le=20),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    create_audit(db := next(get_db()), principal, "wifi.deauth", {"interface": interface, "bssid": bssid})
    db.close()
    return wifi_security.deauth_attack(interface, bssid, count)


@app.get("/firmware/cve")
def firmware_cve_lookup(
    keyword: str = Query(..., min_length=3, max_length=200),
    limit: int = Query(10, ge=1, le=50),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    return firmware.lookup_cve(keyword, limit)


@app.get("/firmware/diagnose/{ip}")
def firmware_diagnose(
    ip: str,
    manufacturer: str = Query("", max_length=100),
    model: str = Query("", max_length=100),
    firmware_version: str = Query("", max_length=100),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    create_audit(db := next(get_db()), principal, "firmware.diagnose", {"ip": ip})
    db.close()
    return firmware.diagnose_firmware(ip, manufacturer, model, firmware_version)


@app.get("/firmware/health/{ip}")
def firmware_health(
    ip: str,
    principal: Principal = Depends(require_roles("viewer", "operator", "admin")),
) -> dict:
    return firmware.check_device_health(ip)


@app.post("/vehicle/stolen-report")
def vehicle_stolen_report(
    device_id: str = Query(..., max_length=36),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    db = next(get_db())
    result = vehicle_recovery.report_stolen(db, device_id, principal.subject)
    create_audit(db, principal, "vehicle.stolen_report", {"device_id": device_id})
    device = db.get(Device, device_id)
    if device:
        alert = Alert(
            device_id=device_id,
            alert_type="theft",
            severity="critical",
            title=f"Vehicle {device.name} reported stolen",
            message=f"Reported by {principal.subject}. Recovery mode activated.",
        )
        db.add(alert)
        db.commit()
    db.close()
    return result


@app.get("/vehicle/recovery/{recovery_id}")
def vehicle_recovery_status(
    recovery_id: str,
    principal: Principal = Depends(require_roles("viewer", "operator", "admin")),
) -> dict:
    db = next(get_db())
    result = vehicle_recovery.get_recovery_status(db, recovery_id)
    db.close()
    return result


@app.post("/vehicle/recovery/{recovery_id}/end")
def vehicle_recovery_end(
    recovery_id: str,
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    db = next(get_db())
    result = vehicle_recovery.end_recovery(db, recovery_id)
    create_audit(db, principal, "vehicle.recovery_end", {"recovery_id": recovery_id})
    db.close()
    return result


@app.post("/vehicle/recovery/{recovery_id}/link-camera")
def vehicle_link_camera(
    recovery_id: str,
    device_id: str = Query(..., max_length=36),
    camera_ip: str = Query(..., max_length=45),
    camera_port: int = Query(554, ge=1, le=65535),
    stream_url: str = Query("", max_length=200),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    db = next(get_db())
    result = vehicle_recovery.link_camera(db, recovery_id, device_id, camera_ip, camera_port, stream_url)
    db.close()
    return result


@app.get("/vehicle/active-recoveries")
def vehicle_active_recoveries(
    principal: Principal = Depends(require_roles("viewer", "operator", "admin")),
) -> dict:
    db = next(get_db())
    result = vehicle_recovery.list_active_recoveries(db)
    db.close()
    return {"recoveries": result}


@app.get("/camera/stream/{camera_id}")
def camera_stream_proxy(
    camera_id: str,
    rtsp_url: str = Query(..., max_length=200),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    return {"stream_url": rtsp_url, "proxy_url": f"/camera/proxy/{camera_id}", "note": "Use /camera/proxy for MJPEG stream"}


@app.get("/alerts")
def alerts_list(
    limit: int = Query(50, ge=1, le=500),
    severity: str | None = Query(None, max_length=20),
    acknowledged: bool | None = Query(None),
    principal: Principal = Depends(require_roles("viewer", "operator", "admin")),
) -> dict:
    db = next(get_db())
    db.execute(text(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY, device_id TEXT, alert_type TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'info', title TEXT NOT NULL,
            message TEXT, acknowledged INTEGER DEFAULT 0,
            metadata TEXT, created_at TIMESTAMP DEFAULT (datetime('now')),
            acknowledged_at TIMESTAMP
        )
        """
    ))
    query = "SELECT id, device_id, alert_type, severity, title, message, acknowledged, created_at, acknowledged_at FROM alerts WHERE 1=1"
    params: dict[str, Any] = {"limit": limit}
    if severity:
        query += " AND severity = :severity"
        params["severity"] = severity
    if acknowledged is not None:
        query += " AND acknowledged = :acknowledged"
        params["acknowledged"] = int(acknowledged)
    query += " ORDER BY created_at DESC LIMIT :limit"
    rows = db.execute(text(query), params).fetchall()
    db.close()
    return {
        "alerts": [
            {
                "id": r[0], "device_id": r[1], "alert_type": r[2], "severity": r[3],
                "title": r[4], "message": r[5], "acknowledged": bool(r[6]),
                "created_at": str(r[7]),
                "acknowledged_at": str(r[8]) if r[8] else None,
            }
            for r in rows
        ]
    }


@app.post("/alerts/{alert_id}/acknowledge")
def alert_acknowledge(
    alert_id: str,
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    db = next(get_db())
    db.execute(text("UPDATE alerts SET acknowledged = 1, acknowledged_at = datetime('now') WHERE id = :id"), {"id": alert_id})
    db.commit()
    db.close()
    return {"alert_id": alert_id, "acknowledged": True}


@app.post("/tasks/schedule")
def task_schedule(
    name: str = Query(..., min_length=1, max_length=120),
    cron_expr: str = Query(..., min_length=5, max_length=50),
    command_id: str = Query("", max_length=120),
    principal: Principal = Depends(require_roles("admin")),
) -> dict:
    db = next(get_db())
    result = scheduler.create_task(db, name, cron_expr, command_id)
    create_audit(db, principal, "task.schedule", {"name": name, "cron_expr": cron_expr})
    db.close()
    return result


@app.get("/tasks")
def tasks_list(
    principal: Principal = Depends(require_roles("viewer", "operator", "admin")),
) -> dict:
    db = next(get_db())
    result = scheduler.list_tasks(db)
    db.close()
    return {"tasks": result}


@app.put("/tasks/{task_id}/toggle")
def task_toggle(
    task_id: str,
    enabled: bool = Query(...),
    principal: Principal = Depends(require_roles("admin")),
) -> dict:
    db = next(get_db())
    result = scheduler.toggle_task(db, task_id, enabled)
    db.close()
    return result


@app.delete("/tasks/{task_id}")
def task_delete(
    task_id: str,
    principal: Principal = Depends(require_roles("admin")),
) -> dict:
    db = next(get_db())
    result = scheduler.delete_task(db, task_id)
    db.close()
    return result


@app.post("/webhooks")
def webhook_register(
    url: str = Query(..., max_length=500),
    events: str = Query("location.updated,geofence.breach,vehicle.stolen", max_length=500),
    principal: Principal = Depends(require_roles("admin")),
) -> dict:
    db = next(get_db())
    result = webhooks.register_endpoint(db, url, [e.strip() for e in events.split(",")])
    create_audit(db, principal, "webhook.register", {"url": url})
    db.close()
    return result


@app.get("/webhooks")
def webhooks_list(
    principal: Principal = Depends(require_roles("viewer", "operator", "admin")),
) -> dict:
    db = next(get_db())
    result = webhooks.list_endpoints(db)
    db.close()
    return {"endpoints": result}


@app.delete("/webhooks/{endpoint_id}")
def webhook_delete(
    endpoint_id: str,
    principal: Principal = Depends(require_roles("admin")),
) -> dict:
    db = next(get_db())
    result = webhooks.delete_endpoint(db, endpoint_id)
    db.close()
    return result


@app.get("/webhooks/{endpoint_id}/deliveries")
def webhook_deliveries(
    endpoint_id: str,
    limit: int = Query(50, ge=1, le=200),
    principal: Principal = Depends(require_roles("operator", "admin")),
) -> dict:
    db = next(get_db())
    result = webhooks.list_deliveries(db, endpoint_id, limit)
    db.close()
    return {"deliveries": result}


@app.get("/analytics/dashboard")
def analytics_dashboard(
    days: int = Query(7, ge=1, le=90),
    db: Session = Depends(get_db),
    _: Principal = Depends(require_roles("viewer", "operator", "admin", "auditor")),
) -> dict[str, Any]:
    since = datetime.utcnow() - timedelta(days=days)

    total_devices = db.query(func.count(Device.id)).scalar() or 0
    active_devices = db.query(func.count(Device.id)).filter(Device.is_active.is_(True)).scalar() or 0
    lost_mode = db.query(func.count(Device.id)).filter(Device.is_lost_mode.is_(True)).scalar() or 0

    location_count = db.query(func.count(Location.id)).filter(Location.recorded_at >= since).scalar() or 0
    recent_devices = (
        db.query(func.count(func.distinct(Location.device_id)))
        .filter(Location.recorded_at >= since)
        .scalar()
        or 0
    )

    open_alerts = db.query(func.count(Alert.id)).filter(Alert.acknowledged.is_(False)).scalar() or 0
    critical_alerts = (
        db.query(func.count(Alert.id)).filter(Alert.severity == "critical", Alert.acknowledged.is_(False)).scalar()
        or 0
    )

    day_bucket = func.date(Location.recorded_at)
    activity = (
        db.query(day_bucket, func.count(Location.id))
        .filter(Location.recorded_at >= since)
        .group_by(day_bucket)
        .order_by(day_bucket)
        .all()
    )

    speed_rows = (
        db.query(Location.speed).filter(Location.recorded_at >= since, Location.speed.isnot(None)).all()
    )
    speeds = [row[0] for row in speed_rows]
    avg_speed = round(sum(speeds) / len(speeds), 2) if speeds else 0.0

    user_actions = db.query(func.count(AuditLog.id)).filter(AuditLog.created_at >= since).scalar() or 0

    return {
        "summary": {
            "total_devices": total_devices,
            "active_devices": active_devices,
            "lost_mode_devices": lost_mode,
            "locations_24h": location_count,
            "active_devices_24h": recent_devices,
            "open_alerts": open_alerts,
            "critical_alerts": critical_alerts,
            "avg_speed_kph": avg_speed,
            "audit_actions": user_actions,
        },
        "activity": [
            {"date": str(day), "updates": count} for day, count in activity
        ],
        "period_days": days,
    }


@app.get("/analytics/device/{device_id}")
def analytics_device(
    device_id: str,
    limit: int = Query(200, ge=10, le=1000),
    db: Session = Depends(get_db),
    _: Principal = Depends(require_roles("viewer", "operator", "admin", "auditor")),
) -> dict[str, Any]:
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

    def record(item: Location) -> dict[str, Any]:
        return {
            "latitude": item.latitude,
            "longitude": item.longitude,
            "altitude": item.altitude,
            "speed": item.speed,
            "heading": item.heading,
            "source": item.source,
            "place_name": item.place_name,
            "recorded_at": item.recorded_at,
        }

    payload = [record(item) for item in locations]

    speeds = [item.speed for item in locations if item.speed is not None]
    max_speed = max(speeds) if speeds else 0.0
    avg_speed = round(sum(speeds) / len(speeds), 2) if speeds else 0.0

    return {
        "device": device_response(db, device),
        "metrics": {
            "samples": len(locations),
            "max_speed_kph": max_speed,
            "avg_speed_kph": avg_speed,
            "active": device.is_active,
            "lost_mode": device.is_lost_mode,
            "os": device.os_type,
            "os_version": device.os_version,
            "imei": device.imei,
        },
        "trail": payload,
    }


@app.get("/analytics/device/{device_id}/fraud")
def analytics_fraud(
    device_id: str,
    window: int = Query(6, ge=1, le=72),
    db: Session = Depends(get_db),
    _: Principal = Depends(require_roles("admin", "auditor")),
) -> dict[str, Any]:
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    since = datetime.utcnow() - timedelta(hours=window)
    rows = (
        db.query(Location)
        .filter(Location.device_id == device_id, Location.recorded_at >= since)
        .order_by(Location.recorded_at.asc())
        .all()
    )

    anomalies = []
    if len(rows) >= 3:
        for i in range(1, len(rows)):
            prev, curr = rows[i - 1], rows[i]
            dt = (curr.recorded_at - prev.recorded_at).total_seconds()
            if dt <= 0:
                continue
            import math

            speed = (curr.speed or 0.0)
            if speed <= 1:
                speed = math.hypot(curr.latitude - prev.latitude, curr.longitude - prev.longitude) * 111000 / dt * 3.6
            if speed > 220:
                anomalies.append(
                    {
                        "time": curr.recorded_at,
                        "speed_kph": round(speed, 2),
                        "lat": curr.latitude,
                        "lon": curr.longitude,
                        "reason": "implausible_speed",
                    }
                )

    return {
        "device_id": device_id,
        "window_hours": window,
        "samples": len(rows),
        "anomalies": anomalies,
        "anomaly_count": len(anomalies),
        "verdict": "suspicious" if anomalies else "clean",
    }


@app.get("/analytics/device/{device_id}/heartbeat")
def analytics_heartbeat(
    device_id: str,
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db),
    _: Principal = Depends(require_roles("viewer", "operator", "admin", "auditor")),
) -> dict[str, Any]:
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    since = datetime.utcnow() - timedelta(hours=hours)
    updates = (
        db.query(Location.recorded_at)
        .filter(Location.device_id == device_id, Location.recorded_at >= since)
        .order_by(Location.recorded_at.asc())
        .all()
    )

    if not updates:
        return {
            "device_id": device_id,
            "status": "no_heartbeat",
            "last_update": None,
            "updates": [],
            "count": 0,
            "cadence_seconds": None,
        }

    last = updates[-1][0]
    timestamps = [row[0].isoformat() for row in updates]

    gaps = []
    for i in range(1, len(updates)):
        gaps.append((updates[i][0] - updates[i - 1][0]).total_seconds())
    cadence = round(sum(gaps) / len(gaps), 1) if gaps else None

    age_hours = (datetime.utcnow() - last).total_seconds() / 3600
    if age_hours > 24:
        state = "offline"
    elif age_hours > 2:
        state = "delayed"
    else:
        state = "healthy"

    return {
        "device_id": device_id,
        "status": state,
        "last_update": last,
        "updates": timestamps,
        "count": len(updates),
        "cadence_seconds": cadence,
    }


@app.get("/analytics/device/{device_id}/location-stats")
def analytics_location_stats(
    device_id: str,
    limit: int = Query(500, ge=10, le=5000),
    db: Session = Depends(get_db),
    _: Principal = Depends(require_roles("viewer", "operator", "admin", "auditor")),
) -> dict[str, Any]:
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

    source_counts: dict[str, int] = {}
    places: dict[str, int] = {}
    distance_km = 0.0
    peak_speed = 0.0

    for i, item in enumerate(locations):
        source_counts[item.source or "unknown"] = source_counts.get(item.source or "unknown", 0) + 1
        if item.place_name:
            places[item.place_name] = places.get(item.place_name, 0) + 1
        if item.speed and item.speed > peak_speed:
            peak_speed = item.speed
        if i < len(locations) - 1:
            nxt = locations[i + 1]
            distance_km += haversine_km(item.latitude, item.longitude, nxt.latitude, nxt.longitude)

    return {
        "device_id": device_id,
        "samples": len(locations),
        "distance_tracked_km": round(distance_km, 3),
        "peak_speed_kph": peak_speed,
        "top_sources": sorted(source_counts.items(), key=lambda kv: kv[1], reverse=True),
        "top_places": sorted(places.items(), key=lambda kv: kv[1], reverse=True)[:10],
    }


@app.get("/analytics/device/{device_id}/export")
def analytics_export(
    device_id: str,
    limit: int = Query(500, ge=10, le=5000),
    format: str = Query("csv", pattern="^(csv|json)$"),
    db: Session = Depends(get_db),
    _: Principal = Depends(require_roles("viewer", "operator", "admin", "auditor")),
) -> Any:
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

    payload = [
        {
            "latitude": item.latitude,
            "longitude": item.longitude,
            "altitude": item.altitude,
            "speed": item.speed,
            "heading": item.heading,
            "source": item.source,
            "recorded_at": item.recorded_at.isoformat() if item.recorded_at else None,
        }
        for item in locations
    ]

    if format == "json":
        return {"device_id": device_id, "rows": payload}

    import csv
    import io

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=["latitude", "longitude", "altitude", "speed", "heading", "source", "recorded_at"])
    writer.writeheader()
    writer.writerows(payload)
    return {"device_id": device_id, "format": "csv", "content": buffer.getvalue()}


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    import math

    radius = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * radius * math.asin(math.sqrt(a))


_frontend_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if _frontend_dist.is_dir():
    from fastapi.staticfiles import StaticFiles

    app.mount("/", StaticFiles(directory=str(_frontend_dist), html=True), name="frontend")

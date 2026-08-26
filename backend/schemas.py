from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, EmailStr, Field, SecretStr, model_validator

from models import DeviceType


class DeviceRegisterRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=160)
    email: EmailStr
    phone: str = Field(..., min_length=3, max_length=64)
    identifier: str | None = Field(None, min_length=3, max_length=160)
    serial: str | None = Field(None, max_length=160)
    imei: str | None = Field(None, max_length=32)
    model: str | None = Field(None, max_length=160)
    device_type: DeviceType = DeviceType.other
    consent_source: str | None = Field(None, max_length=120)
    consent_scope: str | None = Field(None, max_length=1000)


class ConsentRequest(BaseModel):
    device_id: str
    source: str = Field(..., min_length=1, max_length=120)
    scope: str = Field(..., min_length=1, max_length=1000)
    proof: str | None = Field(None, max_length=2000)


class ConsentRevokeRequest(BaseModel):
    device_id: str
    reason: str | None = Field(None, max_length=500)


class LocationUpdateRequest(BaseModel):
    device_id: str | None = None
    identifier: str | None = None
    latitude: float = Field(..., ge=-90, le=90)
    longitude: float = Field(..., ge=-180, le=180)
    altitude: float | None = None
    speed: float | None = Field(None, ge=0)
    heading: float | None = Field(None, ge=0, le=360)
    accuracy: float | None = Field(None, ge=0)
    place_name: str | None = Field(None, max_length=500)
    source: Literal["http", "mobile", "traccar", "iot", "mqtt", "lorawan", "lte-m", "nb-iot"] = "http"
    recorded_at: datetime | None = None
    raw_payload: dict[str, Any] | None = None

    @model_validator(mode="after")
    def device_or_identifier_required(self):
        if not self.identifier and not self.device_id:
            raise ValueError("device_id or identifier is required")
        return self


class DeviceResponse(BaseModel):
    id: str
    name: str
    email: EmailStr
    phone: str
    identifier: str
    serial: str | None
    imei: str | None
    model: str | None
    device_type: DeviceType
    is_active: bool
    created_at: datetime
    latest_location: dict[str, Any] | None = None

    model_config = {"from_attributes": True}


class DiagnoseRequest(BaseModel):
    command_id: str = Field(..., min_length=1, max_length=120)
    args: dict[str, str] = Field(default_factory=dict)


class DiagnoseResponse(BaseModel):
    command_id: str
    exit_code: int
    output: str
    output_hash: str
    started_at: datetime
    ended_at: datetime


class BroadcastRequest(BaseModel):
    channel: Literal["map", "terminal", "alerts"] = "map"
    scope: Literal["viewer", "operator"] = "viewer"
    expires_in_minutes: int = Field(60, ge=5, le=1440)


class DeleteDataRequest(BaseModel):
    device_id: str | None = None
    email: EmailStr | None = None
    reason: str = Field("gdpr_user_request", max_length=500)

    @model_validator(mode="after")
    def target_required(self):
        if not self.email and not self.device_id:
            raise ValueError("device_id or email is required")
        return self


class ExternalSourceType(str, Enum):
    postgresql = "postgresql"
    mariadb = "mariadb"
    firebase = "firebase"
    supabase = "supabase"


class ImportUsersRequest(BaseModel):
    source_type: ExternalSourceType
    source_name: str = Field(..., min_length=1, max_length=120)
    connection_url: SecretStr | None = None
    service_account_json: SecretStr | None = None
    table_name: str = Field("users", max_length=120)
    name_column: str = Field("name", max_length=120)
    email_column: str = Field("email", max_length=120)
    phone_column: str = Field("phone", max_length=120)
    external_id_column: str | None = Field("id", max_length=120)
    limit: int = Field(500, ge=1, le=5000)

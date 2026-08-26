import pytest
from pydantic import ValidationError

from schemas import (
    BroadcastRequest,
    ConsentRequest,
    ConsentRevokeRequest,
    DeleteDataRequest,
    DeviceRegisterRequest,
    DiagnoseRequest,
    ImportUsersRequest,
    LocationUpdateRequest,
    ExternalSourceType,
)
from models import DeviceType


def test_device_register_minimal():
    d = DeviceRegisterRequest(name="Test", email="t@x.com", phone="+1234567890")
    assert d.device_type == DeviceType.other
    assert d.imei is None


def test_device_register_all_fields():
    d = DeviceRegisterRequest(
        name="Tracker",
        email="a@b.com",
        phone="+123",
        identifier="id-001",
        serial="SN123",
        imei="123456789012345",
        model="X1",
        manufacturer="ACME",
        os_type="android",
        os_version="14",
        device_type=DeviceType.vehicle,
    )
    assert d.device_type == DeviceType.vehicle


def test_device_register_rejects_empty_name():
    with pytest.raises(ValidationError):
        DeviceRegisterRequest(name="", email="a@b.com", phone="+123")


def test_device_register_rejects_bad_email():
    with pytest.raises(ValidationError):
        DeviceRegisterRequest(name="X", email="not-an-email", phone="+123")


def test_consent_request_requires_fields():
    with pytest.raises(ValidationError):
        ConsentRequest(device_id="d1", source="", scope="test")
    with pytest.raises(ValidationError):
        ConsentRequest(device_id="d1", source="manual", scope="")


def test_consent_revoke_request():
    c = ConsentRevokeRequest(device_id="d1", reason="user asked")
    assert c.reason == "user asked"


def test_location_update_requires_device():
    with pytest.raises(ValidationError):
        LocationUpdateRequest(latitude=1.0, longitude=2.0)


def test_location_update_accepts_device_id():
    loc = LocationUpdateRequest(device_id="d1", latitude=0.0, longitude=0.0)
    assert loc.device_id == "d1"


def test_location_update_rejects_lat_out_of_range():
    with pytest.raises(ValidationError):
        LocationUpdateRequest(device_id="d1", latitude=91.0, longitude=0.0)
    with pytest.raises(ValidationError):
        LocationUpdateRequest(device_id="d1", latitude=-91.0, longitude=0.0)


def test_location_update_rejects_lon_out_of_range():
    with pytest.raises(ValidationError):
        LocationUpdateRequest(device_id="d1", latitude=0.0, longitude=181.0)
    with pytest.raises(ValidationError):
        LocationUpdateRequest(device_id="d1", latitude=0.0, longitude=-181.0)


def test_location_update_speed_bounds():
    with pytest.raises(ValidationError):
        LocationUpdateRequest(device_id="d1", latitude=0.0, longitude=0.0, speed=-5.0)
    loc = LocationUpdateRequest(device_id="d1", latitude=0.0, longitude=0.0, speed=100.0)
    assert loc.speed == 100.0


def test_location_update_heading_bounds():
    with pytest.raises(ValidationError):
        LocationUpdateRequest(device_id="d1", latitude=0.0, longitude=0.0, heading=361.0)
    with pytest.raises(ValidationError):
        LocationUpdateRequest(device_id="d1", latitude=0.0, longitude=0.0, heading=-1.0)


def test_location_update_source_literal():
    loc = LocationUpdateRequest(device_id="d1", latitude=0.0, longitude=0.0, source="mqtt")
    assert loc.source == "mqtt"
    with pytest.raises(ValidationError):
        LocationUpdateRequest(device_id="d1", latitude=0.0, longitude=0.0, source="invalid")


def test_broadcast_request_defaults():
    b = BroadcastRequest()
    assert b.channel == "map"
    assert b.scope == "viewer"
    assert b.expires_in_minutes == 60


def test_broadcast_request_bounds():
    with pytest.raises(ValidationError):
        BroadcastRequest(expires_in_minutes=1)
    with pytest.raises(ValidationError):
        BroadcastRequest(expires_in_minutes=2000)


def test_delete_data_requires_target():
    with pytest.raises(ValidationError):
        DeleteDataRequest(reason="test")


def test_delete_data_accepts_email():
    d = DeleteDataRequest(email="x@y.com")
    assert str(d.email) == "x@y.com"


def test_diagnose_request():
    d = DiagnoseRequest(command_id="system.health")
    assert d.args == {}


def test_import_users_request():
    i = ImportUsersRequest(
        source_type=ExternalSourceType.postgresql,
        source_name="main-db",
        connection_url="postgresql://localhost/db",
    )
    assert i.table_name == "users"
    assert i.limit == 500


def test_import_users_rejects_empty_source_name():
    with pytest.raises(ValidationError):
        ImportUsersRequest(source_type=ExternalSourceType.postgresql, source_name="")

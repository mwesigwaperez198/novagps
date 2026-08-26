import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db import Base
import models


def _session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, future=True)()


def _make_device(**overrides):
    defaults = dict(name="T", email="t@x.com", phone="+1", identifier="i-1", device_type=models.DeviceType.other)
    defaults.update(overrides)
    return models.Device(**defaults)


def test_device_default_values():
    session = _session()
    device = _make_device(name="Test", email="t@x.com", identifier="id-1")
    session.add(device)
    session.commit()
    assert device.is_active is True
    assert device.device_type == models.DeviceType.other
    assert device.id is not None
    assert device.created_at is not None


def test_device_type_enum():
    for dt in models.DeviceType:
        assert dt.value in ("vehicle", "motorcycle", "phone", "laptop", "other")


def test_consent_default_status():
    session = _session()
    device = _make_device(identifier="i-consent")
    session.add(device)
    session.flush()
    consent = models.Consent(device_id=device.id, user_email="t@x.com", source="manual", scope="tracking")
    session.add(consent)
    session.commit()
    assert consent.status == models.ConsentStatus.active
    assert consent.consented_at is not None


def test_consent_status_enum():
    for cs in models.ConsentStatus:
        assert cs.value in ("active", "revoked", "deleted")


def test_role_enum():
    for r in models.Role:
        assert r.value in ("admin", "operator", "viewer", "auditor")


def test_location_composite_index():
    session = _session()
    device = _make_device(identifier="i-loc")
    session.add(device)
    session.flush()
    for i in range(3):
        loc = models.Location(device_id=device.id, latitude=float(i), longitude=float(i), source="http")
        session.add(loc)
    session.commit()
    count = session.query(models.Location).filter(models.Location.device_id == device.id).count()
    assert count == 3


def test_device_relationships():
    session = _session()
    device = _make_device(name="RelTest", identifier="rel-1")
    session.add(device)
    session.flush()
    loc = models.Location(device_id=device.id, latitude=0.0, longitude=0.0, source="http")
    consent = models.Consent(device_id=device.id, user_email="r@x.com", source="api", scope="full")
    session.add_all([loc, consent])
    session.commit()
    session.refresh(device)
    assert len(device.locations) == 1
    assert len(device.consents) == 1


def test_imported_user_unique_constraint():
    session = _session()
    u1 = models.ImportedUser(source="test", external_id="e1", name="A", email="a@b.com", phone="+1")
    session.add(u1)
    session.commit()
    u2 = models.ImportedUser(source="test", external_id="e2", name="B", email="a@b.com", phone="+2")
    session.add(u2)
    with pytest.raises(Exception):
        session.commit()


def test_broadcast_session_model():
    session = _session()
    from datetime import datetime, timezone, timedelta
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    bs = models.BroadcastSession(channel="map", token_hash="abc123", scope="viewer", created_by="admin", expires_at=expires)
    session.add(bs)
    session.commit()
    assert bs.active is True
    assert bs.id is not None


def test_audit_log_model():
    session = _session()
    log = models.AuditLog(actor="admin@test.com", role="admin", action="test.action", metadata_json={"key": "value"})
    session.add(log)
    session.commit()
    assert log.id is not None
    assert log.created_at is not None

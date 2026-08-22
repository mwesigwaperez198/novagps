import asyncio
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from db import Base
import models  # noqa: F401
from eventbus import EventBus


def _session(tmp_path: Path) -> Session:
    engine = create_engine(f"sqlite:///{tmp_path/'nova.sqlite3'}", future=True)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, future=True)
    return factory()


def test_sqlite_models_roundtrip(tmp_path):
    session = _session(tmp_path)
    device = models.Device(
        name="Field Laptop",
        email="op@nova.local",
        phone="+10000000000",
        identifier="field-001",
        device_type=models.DeviceType.laptop,
    )
    session.add(device)
    session.flush()
    location = models.Location(device_id=device.id, latitude=37.77, longitude=-122.41, source="http")
    consent = models.Consent(device_id=device.id, user_email=device.email, source="manual", scope="field-test")
    audit = models.AuditLog(actor="tester", role="admin", action="test.bootstrap", metadata_json={"k": "v"})
    session.add_all([location, consent, audit])
    session.commit()

    loaded = session.query(models.Device).one()
    assert loaded.identifier == "field-001"
    assert loaded.locations[0].latitude == pytest.approx(37.77)
    assert loaded.consents[0].status.value == "active"


def test_eventbus_async_pubsub():
    async def scenario() -> None:
        loop = asyncio.get_running_loop()
        bus = EventBus()
        bus.attach_loop(loop)
        queue = bus.subscribe()
        await bus.publish({"event": "location.updated", "device_id": "d1"})
        received = queue.get_nowait()
        assert received["device_id"] == "d1"
        bus.unsubscribe(queue)
        await bus.publish({"event": "second"})
        assert queue.empty()
        assert bus.recent(5)[-1]["event"] == "second"

    asyncio.run(scenario())


def test_eventbus_threadsafe_without_loop_records_history():
    bus = EventBus()
    delivered = bus.publish_threadsafe({"event": "x"})
    assert delivered is False
    assert bus.recent(10)[0]["event"] == "x"


def test_geofence_local_containment():
    from worker.geofence import check_event_against_geofences_local

    inside = check_event_against_geofences_local("dev1", -122.41, 37.78)
    assert len(inside) == 1
    outside = check_event_against_geofences_local("dev1", 0.0, 0.0)
    assert outside == []


def test_tool_registry_role_and_args_gate():
    from command_registry import CommandRegistryError, validate_command

    with pytest.raises(CommandRegistryError):
        validate_command("does.not.exist", {}, "admin")

    with pytest.raises(CommandRegistryError):
        validate_command("net.scan.topports", {"target": "10.0.0.5"}, "viewer")

    with pytest.raises(CommandRegistryError):
        validate_command("osint.http.headers", {"url": "ftp://example.com"}, "admin")

    spec = validate_command("net.scan.topports", {"target": "10.0.0.5"}, "operator")
    assert spec.command_id == "net.scan.topports"

    with pytest.raises(CommandRegistryError):
        validate_command("net.scan.topports", {"target": "bad target!"}, "admin")


def test_resolve_host_argv_substitution():
    from command_registry import validate_command
    from tool_registry import resolve_host_argv

    spec = validate_command("net.scan.topports", {"target": "192.168.1.1"}, "admin")
    argv = resolve_host_argv(spec, {"target": "192.168.1.1"})
    assert "192.168.1.1" in argv
    assert argv[0] == "nmap"


def test_forensics_hash_rejects_paths_outside_data_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "data").mkdir(exist_ok=True)
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    from config import get_settings

    get_settings.cache_clear()
    try:
        from command_registry import CommandRegistryError, validate_command

        with pytest.raises(CommandRegistryError):
            validate_command("forensics.hash.file", {"path": "/etc/shadow"}, "admin")
        ok = validate_command("forensics.hash.file", {"path": "evidence.bin"}, "admin")
        assert ok.command_id == "forensics.hash.file"
    finally:
        get_settings.cache_clear()


def test_builtin_system_info_executes():
    from command_registry import execute_registered_command

    result = execute_registered_command("system.info", {}, "viewer")
    assert result["exit_code"] == 0
    assert "NOVA BUILTIN" in result["output"]


def test_host_tool_missing_binary_returns_127(monkeypatch):
    import shutil

    monkeypatch.setattr(shutil, "which", lambda binary: None)
    from command_registry import execute_registered_command

    result = execute_registered_command("net.scan.topports", {"target": "127.0.0.1"}, "admin")
    assert result["exit_code"] == 127
    assert "NOVA TOOL MISSING" in result["output"]

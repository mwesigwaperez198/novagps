"""Tests for NOVA-CORE agent framework."""

import json
import os
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


@pytest.fixture
def tmp_vault(tmp_path):
    vault = tmp_path / "nova_vault"
    vault.mkdir()
    return vault


@pytest.fixture
def memory(tmp_vault):
    os.environ["NOVA_MEMORY_DB"] = str(tmp_vault / "test_memory.db")
    os.environ["NOVA_ESCROW_BIN"] = str(tmp_vault / "test_escrow.bin")
    os.environ["NOVA_VAULT_DIR"] = str(tmp_vault)
    os.environ["NOVA_DATA_DIR"] = str(tmp_vault)
    os.environ["NOVA_BACKEND_DIR"] = str(tmp_vault)
    os.environ["NOVA_PROJECT_ROOT"] = str(tmp_vault)

    from nova_core.memory import NovaMemory
    mem = NovaMemory(db_path=str(tmp_vault / "test_memory.db"))
    yield mem


@pytest.fixture
def escrow(tmp_vault):
    os.environ["NOVA_ESCROW_BIN"] = str(tmp_vault / "test_escrow.bin")
    from nova_core.enforcer import StateEscrow
    return StateEscrow(bin_path=str(tmp_vault / "test_escrow.bin"), size=4096)


@pytest.fixture
def registry():
    os.environ["NOVA_BACKEND_DIR"] = "/tmp"
    os.environ["NOVA_PROJECT_ROOT"] = "/tmp"
    from nova_core.tools import get_registry
    return get_registry()


class TestMemory:
    def test_record_and_retrieve_lesson(self, memory):
        lesson_id = memory.record_lesson(
            category="test",
            obstacle="Something broke",
            maneuver="Fixed it",
            delta="Applied patch",
        )
        assert lesson_id is not None

        lessons = memory.get_recent_lessons(limit=10)
        assert len(lessons) >= 1
        assert lessons[0]["category"] == "test"
        assert "Something broke" in lessons[0]["obstacle"]

    def test_search_lessons(self, memory):
        memory.record_lesson("security", "SQL injection found", "Added parameterized query", "patch")
        memory.record_lesson("network", "Timeout on ping", "Increased timeout", "config")

        results = memory.search_lessons("injection")
        assert len(results) >= 1

    def test_state_persistence(self, memory):
        memory.set_state("test_key", "test_value")
        value = memory.get_state("test_key")
        assert value == "test_value"

    def test_scan_results(self, memory):
        scan_id = memory.record_scan("vuln_scan", "localhost", {"findings": []}, "low")
        assert scan_id is not None

        scans = memory.get_recent_scans()
        assert len(scans) >= 1

    def test_alerts(self, memory):
        alert_id = memory.create_alert("test_alert", "Test message")
        assert alert_id is not None

        alerts = memory.get_alerts(acknowledged=False)
        assert len(alerts) >= 1

        memory.acknowledge_alert(alert_id)
        alerts = memory.get_alerts(acknowledged=False)
        assert len(alerts) == 0

    def test_hash_chain(self, memory):
        memory.record_lesson("test", "First issue", "First fix", "delta1")
        memory.record_lesson("test", "Second issue", "Second fix", "delta2")

        lessons = memory.get_recent_lessons(limit=2)
        assert lessons[0]["hash_chain"] != lessons[1]["hash_chain"]
        assert lessons[0]["hash_chain"] != ""

    def test_memory_stats(self, memory):
        memory.record_lesson("test", "obstacle", "maneuver", "delta")
        memory.create_alert("test", "message")

        stats = memory.get_memory_stats()
        assert stats["total_lessons"] >= 1
        assert stats["total_alerts"] >= 1

    def test_severity_filter(self, memory):
        memory.record_lesson("test", "Critical issue", "Fix", "delta", severity="critical")
        memory.record_lesson("test", "Info note", "Note", "delta", severity="info")

        critical = memory.get_lessons_by_severity("critical")
        assert len(critical) >= 1
        assert all(l["severity"] == "critical" for l in critical)

    def test_category_filter(self, memory):
        memory.record_lesson("security", "Issue 1", "Fix 1", "d1")
        memory.record_lesson("network", "Issue 2", "Fix 2", "d2")

        sec_lessons = memory.get_recent_lessons(category="security")
        assert all(l["category"] == "security" for l in sec_lessons)

    def test_retention_enforcement(self, memory):
        memory.max_entries = 5
        for i in range(10):
            memory.record_lesson("test", f"Issue {i}", f"Fix {i}", f"delta {i}")

        lessons = memory.get_recent_lessons(limit=100)
        assert len(lessons) <= 5


class TestEscrow:
    def test_write_and_read(self, escrow):
        test_data = "test_state_data_12345"
        escrow.write(test_data)
        result = escrow.read()
        assert result == test_data

    def test_json_roundtrip(self, escrow):
        test_obj = {"task_id": "test", "progress": 0.5, "timestamp": time.time()}
        escrow.write_json(test_obj)
        result = escrow.read_json()
        assert result["task_id"] == "test"
        assert result["progress"] == 0.5

    def test_overwrite(self, escrow):
        escrow.write("first")
        escrow.write("second")
        assert escrow.read() == "second"

    def test_empty_read(self, escrow):
        result = escrow.read_json()
        assert result == {}


class TestTools:
    def test_tool_registry_has_tools(self, registry):
        tools = registry.list_tools()
        assert len(tools) > 0
        tool_names = [t["name"] for t in tools]
        assert "system_info" in tool_names
        assert "port_scan" in tool_names

    def test_tool_categories(self, registry):
        scanner_tools = registry.list_by_category("scanner")
        assert len(scanner_tools) > 0
        system_tools = registry.list_by_category("system")
        assert len(system_tools) > 0

    def test_tool_execution(self, registry):
        result = registry.execute("system_info")
        assert result.success is True
        assert "os" in result.output

    def test_unknown_tool(self, registry):
        result = registry.execute("nonexistent_tool")
        assert result.success is False
        assert "not found" in result.error

    def test_port_scan(self, registry):
        result = registry.execute("port_scan", host="127.0.0.1", ports="22,80,443")
        assert result.success is True
        assert "open_ports" in result.output

    def test_system_info(self, registry):
        result = registry.execute("system_info")
        assert result.success is True
        output = result.output
        assert "os" in output
        assert "memory" in output
        assert "disk" in output

    def test_process_list(self, registry):
        result = registry.execute("process_list", top_n=5)
        assert result.success is True
        assert "processes" in result.output

    def test_connectivity_probe(self, registry):
        result = registry.execute("connectivity_probe", host="127.0.0.1", port=22, retries=1)
        assert result.success is True
        assert "reachable" in result.output

    def test_payload_gen(self, registry):
        result = registry.execute("payload_gen", category="sqli", count=5)
        assert result.success is True
        assert len(result.output["payloads"]) == 5

    def test_file_integrity(self, registry):
        result = registry.execute("file_integrity", files="/etc/hostname")
        assert result.success is True
        assert result.output["checked"] >= 1

    def test_tool_schema(self, registry):
        schema = registry.get_schema()
        assert len(schema) > 0
        assert all("name" in s and "description" in s for s in schema)


class TestWatcher:
    def test_anomaly_detection(self, memory):
        from nova_core.watcher import NovaWatcher
        watcher = NovaWatcher(memory)

        normal_snapshot = {
            "system": {"load_avg": [0.5, 0.5, 0.5], "memory_percent": 50},
            "network": {"reachable": True, "latency_ms": 10},
            "disk": {"used_percent": 60},
            "backend": {"healthy": True},
            "processes": {"uvicorn_running": True},
        }
        anomalies = watcher._detect_anomalies(normal_snapshot)
        assert len(anomalies) == 0

        critical_snapshot = {
            "system": {"load_avg": [8.0, 8.0, 8.0], "memory_percent": 95},
            "network": {"reachable": False, "latency_ms": 0},
            "disk": {"used_percent": 95},
            "backend": {"healthy": False, "error": "Connection refused"},
            "processes": {"uvicorn_running": False},
        }
        anomalies = watcher._detect_anomalies(critical_snapshot)
        assert len(anomalies) >= 3


class TestEnforcer:
    def test_patch_file(self, tmp_vault):
        os.environ["NOVA_MEMORY_DB"] = str(tmp_vault / "patch_test.db")
        os.environ["NOVA_ESCROW_BIN"] = str(tmp_vault / "patch_escrow.bin")
        os.environ["NOVA_VAULT_DIR"] = str(tmp_vault)

        from nova_core.enforcer import NovaEnforcer
        from nova_core.memory import NovaMemory

        mem = NovaMemory(db_path=str(tmp_vault / "patch_test.db"))
        enforcer = NovaEnforcer(memory=mem)

        test_file = tmp_vault / "test_patch.py"
        test_file.write_text("print('hello')\n")

        result = enforcer.patch_file(str(test_file), "print('world')\n")
        assert result["success"] is True
        assert test_file.read_text() == "print('world')\n"

    def test_dry_run_patch(self, tmp_vault):
        os.environ["NOVA_MEMORY_DB"] = str(tmp_vault / "dry_test.db")
        os.environ["NOVA_ESCROW_BIN"] = str(tmp_vault / "dry_escrow.bin")
        os.environ["NOVA_VAULT_DIR"] = str(tmp_vault)

        from nova_core.enforcer import NovaEnforcer
        from nova_core.memory import NovaMemory

        mem = NovaMemory(db_path=str(tmp_vault / "dry_test.db"))
        enforcer = NovaEnforcer(memory=mem)

        test_file = tmp_vault / "dry_test.py"
        test_file.write_text("original\n")

        result = enforcer.patch_file(str(test_file), "modified\n", dry_run=True)
        assert result["dry_run"] is True
        assert test_file.read_text() == "original\n"

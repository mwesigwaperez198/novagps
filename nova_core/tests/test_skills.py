"""Gates for the LAU skills registry and guarded adapters."""

import sys

import pytest

from nova_core.skills import adapters, registry


def test_registry_entries_are_complete():
    skills = registry.list_skills()
    assert len(skills) >= 18
    for skill in skills:
        assert skill["name"]
        assert skill["priority"] in {"P0", "P1", "P2", "P3"}
        assert skill["source"].startswith("https://github.com/")
        assert skill["purpose"]
        assert isinstance(skill["available"], bool)


def test_unknown_skill_is_reported_not_raised():
    result = adapters.run_skill("does-not-exist")
    assert result["status"] == "unknown_skill"


def test_missing_skill_returns_install_hint():
    result = adapters.run_skill("phoneinfoga", target="+10000000000")
    if result["status"] == "missing":
        assert result["install"]
    else:
        assert result["status"] in {"ok", "failed", "error", "timeout"}


def test_lab_only_skill_refused_without_lab_mode(monkeypatch):
    monkeypatch.delenv("NOVA_LAB_MODE", raising=False)
    with pytest.raises(adapters.SkillRefused):
        adapters.run_skill("kismet")


def test_available_skill_runs(monkeypatch, tmp_path):
    script = tmp_path / "probe.py"
    script.write_text("print('SKILLOK')\n")
    monkeypatch.setattr(adapters, "is_available", lambda spec: True)
    monkeypatch.setattr(adapters, "resolve_binary", lambda spec: sys.executable)
    result = adapters.run_skill("yara", target=str(script))
    assert result["status"] == "ok", result
    assert "SKILLOK" in result["stdout"]


def test_lab_skill_runs_when_lab_enabled(monkeypatch, tmp_path):
    script = tmp_path / "probe.py"
    script.write_text("print('LABOK')\n")
    monkeypatch.setenv("NOVA_LAB_MODE", "1")
    monkeypatch.setattr(adapters, "is_available", lambda spec: True)
    monkeypatch.setattr(adapters, "resolve_binary", lambda spec: sys.executable)
    monkeypatch.setattr(registry, "lab_enabled", lambda: True)
    result = adapters.run_skill("kismet", args=[str(script)])
    assert result["status"] == "ok", result
    assert "LABOK" in result["stdout"]


def test_install_hint_and_lookup():
    assert "phoneinfoga" in adapters.install_hint("phoneinfoga").lower() or adapters.install_hint("phoneinfoga")
    assert registry.get_skill("NMAP") is not None
    assert registry.get_skill("nmap").key == "nmap"

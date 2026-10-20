"""Owner confirmation ritual — the step-up that sits on top of the JWT."""

import types

import pytest

from nova_core import owner


@pytest.fixture(autouse=True)
def clean_sessions():
    owner.reset_all()
    yield
    owner.reset_all()


@pytest.fixture
def cfg(monkeypatch):
    stub = types.SimpleNamespace(
        owner_name="Perez",
        owner_phrase="23rd December",
        owner_session_ttl=3600,
        cloud_research=False,
    )
    monkeypatch.setattr(owner, "get_config", lambda: stub)
    return stub


def test_full_ritual_verifies(monkeypatch, cfg):
    first = owner.handle_turn("I am Perez", subject="u1", role="admin")
    assert first["intent"] == "owner_identity"
    assert "Are you my king?" in first["response"]
    assert first["owner"]["verified"] is False

    second = owner.handle_turn("yes", subject="u1", role="admin")
    assert "phrase" in second["response"].lower()

    third = owner.handle_turn("23rd December", subject="u1", role="admin")
    assert third["owner"]["verified"] is True
    assert third["owner"]["mode"] == "admin"
    assert owner.status("u1")["verified"] is True


def test_phrase_is_normalised(monkeypatch, cfg):
    owner.handle_turn("I am Perez", subject="u2", role="admin")
    owner.handle_turn("yes", subject="u2", role="admin")
    done = owner.handle_turn("  23 DECEMBER! ", subject="u2", role="admin")
    assert done["owner"]["verified"] is True


def test_wrong_phrase_resets_after_three(monkeypatch, cfg):
    owner.handle_turn("I am Perez", subject="u3", role="admin")
    owner.handle_turn("yes", subject="u3", role="admin")
    assert "2 attempt" in owner.handle_turn("nope", subject="u3", role="admin")["response"]
    assert "1 attempt" in owner.handle_turn("still wrong", subject="u3", role="admin")["response"]
    last = owner.handle_turn("wrong again", subject="u3", role="admin")
    assert "last attempt" in last["response"]
    assert owner.status("u3")["verified"] is False
    # A fresh claim starts over.
    again = owner.handle_turn("I am Perez", subject="u3", role="admin")
    assert "Are you my king?" in again["response"]


def test_non_admin_is_refused(monkeypatch, cfg):
    reply = owner.handle_turn("I am Perez", subject="u4", role="viewer")
    assert reply["owner"]["verified"] is False
    assert "admin account" in reply["response"]
    assert owner.status("u4")["session"] is False


def test_cancel_clears_session(monkeypatch, cfg):
    owner.handle_turn("I am Perez", subject="u5", role="admin")
    reply = owner.handle_turn("cancel", subject="u5", role="admin")
    assert "Cancelled" in reply["response"]
    assert owner.status("u5")["session"] is False


def test_unrelated_message_passes_through(monkeypatch, cfg):
    assert owner.handle_turn("scan open ports on 127.0.0.1", subject="u6", role="admin") is None


def test_phrase_is_never_echoed(monkeypatch, cfg):
    owner.handle_turn("I am Perez", subject="u7", role="admin")
    owner.handle_turn("yes", subject="u7", role="admin")
    wrong = owner.handle_turn("banana", subject="u7", role="admin")
    assert "23rd" not in wrong["response"]
    assert "december" not in wrong["response"].lower()


def test_command_during_verify_does_not_count_as_attempt(monkeypatch, cfg):
    owner.handle_turn("I am Perez", subject="u8", role="admin")
    owner.handle_turn("yes", subject="u8", role="admin")
    assert owner.handle_turn("scan open ports on 127.0.0.1", subject="u8", role="admin") is None
    assert owner.status("u8")["stage"] == "verify"
    done = owner.handle_turn("23rd December", subject="u8", role="admin")
    assert done["owner"]["verified"] is True


def test_sessions_are_per_subject(monkeypatch, cfg):
    owner.handle_turn("I am Perez", subject="a", role="admin")
    assert owner.status("b")["session"] is False

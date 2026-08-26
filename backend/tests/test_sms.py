import pytest
from unittest.mock import patch, MagicMock

from sms import (
    _normalize_phone,
    send_sms,
    send_sms_africastalking,
    send_sms_generic_http,
    get_icloud_instructions,
    get_android_instructions,
    get_mdm_lock_instructions,
)


def test_normalize_phone_with_plus():
    assert _normalize_phone("+256771234567") == "+256771234567"


def test_normalize_phone_local_uganda():
    assert _normalize_phone("0771234567") == "+256771234567"


def test_normalize_phone_no_plus():
    result = _normalize_phone("771234567")
    assert result.startswith("+")
    assert len(result) >= 10


def test_normalize_phone_strips_dashes():
    result = _normalize_phone("+256-77-123-4567")
    assert "-" not in result


def test_send_sms_no_provider():
    result = send_sms("+256771234567", "test message")
    assert result["success"] is False
    assert "No SMS provider" in result["error"]


def test_send_sms_africastalking_no_key():
    result = send_sms_africastalking("+256771234567", "hello")
    assert "error" in result
    assert "API key not configured" in result["error"]


def test_send_sms_generic_http_no_gateway():
    result = send_sms_generic_http("+256771234567", "hello")
    assert "error" in result
    assert "No SMS gateway" in result["error"]


def test_icloud_instructions():
    result = get_icloud_instructions()
    assert result["service"] == "Apple Find My iPhone"
    assert len(result["steps"]) > 0
    assert "capabilities" in result
    assert "requirements" in result


def test_android_instructions():
    result = get_android_instructions()
    assert result["service"] == "Google Find My Device"
    assert len(result["steps"]) > 0


def test_mdm_lock_instructions():
    result = get_mdm_lock_instructions()
    assert result["service"] == "MDM Remote Lock"
    assert "api_example" in result


def test_send_sms_routes_to_africastalking(monkeypatch):
    import sms as sms_mod
    monkeypatch.setattr(sms_mod, "get_settings", lambda: MagicMock(
        africastalking_api_key="test-key",
        africastalking_username="sandbox",
        africastalking_sender_id="",
        sms_gateway_url="",
        sms_api_key="",
    ))
    with patch.object(sms_mod, "send_sms_africastalking") as mock_at:
        mock_at.return_value = {"provider": "africastalking", "success": True}
        result = send_sms("+256771234567", "test")
        mock_at.assert_called_once()
        assert result["success"] is True


def test_send_sms_routes_to_generic(monkeypatch):
    import sms as sms_mod
    monkeypatch.setattr(sms_mod, "get_settings", lambda: MagicMock(
        africastalking_api_key="",
        sms_gateway_url="https://sms.test.com/send",
        sms_api_key="key123",
    ))
    with patch.object(sms_mod, "send_sms_generic_http") as mock_gen:
        mock_gen.return_value = {"provider": "generic_http", "success": True}
        result = send_sms("+256771234567", "test")
        mock_gen.assert_called_once()
        assert result["success"] is True

import pytest

from camera import RTSP_PATTERN, capture_screenshot, discover_cameras, get_stream_url, start_recording, detect_motion
from vpn import WG_INTERFACE_PATTERN, get_vpn_status, connect_vpn, disconnect_vpn
from ids import get_ids_status, get_recent_alerts, update_rules


def test_rtsp_pattern_valid():
    assert RTSP_PATTERN.fullmatch("rtsp://192.168.1.100:554/live")
    assert RTSP_PATTERN.fullmatch("rtsp://admin:pass@cam.local:554/stream1")
    assert not RTSP_PATTERN.fullmatch("http://192.168.1.100/video")
    assert not RTSP_PATTERN.fullmatch("rtsp://invalid url")


def test_wg_interface_pattern_valid():
    assert WG_INTERFACE_PATTERN.fullmatch("wg0")
    assert WG_INTERFACE_PATTERN.fullmatch("tunnel-vpn")
    assert not WG_INTERFACE_PATTERN.fullmatch("wg0 with spaces")
    assert not WG_INTERFACE_PATTERN.fullmatch("a" * 16)


def test_get_stream_url_valid():
    result = get_stream_url("rtsp://192.168.1.1:554/live")
    assert result["status"] == "ready"
    assert result["stream_url"] == "rtsp://192.168.1.1:554/live"


def test_get_stream_url_invalid():
    result = get_stream_url("http://192.168.1.1/video")
    assert "error" in result


def test_capture_screenshot_invalid_url():
    result = capture_screenshot("not-rtsp")
    assert "error" in result


def test_start_recording_invalid_url():
    result = start_recording("not-rtsp", duration=10)
    assert "error" in result


def test_detect_motion_invalid_url():
    result = detect_motion("bad-url")
    assert "error" in result


def test_discover_cameras_returns_list():
    result = discover_cameras("192.168.1.0/30")
    assert isinstance(result, list)


def test_get_vpn_status_returns_dict():
    result = get_vpn_status()
    assert "wireguard" in result
    assert "openvpn" in result


def test_connect_vpn_missing_config():
    result = connect_vpn("/nonexistent/config.conf", "wireguard")
    assert "error" in result


def test_connect_vpn_unsupported_type():
    result = connect_vpn("/nonexistent.conf", "ipsec")
    assert "error" in result


def test_disconnect_vpn_no_interface():
    result = disconnect_vpn("", "wireguard")
    assert "error" in result


def test_disconnect_vpn_unsupported_type():
    result = disconnect_vpn("wg0", "ipsec")
    assert "error" in result


def test_get_ids_status_returns_dict():
    result = get_ids_status()
    assert "suricata" in result
    assert "installed" in result["suricata"]


def test_get_recent_alerts_without_suricata():
    result = get_recent_alerts(limit=5)
    assert isinstance(result, list)


def test_update_rules_no_suricata():
    result = update_rules()
    assert isinstance(result, dict)

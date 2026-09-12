"""Deterministic location + integrity math shared by LAU perimeter tools.

Pure, testable functions:
  * distance_from_rssi(rssi, measured_power, n)  — log-distance path loss
  * parse_gprmc(sentence)                        — NMEA 0183 $GPRMC fix
  * hmac_verify(payload, signature, secret)      — HMAC-SHA256 payload check

No network, no external deps. This is the "tracking logic" LAU reasons with.
"""

import hashlib
import hmac
import json
import math
import re


def distance_from_rssi(rssi, measured_power=-59.0, n=2.5) -> float:
    """Log-distance path loss: distance = 10 ** ((measured_power - rssi) / (10*n)).

    measured_power is the expected RSSI at 1 meter, n the path-loss exponent
    (2 = free space, 2.5 = indoor default, 3+ = obstructed).
    """
    if rssi is None:
        return float("nan")
    try:
        r = float(rssi)
        mp = float(measured_power)
        exponent = float(n)
    except (TypeError, ValueError):
        return float("nan")
    if exponent <= 0:
        exponent = 2.5
    return round(10.0 ** ((mp - r) / (10.0 * exponent)), 2)


_GPRMC_RE = re.compile(
    r"^\$GPRMC,"
    r"(?P<utc>\d{6}(?:\.\d+)?),(?P<status>[AV]),"
    r"(?P<lat>\d{2,4}\.\d+),(?P<lat_dir>[NS]),"
    r"(?P<lon>\d{3,5}\.\d+),(?P<lon_dir>[EW]),"
    r"(?P<speed>[0-9.]+),(?P<course>[0-9.]+),"
    r"(?P<date>\d{6})(?:,(?P<mag>[0-9.]*),(?P<mag_dir>[EW]*))?"
    r"(?:,(?P<mode>[ANDR]))?\*"
    r"(?P<checksum>[0-9A-Fa-f]{2})$"
)


def _dmm_to_decimal(dmm: str, direction: str) -> float:
    """Convert degrees+decimal-minutes (DDMM.MMMM) to decimal degrees."""
    if not dmm or not direction:
        return None
    try:
        val = float(dmm)
    except (TypeError, ValueError):
        return None
    degrees = int(val // 100)
    minutes = val - degrees * 100
    decimal = degrees + minutes / 60.0
    if direction in ("S", "W"):
        decimal = -decimal
    return round(decimal, 6)


def _nmea_checksum_ok(sentence: str) -> bool:
    match = re.match(r"^\$(?P<body>[^*]*)\*(?P<cs>[0-9A-Fa-f]{2})$", sentence.strip())
    if not match:
        return False
    calc = 0
    for char in match.group("body"):
        calc ^= ord(char)
    return calc == int(match.group("cs"), 16)


def parse_gprmc(sentence: str) -> dict:
    """Parse and validate a $GPRMC sentence; returns a fix dict or an error dict."""
    sentence = (sentence or "").strip()
    if not sentence:
        return {"error": "empty sentence"}
    if not _nmea_checksum_ok(sentence):
        return {"error": "checksum failed"}
    match = _GPRMC_RE.match(sentence)
    if not match:
        return {"error": "not a valid $GPRMC sentence"}
    g = match.groupdict()
    if g["status"] != "A":
        return {"error": "fix void", "status": g["status"]}
    lat = _dmm_to_decimal(g["lat"], g["lat_dir"])
    lon = _dmm_to_decimal(g["lon"], g["lon_dir"])
    if lat is None or lon is None:
        return {"error": "coordinates unparseable"}
    return {
        "utc": g["utc"],
        "status": "A",
        "lat": lat,
        "lon": lon,
        "speed_knots": float(g["speed"] or 0),
        "course_deg": float(g["course"] or 0),
        "date": g["date"],
        "mode": g["mode"] or "",
    }


def hmac_verify(payload, signature: str, secret: str) -> tuple[bool, str]:
    """Verify an HMAC-SHA256 signature over the canonical JSON of `payload`.

    Returns (ok, calculated_signature_hex). Constant-time compare.
    """
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    calculated = hmac.new(
        secret.encode("utf-8"),
        raw.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    ok = hmac.compare_digest(calculated, str(signature or "").lower())
    return ok, calculated
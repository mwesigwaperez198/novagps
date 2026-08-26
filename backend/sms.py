import logging
import re
from typing import Any

import requests as http_requests

from config import get_settings

logger = logging.getLogger("nova.sms")

PHONE_PATTERN = re.compile(r"^\+?\d{7,15}$")


def _normalize_phone(phone: str) -> str:
    clean = re.sub(r"[^\d+]", "", phone)
    if not clean.startswith("+"):
        if clean.startswith("0"):
            clean = f"+256{clean[1:]}"
        else:
            clean = f"+{clean}"
    return clean


def send_sms_africastalking(phone: str, message: str) -> dict[str, Any]:
    settings = get_settings()
    api_key = settings.africastalking_api_key
    username = settings.africastalking_username or "sandbox"
    sender_id = settings.africastalking_sender_id

    if not api_key:
        return {"error": "Africa's Talking API key not configured", "provider": "africastalking"}

    normalized = _normalize_phone(phone)

    try:
        resp = http_requests.post(
            "https://api.africastalking.com/version1/messaging",
            headers={
                "apiKey": api_key,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            data={
                "username": username,
                "to": normalized,
                "message": message,
                **({"from": sender_id} if sender_id else {}),
            },
            timeout=15,
        )
        result = resp.json()
        sms_data = result.get("SMSMessageData", {})
        recipients = sms_data.get("Recipients", [])
        status = recipients[0].get("status") if recipients else "unknown"

        return {
            "provider": "africastalking",
            "phone": normalized,
            "message": message[:200],
            "status": status,
            "cost": recipients[0].get("cost", "N/A") if recipients else "N/A",
            "messageId": recipients[0].get("messageId") if recipients else None,
            "success": status.lower() in ("sent", "success", "Submitted"),
        }
    except Exception as exc:
        logger.warning("Africa's Talking SMS failed: %s", exc)
        return {"error": str(exc), "provider": "africastalking", "phone": normalized}


def send_sms_generic_http(phone: str, message: str) -> dict[str, Any]:
    settings = get_settings()
    gateway_url = settings.sms_gateway_url
    api_key = settings.sms_api_key

    if not gateway_url:
        return {"error": "No SMS gateway configured", "provider": "generic"}

    normalized = _normalize_phone(phone)

    try:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        payload = {
            "phone": normalized,
            "message": message,
            "to": normalized,
            "text": message,
        }

        resp = http_requests.post(gateway_url, json=payload, headers=headers, timeout=15)

        return {
            "provider": "generic_http",
            "phone": normalized,
            "message": message[:200],
            "status_code": resp.status_code,
            "success": resp.ok,
            "response": resp.text[:500],
        }
    except Exception as exc:
        logger.warning("Generic SMS gateway failed: %s", exc)
        return {"error": str(exc), "provider": "generic", "phone": normalized}


def send_sms(phone: str, message: str) -> dict[str, Any]:
    settings = get_settings()

    if settings.africastalking_api_key:
        return send_sms_africastalking(phone, message)

    if settings.sms_gateway_url:
        return send_sms_generic_http(phone, message)

    return {
        "provider": "none",
        "phone": _normalize_phone(phone),
        "message": message[:200],
        "success": False,
        "error": "No SMS provider configured. Set AFRICASTALKING_API_KEY or SMS_GATEWAY_URL in .env",
        "instructions": {
            "africastalking": "Get API key from https://africastalking.com — Uganda SMS cost ~UGX 25/msg",
            "twilio": "Set SMS_GATEWAY_URL to https://api.twilio.com/2010-04-01/Accounts/<SID>/Messages.json",
            "generic": "Set SMS_GATEWAY_URL to any REST endpoint that accepts POST {phone, message}",
        },
    }


def get_icloud_instructions() -> dict[str, Any]:
    return {
        "service": "Apple Find My iPhone",
        "url": "https://www.icloud.com/find",
        "steps": [
            "1. Go to https://www.icloud.com/find",
            "2. Sign in with the Apple ID linked to the target device",
            "3. Select the device from the list",
            "4. Click 'Lost Mode' to lock the device and display a message",
            "5. Enter a phone number and message to display on the lock screen",
            "6. The device will lock immediately and show the message",
        ],
        "capabilities": {
            "lost_mode": "Locks device and displays custom message + phone number on screen",
            "play_sound": "Plays a loud sound for 2 minutes (even if muted)",
            "erase": "Removes all data from the device (irreversible)",
            "directions": "Shows current location and navigation to device",
        },
        "notes": [
            "Device must be powered on and connected to internet (WiFi or cellular)",
            "If device is offline, action triggers when it next connects",
            "Lost Mode locks the device with a passcode",
            "Message appears on the lock screen — anyone who finds the phone sees it",
            "You can track the device location in real-time via Find My",
        ],
        "requirements": [
            "Apple ID and password linked to the device",
            "Find My iPhone must be enabled on the device",
            "Device must be online (WiFi/cellular)",
        ],
    }


def get_android_instructions() -> dict[str, Any]:
    return {
        "service": "Google Find My Device",
        "url": "https://www.google.com/android/find",
        "steps": [
            "1. Go to https://www.google.com/android/find",
            "2. Sign in with the Google account linked to the device",
            "3. Select the target device",
            "4. Click 'Secure Device' to lock and display a message",
            "5. Enter a recovery message and phone number",
            "6. Click 'Secure Device' — device locks immediately",
        ],
        "capabilities": {
            "secure_device": "Locks device and displays custom message + callback number",
            "play_sound": "Plays a loud ringtone for 5 minutes",
            "erase": "Factory resets the device (irreversible)",
        },
    }


def get_mdm_lock_instructions() -> dict[str, Any]:
    return {
        "service": "MDM Remote Lock",
        "note": "If the device is enrolled in a Mobile Device Management (MDM) system, you can send remote commands directly.",
        "steps": [
            "1. Access your MDM console (Jamf, Mosyle, Kandji, etc.)",
            "2. Find the device by serial number or IMEI",
            "3. Send 'Lock Device' command",
            "4. Set a lock message and contact number",
            "5. Device locks on next check-in",
        ],
        "api_example": {
            "jamf": "POST /JSSResource/computers/serial/{serial}/command/LockComputer",
            "mosyle": "POST /v2/device/{id}/command with action: DEVICE_LOST",
        },
    }

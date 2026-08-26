"""Remote device commands — lock, wipe, Lost Mode.

Dispatches commands to devices via MQTT, FCM, or returns platform-specific
instructions for manual execution.
"""

import logging
from typing import Any

from sqlalchemy.orm import Session

from push_service import queue_locate_command, dispatch_mqtt_command, dispatch_fcm

logger = logging.getLogger("nova.remote_commands")


def lock_device(db: Session, device: Any, message: str = "This device has been remotely locked.", contact: str = "") -> dict[str, Any]:
    """Send a lock command to a device."""
    command = {
        "action": "lock",
        "message": message,
        "contact": contact,
        "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
    }
    queued = queue_locate_command(db, device.id, "lock", command)
    mqtt_result = None
    if device.identifier:
        from config import get_settings
        settings = get_settings()
        if settings.mqtt_broker:
            mqtt_result = dispatch_mqtt_command(settings.mqtt_broker, device.identifier, command)
    return {
        "device_id": device.id,
        "device_name": device.name,
        "action": "lock",
        "queued": True,
        "command_id": queued["command_id"],
        "mqtt_dispatched": mqtt_result,
        "instructions": _get_lock_instructions(device),
    }


def wipe_device(db: Session, device: Any, confirm_code: str = "") -> dict[str, Any]:
    """Send a wipe command to a device. Requires confirmation code."""
    if not confirm_code:
        import secrets
        code = secrets.token_hex(4).upper()
        return {
            "status": "confirm_required",
            "confirmation_code": code,
            "message": f"Send confirmation code {code} to execute wipe. This action is irreversible.",
        }
    command = {
        "action": "wipe",
        "confirm": confirm_code,
        "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
    }
    queued = queue_locate_command(db, device.id, "wipe", command)
    return {
        "device_id": device.id,
        "device_name": device.name,
        "action": "wipe",
        "queued": True,
        "command_id": queued["command_id"],
        "warning": "Wipe command queued. Device will factory reset on next connection.",
    }


def lost_mode(db: Session, device: Any, message: str = "This device is lost. Please call the owner.", contact: str = "", location_interval: int = 30) -> dict[str, Any]:
    """Activate Lost Mode — lock + continuous location + display message."""
    command = {
        "action": "lost_mode",
        "message": message,
        "contact": contact,
        "location_interval": location_interval,
        "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
    }
    queued = queue_locate_command(db, device.id, "lost_mode", command)
    mqtt_result = None
    if device.identifier:
        from config import get_settings
        settings = get_settings()
        if settings.mqtt_broker:
            mqtt_result = dispatch_mqtt_command(settings.mqtt_broker, device.identifier, command)
    return {
        "device_id": device.id,
        "device_name": device.name,
        "action": "lost_mode",
        "queued": True,
        "command_id": queued["command_id"],
        "message": message,
        "contact": contact,
        "location_interval_seconds": location_interval,
        "mqtt_dispatched": mqtt_result,
        "note": "Device will lock, report location every " + str(location_interval) + " seconds, and display the message on screen.",
    }


def send_message(db: Session, device: Any, message: str) -> dict[str, Any]:
    """Send a display message to a device."""
    command = {
        "action": "display_message",
        "message": message,
        "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
    }
    queued = queue_locate_command(db, device.id, "display_message", command)
    return {
        "device_id": device.id,
        "device_name": device.name,
        "action": "display_message",
        "queued": True,
        "command_id": queued["command_id"],
    }


def _get_lock_instructions(device: Any) -> dict[str, Any]:
    """Return platform-specific lock instructions."""
    os_type = (device.os_type or "").lower()
    manufacturer = (device.manufacturer or "").lower()
    if "ios" in os_type or "apple" in manufacturer:
        return {
            "platform": "ios",
            "service": "Find My iPhone",
            "url": "https://www.icloud.com/find",
            "steps": [
                "1. Go to https://www.icloud.com/find",
                "2. Sign in with the Apple ID linked to the device",
                "3. Select the device and click Lost Mode",
                "4. Enter a phone number and message to display",
            ],
        }
    elif "android" in os_type or "google" in manufacturer or "samsung" in manufacturer:
        return {
            "platform": "android",
            "service": "Google Find My Device",
            "url": "https://www.google.com/android/find",
            "steps": [
                "1. Go to https://www.google.com/android/find",
                "2. Sign in with the Google account linked to the device",
                "3. Select the device and click Secure Device",
                "4. Enter a recovery message and phone number",
            ],
        }
    else:
        return {
            "platform": "generic",
            "service": "MDM / Manual Lock",
            "steps": [
                "1. If enrolled in MDM (Jamf, Mosyle, Kandji), send Lock command from console",
                "2. Contact carrier to report stolen and request IMEI blacklist",
                "3. File police report with IMEI and serial number",
                f"4. IMEI: {device.imei or 'N/A'} | Serial: {device.serial or 'N/A'}",
            ],
        }

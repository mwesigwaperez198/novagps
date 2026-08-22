import json
import logging
import os
from urllib.parse import urlparse

import httpx
import paho.mqtt.client as mqtt

from config import get_settings


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("nova.mqtt_consumer")


def parse_broker(value: str) -> tuple[str, int]:
    if "://" not in value:
        host, _, port = value.partition(":")
        return host, int(port or 1883)
    parsed = urlparse(value)
    return parsed.hostname or "mosquitto", parsed.port or 1883


def on_connect(client, userdata, flags, reason_code, properties=None):
    logger.info("mqtt connected reason=%s", reason_code)
    client.subscribe("nova/locations/#")


def on_message(client, userdata, message):
    api_url = os.getenv("BACKEND_API_URL", "http://backend-api:8000")
    try:
        payload = json.loads(message.payload.decode("utf-8"))
        payload["source"] = "mqtt"
        with httpx.Client(timeout=5) as http:
            response = http.post(f"{api_url}/update-location", json=payload)
            response.raise_for_status()
        logger.info("mqtt location forwarded topic=%s", message.topic)
    except Exception:
        logger.exception("mqtt forward failed topic=%s", message.topic)


def main() -> None:
    host, port = parse_broker(get_settings().mqtt_broker)
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(host, port, keepalive=60)
    logger.info("mqtt consumer listening broker=%s:%s", host, port)
    client.loop_forever()


if __name__ == "__main__":
    main()

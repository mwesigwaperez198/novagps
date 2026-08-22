import json
import logging
import signal
import time
from typing import Any

from kafka import KafkaConsumer
from kafka.errors import KafkaError

from config import get_settings
from db import SessionLocal
from worker.geofence import check_event_against_geofences


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("nova.kafka_consumer")
running = True


def stop_handler(signum, frame):
    global running
    running = False


def handle_location_event(event: dict[str, Any]) -> None:
    device_type = event.get("device_type")
    logger.info("location event device_id=%s device_type=%s", event.get("device_id"), device_type)
    if device_type in {"vehicle", "motorcycle"}:
        logger.info("vehicle_pipeline speed=%s heading=%s", event.get("speed"), event.get("heading"))
    elif device_type in {"phone", "laptop"}:
        logger.info("portable_pipeline source=%s", event.get("source"))

    if event.get("longitude") is None or event.get("latitude") is None:
        return
    with SessionLocal() as db:
        matches = check_event_against_geofences(
            db,
            device_id=event["device_id"],
            longitude=float(event["longitude"]),
            latitude=float(event["latitude"]),
        )
        for match in matches:
            logger.warning("geofence_match %s", match)


def create_kafka_consumer(settings):
    retry_delay = 5
    while True:
        try:
            consumer = KafkaConsumer(
                settings.kafka_topic,
                bootstrap_servers=settings.kafka_broker,
                group_id="nova-geofence-worker",
                auto_offset_reset="latest",
                enable_auto_commit=True,
                value_deserializer=lambda raw: json.loads(raw.decode("utf-8")),
            )
            logger.info("worker listening topic=%s broker=%s", settings.kafka_topic, settings.kafka_broker)
            return consumer
        except KafkaError as exc:
            logger.warning("Kafka consumer connection failed: %s. Retrying in %s seconds.", exc, retry_delay)
            time.sleep(retry_delay)


def main() -> None:
    settings = get_settings()
    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)
    while running:
        consumer = create_kafka_consumer(settings)
        try:
            while running:
                records = consumer.poll(timeout_ms=1000)
                for messages in records.values():
                    for message in messages:
                        handle_location_event(message.value)
        except Exception:
            logger.exception("Kafka worker error. Restarting consumer after backoff.")
            time.sleep(5)
        finally:
            try:
                consumer.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()

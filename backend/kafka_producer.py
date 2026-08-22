import json
import logging
from functools import lru_cache
from typing import Any

from config import get_settings
from eventbus import bus


logger = logging.getLogger(__name__)


@lru_cache
def get_producer():
    from kafka import KafkaProducer

    settings = get_settings()
    return KafkaProducer(
        bootstrap_servers=settings.kafka_broker,
        value_serializer=lambda value: json.dumps(value, default=str).encode("utf-8"),
        key_serializer=lambda value: value.encode("utf-8") if value else None,
        linger_ms=20,
        retries=3,
    )


def publish_location_event(event: dict[str, Any]) -> bool:
    """Fan a location event out to the pipeline.

    Kafka is used when KAFKA_BROKER is configured (full mode). The in-process
    event bus always receives the event so WebSocket clients stay live even
    without Kafka (portable mode).
    """
    settings = get_settings()
    delivered = bus.publish_threadsafe(event)
    if settings.kafka_enabled:
        try:
            get_producer().send(settings.kafka_topic, key=event.get("device_id"), value=event)
            get_producer().flush(timeout=2)
            delivered = True
        except Exception:
            logger.exception("Kafka publish failed; event still available on local bus")
    return delivered

import asyncio
import json
import logging
import os
import time
from threading import Thread
from urllib.parse import parse_qs, urlparse

import websockets
from kafka import KafkaConsumer
from kafka.errors import KafkaError

from broadcast_auth import token_allowed
from config import get_settings


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("nova.kafka_to_ws")
CLIENTS: set[websockets.WebSocketServerProtocol] = set()


async def websocket_handler(websocket, path: str):
    query = parse_qs(urlparse(path).query)
    channel = query.get("channel", ["map"])[0]
    token = query.get("token", [None])[0]
    if not token_allowed(token, channel):
        await websocket.close(code=4403, reason="invalid broadcast token")
        return
    CLIENTS.add(websocket)
    try:
        await websocket.send(json.dumps({"event": "connected", "channel": channel}))
        await websocket.wait_closed()
    finally:
        CLIENTS.discard(websocket)


async def broadcast(message: dict):
    if not CLIENTS:
        return
    encoded = json.dumps(message, default=str)
    await asyncio.gather(*(client.send(encoded) for client in list(CLIENTS)), return_exceptions=True)


def create_kafka_consumer(settings):
    retry_delay = 5
    while True:
        try:
            consumer = KafkaConsumer(
                settings.kafka_topic,
                bootstrap_servers=settings.kafka_broker,
                group_id="nova-kafka-to-ws",
                auto_offset_reset="latest",
                enable_auto_commit=True,
                value_deserializer=lambda raw: json.loads(raw.decode("utf-8")),
            )
            logger.info("bridge consuming topic=%s broker=%s", settings.kafka_topic, settings.kafka_broker)
            return consumer
        except KafkaError as exc:
            logger.warning("Kafka consumer connection failed: %s. Retrying in %s seconds.", exc, retry_delay)
            time.sleep(retry_delay)


def consume_kafka(loop: asyncio.AbstractEventLoop) -> None:
    settings = get_settings()
    while True:
        consumer = create_kafka_consumer(settings)
        try:
            for message in consumer:
                asyncio.run_coroutine_threadsafe(broadcast(message.value), loop)
        except Exception:
            logger.exception("Kafka consumer error. Restarting consumer after backoff.")
        finally:
            try:
                consumer.close()
            except Exception:
                pass
        time.sleep(5)


async def main() -> None:
    host = os.getenv("WS_HOST", "0.0.0.0")
    port = int(os.getenv("WS_PORT", "8765"))
    loop = asyncio.get_running_loop()
    Thread(target=consume_kafka, args=(loop,), daemon=True).start()
    async with websockets.serve(websocket_handler, host, port):
        logger.info("websocket bridge listening ws://%s:%s", host, port)
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())

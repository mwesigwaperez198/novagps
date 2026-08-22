import asyncio
import logging
import threading
from collections import deque
from typing import Any

logger = logging.getLogger(__name__)


class EventBus:
    """In-process pub/sub used when Kafka is not configured (portable mode).

    Sync FastAPI endpoints run in a worker thread, so publishes are marshalled
    onto the asyncio loop that owns the subscriber queues.
    """

    def __init__(self, history_size: int = 500) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._subscribers: dict[int, asyncio.Queue] = {}
        self._history: deque[dict[str, Any]] = deque(maxlen=history_size)
        self._next_id = 1
        self._lock = threading.Lock()

    def attach_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=256)
        with self._lock:
            subscription_id = self._next_id
            self._next_id += 1
            self._subscribers[subscription_id] = queue
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        with self._lock:
            for key, value in list(self._subscribers.items()):
                if value is queue:
                    del self._subscribers[key]

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        items = list(self._history)
        return items[-limit:]

    async def publish(self, event: dict[str, Any]) -> None:
        self._record(event)
        with self._lock:
            subscribers = list(self._subscribers.values())
        for queue in subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning("eventbus subscriber dropped event (queue full)")

    def publish_threadsafe(self, event: dict[str, Any]) -> bool:
        """Deliver an event from any thread. Returns True if dispatched."""
        self._record(event)
        loop = self._loop
        if loop is None or loop.is_closed():
            return False
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is loop:
            loop.create_task(self.publish(event))
            return True
        asyncio.run_coroutine_threadsafe(self.publish(event), loop)
        return True

    def _record(self, event: dict[str, Any]) -> None:
        self._history.append(event)


bus = EventBus()

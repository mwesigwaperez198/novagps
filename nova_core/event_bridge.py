"""Bridge NOVA's in-process operational events into LAU's durable memory."""

from __future__ import annotations

import asyncio
import json
import logging

from .memory import NovaMemory

logger = logging.getLogger("nova_core.event_bridge")


async def consume_events(bus, memory: NovaMemory) -> None:
    queue = bus.subscribe()
    try:
        while True:
            event = await queue.get()
            name = str(event.get("event", "system.event"))
            # Keep location traffic compact; record a rolling state, while all
            # state-changing/audit events become durable lessons.
            if name == "location.updated":
                memory.set_state("last_location_event", json.dumps({
                    key: event.get(key) for key in ("device_id", "recorded_at", "source", "place_name")
                }))
                continue
            memory.record_lesson(
                "live_event",
                f"NOVA event: {name}",
                "Event bridge delivered live system activity to LAU",
                json.dumps(event, default=str)[:500],
                severity="warning" if name.startswith("security.") else "info",
                tags="eventbus,queen",
                engine_used="LAU_EVENT_BRIDGE",
            )
    except asyncio.CancelledError:
        raise
    finally:
        bus.unsubscribe(queue)


def start_event_bridge(bus) -> asyncio.Task:
    """Start once on FastAPI's active loop; retained task owns the subscription."""
    return asyncio.create_task(consume_events(bus, NovaMemory()), name="lau-event-bridge")

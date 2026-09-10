"""NOVA-CORE integration with NovaGPS FastAPI backend.

Adds /nova-core/* endpoints to the existing NovaGPS backend
for agent control, security scanning, and status monitoring.
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
import asyncio
import time

router = APIRouter(prefix="/nova-core", tags=["nova-core"])


class NovaQueryRequest(BaseModel):
    query: str


class NovaQueryResponse(BaseModel):
    query: str
    response: str
    tools_executed: list
    duration_ms: float
    cycle: int


class NovaStatusResponse(BaseModel):
    agent_version: str
    memory_stats: dict
    escrow_state: dict
    tools_registered: int
    uptime_seconds: float


_agent_start_time = time.time()


@router.get("/status", response_model=NovaStatusResponse)
async def nova_status():
    from ..nova_core.brain import NovaBrain
    brain = NovaBrain()
    stats = brain.memory.get_memory_stats()
    escrow = brain.enforcer.recover_task_state()
    tools = brain.tools.list_tools()

    return NovaStatusResponse(
        agent_version="0.1.0",
        memory_stats=stats,
        escrow_state=escrow,
        tools_registered=len(tools),
        uptime_seconds=round(time.time() - _agent_start_time, 2),
    )


@router.post("/query", response_model=NovaQueryResponse)
async def nova_query(req: NovaQueryRequest):
    from ..nova_core.brain import NovaBrain
    brain = NovaBrain()
    result = await brain.process_query(req.query)

    return NovaQueryResponse(
        query=result["query"],
        response=result["response"],
        tools_executed=result["tools_executed"],
        duration_ms=result["duration_ms"],
        cycle=result["cycle"],
    )


@router.get("/tools")
async def nova_tools():
    from ..nova_core.tools import get_registry
    registry = get_registry()
    return {"tools": registry.list_tools(), "count": len(registry.list_tools())}


@router.post("/scan")
async def nova_scan(scan_type: str = Query(default="all")):
    from ..nova_core.tools import get_registry
    registry = get_registry()

    scan_map = {
        "vuln": "vuln_scan",
        "auth": "auth_scan",
        "secrets": "secret_scan",
        "ports": "port_scan",
        "crypto": "crypto_audit",
        "integrity": "file_integrity",
        "endpoints": "endpoint_test",
    }

    if scan_type == "all":
        tools_to_run = list(scan_map.values())
    elif scan_type in scan_map:
        tools_to_run = [scan_map[scan_type]]
    else:
        raise HTTPException(status_code=400, detail=f"Unknown scan type: {scan_type}")

    results = {}
    for tool_name in tools_to_run:
        result = registry.execute(tool_name)
        results[tool_name] = result.to_dict()

    return {"scan_type": scan_type, "results": results}


@router.get("/memory/stats")
async def nova_memory_stats():
    from ..nova_core.memory import NovaMemory
    memory = NovaMemory()
    return memory.get_memory_stats()


@router.get("/memory/lessons")
async def nova_lessons(
    limit: int = Query(default=20),
    category: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
):
    from ..nova_core.memory import NovaMemory
    memory = NovaMemory()

    if search:
        lessons = memory.search_lessons(search, limit=limit)
    elif severity:
        lessons = memory.get_lessons_by_severity(severity, limit=limit)
    else:
        lessons = memory.get_recent_lessons(limit=limit, category=category)

    return {"lessons": lessons, "count": len(lessons)}


@router.post("/memory/lesson")
async def nova_record_lesson(category: str, obstacle: str, maneuver: str, delta: str, severity: str = "info"):
    from ..nova_core.memory import NovaMemory
    memory = NovaMemory()
    lesson_id = memory.record_lesson(category, obstacle, maneuver, delta, severity=severity)
    return {"id": lesson_id, "status": "recorded"}


@router.get("/alerts")
async def nova_alerts(limit: int = Query(default=20), acknowledged: bool = Query(default=False)):
    from ..nova_core.memory import NovaMemory
    memory = NovaMemory()
    alerts = memory.get_alerts(acknowledged=acknowledged, limit=limit)
    return {"alerts": alerts, "count": len(alerts)}


@router.post("/alerts/{alert_id}/acknowledge")
async def nova_acknowledge_alert(alert_id: int):
    from ..nova_core.memory import NovaMemory
    memory = NovaMemory()
    memory.acknowledge_alert(alert_id)
    return {"status": "acknowledged"}


@router.post("/integrity/snapshot")
async def nova_integrity_snapshot():
    from ..nova_core.enforcer import NovaEnforcer
    enforcer = NovaEnforcer()
    snapshot = enforcer.take_integrity_snapshot()
    return {"snapshot": snapshot}


@router.get("/integrity/verify")
async def nova_integrity_verify():
    from ..nova_core.enforcer import NovaEnforcer
    enforcer = NovaEnforcer()
    result = enforcer.verify_integrity()
    return result


@router.get("/config")
async def nova_config():
    from ..nova_core.config import get_config
    cfg = get_config()
    return {
        "environment": cfg.environment,
        "nova_mode": cfg.ollama_model,
        "llm_backend": cfg.llm_backend,
        "watch_interval": cfg.watch_interval,
        "scan_interval": cfg.scan_interval,
        "fuzz_interval": cfg.fuzz_interval,
    }


def register_nova_router(app):
    app.include_router(router)

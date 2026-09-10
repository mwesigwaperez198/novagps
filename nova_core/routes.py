"""NOVA-CORE routes — added to NovaGPS FastAPI app.

Import and call register_nova_routes(app) from main.py to
add all NOVA-CORE agent endpoints.
"""

import time
import sys
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel


nova_router = APIRouter(prefix="/nova-core", tags=["nova-core"])


class NovaQueryRequest(BaseModel):
    query: str


class NovaTelemetryRequest(BaseModel):
    packet: dict


class NovaQueryResponse(BaseModel):
    query: str
    response: str
    tools_executed: list
    results: dict
    duration_ms: float
    cycle: int


_agent_start_time = time.time()


def _get_brain():
    nova_core_path = Path(__file__).resolve().parent.parent
    if str(nova_core_path) not in sys.path:
        sys.path.insert(0, str(nova_core_path))

    from nova_core.brain import NovaBrain
    return NovaBrain()


@nova_router.get("/status")
async def nova_status():
    brain = _get_brain()
    from nova_core.config import get_config
    stats = brain.memory.get_memory_stats()
    escrow = brain.enforcer.recover_task_state()
    tools = brain.tools.list_tools()

    return {
        "agent": get_config().agent_name,
        "agent_version": "0.1.0",
        "codename": "LAU",
        "memory_stats": stats,
        "escrow_state": escrow,
        "tools_registered": len(tools),
        "uptime_seconds": round(time.time() - _agent_start_time, 2),
        "categories": list(set(t["category"] for t in tools)),
    }


@nova_router.post("/query")
async def nova_query(req: NovaQueryRequest):
    brain = _get_brain()
    result = await brain.process_query(req.query)

    return {
        "query": result["query"],
        "response": result["response"],
        "tools_executed": result["tools_executed"],
        "results": result["results"],
        "duration_ms": result["duration_ms"],
        "cycle": result["cycle"],
        "engine_used": result.get("engine_used", "UNKNOWN"),
        "agent": result.get("agent", "LAU"),
    }


@nova_router.get("/tools")
async def nova_tools():
    brain = _get_brain()
    tools = brain.tools.list_tools()
    return {"tools": tools, "count": len(tools)}


@nova_router.post("/scan")
async def nova_scan(scan_type: str = Query(default="all")):
    brain = _get_brain()

    scan_map = {
        "vuln": "vuln_scan",
        "auth": "auth_scan",
        "secrets": "secret_scan",
        "ports": "port_scan",
        "crypto": "crypto_audit",
        "integrity": "file_integrity",
        "endpoints": "endpoint_test",
        "fuzz": "api_fuzzer",
        "injection": "injection_test",
        "dependencies": "dependency_audit",
        "complexity": "complexity_scan",
    }

    if scan_type == "all":
        tools_to_run = list(scan_map.values())
    elif scan_type in scan_map:
        tools_to_run = [scan_map[scan_type]]
    else:
        raise HTTPException(status_code=400, detail=f"Unknown scan type: {scan_type}. Available: {list(scan_map.keys())}")

    results = {}
    for tool_name in tools_to_run:
        result = brain.tools.execute(tool_name)
        results[tool_name] = result.to_dict()

    brain.memory.record_scan("nova_scan", scan_type, results)
    return {"scan_type": scan_type, "results": results}


@nova_router.get("/memory/stats")
async def nova_memory_stats():
    brain = _get_brain()
    return brain.memory.get_memory_stats()


@nova_router.get("/memory/lessons")
async def nova_lessons(
    limit: int = Query(default=20),
    category: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
):
    brain = _get_brain()
    if search:
        lessons = brain.memory.search_lessons(search, limit=limit)
    elif severity:
        lessons = brain.memory.get_lessons_by_severity(severity, limit=limit)
    else:
        lessons = brain.memory.get_recent_lessons(limit=limit, category=category)
    return {"lessons": lessons, "count": len(lessons)}


@nova_router.post("/memory/lesson")
async def nova_record_lesson(
    category: str = Query(...),
    obstacle: str = Query(...),
    maneuver: str = Query(...),
    delta: str = Query(...),
    severity: str = Query(default="info"),
):
    brain = _get_brain()
    lesson_id = brain.memory.record_lesson(category, obstacle, maneuver, delta, severity=severity)
    return {"id": lesson_id, "status": "recorded"}


@nova_router.get("/alerts")
async def nova_alerts(
    limit: int = Query(default=20),
    acknowledged: bool = Query(default=False),
):
    brain = _get_brain()
    alerts = brain.memory.get_alerts(acknowledged=acknowledged, limit=limit)
    return {"alerts": alerts, "count": len(alerts)}


@nova_router.post("/alerts/{alert_id}/acknowledge")
async def nova_acknowledge_alert(alert_id: int):
    brain = _get_brain()
    brain.memory.acknowledge_alert(alert_id)
    return {"status": "acknowledged"}


@nova_router.post("/integrity/snapshot")
async def nova_integrity_snapshot():
    brain = _get_brain()
    return brain.enforcer.take_integrity_snapshot()


@nova_router.get("/integrity/verify")
async def nova_integrity_verify():
    brain = _get_brain()
    return brain.enforcer.verify_integrity()


@nova_router.get("/config")
async def nova_config():
    from nova_core.config import get_config
    cfg = get_config()
    return {
        "environment": cfg.environment,
        "llm_backend": cfg.llm_backend,
        "ollama_host": cfg.ollama_host,
        "ollama_model": cfg.ollama_model,
        "embedded_enabled": cfg.embedded_enabled,
        "embedded_max_ctx": cfg.embedded_max_ctx,
        "embedded_max_tokens": cfg.embedded_max_tokens,
        "embedded_threads": cfg.embedded_threads,
        "mem_reserve_mb": cfg.mem_reserve_mb,
        "watch_interval": cfg.watch_interval,
        "scan_interval": cfg.scan_interval,
        "fuzz_interval": cfg.fuzz_interval,
    }


@nova_router.get("/engine/status")
async def nova_engine_status():
    brain = _get_brain()
    return brain.engine.status()


@nova_router.post("/engine/init")
async def nova_engine_init(force: bool = Query(default=False)):
    brain = _get_brain()
    brain.engine.initialize(force=force)
    return brain.engine.status()


@nova_router.post("/telemetry/verify")
async def nova_telemetry_verify(req: NovaTelemetryRequest):
    brain = _get_brain()
    verified = brain.engine.telemetry_verify(req.packet)
    return verified


@nova_router.get("/llm/status")
async def nova_llm_status():
    brain = _get_brain()
    return brain.llm.check_availability()


@nova_router.post("/llm/chat")
async def nova_llm_chat(prompt: str = Query(...), system: str = Query(default="")):
    brain = _get_brain()
    ok, response = brain.llm.chat(system=system, prompt=prompt)
    if not ok:
        raise HTTPException(status_code=502, detail=response)
    return {"success": ok, "response": response, "model": brain.llm.model}


@nova_router.post("/llm/reason")
async def nova_llm_reason(task: str = Query(...), state: str = Query(default="")):
    brain = _get_brain()
    reasoning = brain.llm.reason(state, task)
    return {"reasoning": reasoning, "model": brain.llm.model}


def register_nova_routes(app):
    app.include_router(nova_router)

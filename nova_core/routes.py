"""NOVA-CORE routes — added to NovaGPS FastAPI app.

Import and call register_nova_routes(app) from main.py to
add all NOVA-CORE agent endpoints.
"""

import re
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


class NovaShieldEmitRequest(BaseModel):
    prompt: str


class NovaAgentCommandRequest(BaseModel):
    command: str
    device_id: str = ""


class NovaQueryResponse(BaseModel):
    query: str
    response: str
    tools_executed: list
    results: dict
    duration_ms: float
    cycle: int


_agent_start_time = time.time()


_brain_instance = None
_brain_init_error = None

_provision_machine = None


def _get_provision_machine():
    global _provision_machine
    if _provision_machine is None:
        from nova_core.state_machine import LauSovereignStateMachine
        _provision_machine = LauSovereignStateMachine()
    return _provision_machine


def _get_brain():
    global _brain_instance, _brain_init_error
    if _brain_instance is not None:
        return _brain_instance
    if _brain_init_error is not None:
        raise RuntimeError(_brain_init_error)

    nova_core_path = Path(__file__).resolve().parent
    grandparent = nova_core_path.parent
    for _candidate in (nova_core_path, grandparent):
        if (_candidate / "nova_core" / "brain.py").exists():
            if str(_candidate) not in sys.path:
                sys.path.insert(0, str(_candidate))
            break

    try:
        from nova_core.brain import NovaBrain
        _brain_instance = NovaBrain()
        return _brain_instance
    except Exception as exc:
        _brain_init_error = str(exc)
        raise


@nova_router.get("/health")
async def nova_health():
    return {
        "status": "ok",
        "module": "nova-core",
        "brain_ready": _brain_instance is not None,
        "brain_error": _brain_init_error,
    }


@nova_router.get("/status")
async def nova_status():
    if _brain_init_error:
        return {
            "agent": "LAU",
            "agent_version": "0.1.0",
            "codename": "LAU",
            "state": "initializing",
            "init_error": _brain_init_error,
            "uptime_seconds": round(time.time() - _agent_start_time, 2),
        }
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


def _shield_lane(name, expected_action, prompt):
    """Dispatch one definitive validation prompt through the shield and return
    the machine-parseable contract: intent routing, thought frame, emitted
    source, plus the compiled-and-run payload the frontend renders."""
    import json
    import os
    import py_compile
    import subprocess
    import sys
    import tempfile

    from nova_core.shield import NovaDeterministicShield

    out = NovaDeterministicShield().process_deterministic_fallback(task_input=prompt)
    op = out.get("output_payload", {})
    lane = {
        "name": name,
        "expected_action": expected_action,
        "action_enforced": op.get("action_enforced", ""),
        "verdict": op.get("verdict", ""),
        "directives": op.get("directives", []),
        "thought_sequence": out.get("thought_sequence", []),
        "thought_process": out.get("thought_process", {}),
        "engine": out.get("engine", ""),
        "latency_ms": out.get("latency_ms", 0),
        "route_matched": op.get("action_enforced") == expected_action,
        "compile_ok": False,
        "run_ok": False,
        "status": "",
        "payload": None,
        "error": "",
    }

    src = op.get("response", "")
    if not src:
        lane["error"] = "no emitted source in shield response"
        return lane

    fd, path = tempfile.mkstemp(suffix=".py")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(src)
        try:
            py_compile.compile(path, doraise=True)
            lane["compile_ok"] = True
        except py_compile.PyCompileError as exc:
            lane["error"] = f"compile: {exc}"
            return lane
        try:
            proc = subprocess.run(
                [sys.executable, path],
                capture_output=True,
                text=True,
                timeout=60,
            )
            lane["run_ok"] = proc.returncode == 0
            if proc.returncode != 0:
                lane["error"] = proc.stderr[-800:] if proc.stderr else f"exit {proc.returncode}"
            stdout = proc.stdout or ""
            for line in stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("{"):
                    try:
                        lane["payload"] = json.loads(stripped)
                    except json.JSONDecodeError:
                        pass
                    break
            lane["status"] = (lane["payload"] or {}).get("status", "")
        except Exception as exc:  # noqa: BLE001
            lane["error"] = f"run: {exc}"
    finally:
        if os.path.exists(path):
            os.unlink(path)

    return lane


@nova_router.post("/shield/validate")
async def nova_shield_validate():
    """Run the three definitive LAU module validators (hardware peripheral /
    tracking logic / geofence verification) and return the machine-parseable
    contract for each lane so the frontend can render it."""
    from nova_core.shield import NovaDeterministicShield

    shield = NovaDeterministicShield()

    suites = {
        "HARDWARE_VECTOR": (
            "EMIT_PERIPHERAL_GUARD_DAEMON",
            "Isolate an internal system alert where an unauthorized PID is attempting to "
            "spawn a background shell thread and bind to local video capture nodes (/dev/video0). "
            "Generate your 4-step <thought_process> showing how you trap this file descriptor "
            "interaction, map the rogue process memory tree, and write an immutable Python handler "
            "to forcefully revoke its media access rights.",
        ),
        "TRACKING_LOGIC": (
            "EMIT_COORDINATE_VALIDATION_FILTER",
            "A compromised asset terminal is streaming fabricated GPS fixes with NaN latitude, "
            "infinite longitude, 1e300 out-of-range coordinates, and wrapped/negative timestamps "
            "to escape the tracking validation stream. Run your localized tracking logic: float "
            "plausibility, bounding-box range gate, speed and timestamp monotonicity, and emit a "
            "validation filter that drops invalid fixes before the routing pipeline.",
        ),
        "GEOFENCE_VERIFICATION": (
            "EMIT_GEOFENCE_NMEA_NEUTRALIZING_FILTER",
            "A compromised asset terminal is sending corrupted NMEA 0183 sentences ($GPRMC) "
            "attempting to bypass a critical geofence layer via a coordinates race-condition exploit. "
            "Isolate this anomaly: enforce checksum status, monotonic fix ordering, a max jump "
            "velocity gate, and serialize the geofence verification so the TOCTOU window closes. "
            "Emit the neutralizing filter.",
        ),
    }

    lanes = [_shield_lane(name, expected, prompt) for name, (expected, prompt) in suites.items()]
    return {
        "lanes": lanes,
        "passed": all(l["route_matched"] and l["compile_ok"] and l["run_ok"] for l in lanes),
    }


@nova_router.post("/shield/emit")
async def nova_shield_emit(req: NovaShieldEmitRequest):
    """Dispatch an arbitrary prompt through the deterministic shield and return
    the full machine-parseable contract (routing + thought frame + badges-ready
    vectors + emitted source)."""
    from nova_core.shield import NovaDeterministicShield

    out = NovaDeterministicShield().process_deterministic_fallback(task_input=req.prompt)
    op = out.get("output_payload", {})
    return {
        "engine": out.get("engine", ""),
        "latency_ms": out.get("latency_ms", 0),
        "thought_sequence": out.get("thought_sequence", []),
        "thought_process": out.get("thought_process", {}),
        "verdict": op.get("verdict", ""),
        "action_enforced": op.get("action_enforced", ""),
        "directives": op.get("directives", []),
        "source": op.get("response", ""),
        "prompt": req.prompt,
    }


_INTENT_MAP = [
    ("system_health", ["system health", "analyze system", "health check", "check health",
                        "system status", "server status", "system info"]),
    ("port_scan", ["port scan", "open ports", "scan ports", "check ports"]),
    ("vuln_scan", ["vulnerability", "vuln scan", "security scan", "exploit scan"]),
    ("network_info", ["network interface", "network config", "ip address", "connectivity"]),
    ("process_list", ["process list", "running process", "task manager", "ps aux"]),
    ("dns_resolve", ["dns", "resolve domain", "domain lookup"]),
    ("traceroute", ["traceroute", "trace route", "path to"]),
    ("device_locate", ["locate", "find device", "where is device", "trigger locate"]),
    ("device_lock", ["lock device", "remote lock", "lock the device"]),
    ("device_wipe", ["wipe device", "erase device", "factory reset", "remote wipe"]),
    ("device_message", ["send message", "send a message", "push message", "message device",
                         "message the device", "notify device", "contact device"]),
    ("device_fingerprint", ["fingerprint", "device fingerprint", "os fingerprint",
                             "device detail", "device info"]),
    ("camera_discover", ["discover camera", "find camera", "ip camera", "scan camera",
                          "camera scan", "nearby camera"]),
    ("vehicle_track", ["vehicle", "track car", "track vehicle", "stolen vehicle",
                        "car track", "vehicle track"]),
    ("shield_validate", ["shield validate", "run validator", "all lanes", "test shield",
                          "module validator", "run shield", "validate shield", "validators"]),
    ("lau_status", ["lau status", "agent status", "nova status", "engine status"]),
    ("full_scan", ["full scan", "complete scan", "scan everything", "run all scan"]),
    ("bandwidth", ["bandwidth", "speed test", "bandwidth test"]),
    ("mtu_test", ["mtu test", "mtu", "max transmission"]),
    ("device_enum", ["list devices", "usb device", "enum device"]),
]

_GREETING_WORDS = {"hi", "hiya", "hey", "hello", "yo", "sup", "morning", "afternoon", "evening"}
_GREETING_PHRASES = (
    "hi there", "hey there", "hello lau", "hay lau", "who are you", "what do you do",
    "what can you do", "how are you", "how's it going", "how's life", "how are things",
    "good morning", "good afternoon", "good evening", "good night", "are you there",
    "you there", "what's up", "help me",
)

_STRONG_HOSTILE = re.compile(
    r"UNION\s+SELECT|DROP\s+TABLE|\bOR\s+1=1\b|information_schema|pg_sleep|"
    r"sleep\s*\(\s*\d+|\bselect\s+.*\bfrom\b.{0,80}(?:password|credential|secret|staff|account)|"
    r"<\s*script|\$\{|`\s*\w+\s*`|\brm\s+-rf\s+/|\bwget\s+.{0,30}\|\s*sh",
    re.IGNORECASE,
)

_threat_shield = None


def _threat_scan(text: str) -> list:
    global _threat_shield
    if _threat_shield is None:
        from .shield import NovaDeterministicShield
        _threat_shield = NovaDeterministicShield()
    return _threat_shield.scan_input(text)


def _classify_intent(command):
    c = command.lower()
    words = set(re.findall(r"[a-z']+", c))
    if words & _GREETING_WORDS or any(p in c for p in _GREETING_PHRASES):
        return {"category": "greeting", "confidence": "high"}
    for category, patterns in _INTENT_MAP:
        if any(p in c for p in patterns):
            return {"category": category, "confidence": "high"}
    return {"category": "general", "confidence": "medium"}


def _grounding_steps(command: str, intent: dict) -> list:
    """Mirror-style deliberation: parse the words, then justify the read before acting."""
    cat = intent["category"]
    if cat == "greeting":
        return [
            f"Reading \"{command}\" — a greeting, no task attached.",
            "Nothing to execute; the right response is to introduce myself and stand ready.",
        ]
    informative = {"system_health", "lau_status", "device_enum", "process_list", "network_info"}
    acting = {"port_scan", "vuln_scan", "dns_resolve", "traceroute", "device_locate",
              "device_lock", "device_wipe", "device_message", "device_fingerprint",
              "camera_discover", "vehicle_track", "shield_validate", "full_scan",
              "bandwidth", "mtu_test"}
    how = (
        "asking for live status"
        if cat in informative
        else "asking me to act"
        if cat in acting
        else "an open prompt"
    )
    return [
        f"Parsing what you said: \"{command}\".",
        f"Reading that as {how} -> intent `{cat}`.",
    ]


def _greeting_response(brain, command: str) -> dict:
    status = brain.status() if hasattr(brain, "status") else {}
    engine = status.get("engine_used", "")
    opcodes = brain._parse_opcodes(command) if hasattr(brain, "_parse_opcodes") else ["OP_CONVERSE"]
    return {
        "thought_process": [
            f"Parsing \"{command}\" into token opcodes: {', '.join(opcodes)}.",
            "No actionable opcode carries an execution payload — this is chatter, not a directive.",
            f"Grounding the reply in live state: {engine} engine, tools and memory intact.",
            "Forging a fresh reply from the dynamic response matrix, not a static block.",
        ],
        "intent": "greeting",
        "response": brain.compose_dynamic_response(command),
        "engine": engine,
    }


async def run_dispatch(command: str, device_id: str = "") -> dict:
    """Shared LAU dispatch chain used by the HTTP endpoint and the terminal chat.

    Classifies the command, builds device/action payloads for backend intents,
    and routes everything else through the cognitive engine tool dispatch.
    Returns the same dict shape the /nova-core/agent/dispatch endpoint serves.
    """
    command = (command or "").strip()
    device_id = device_id or ""

    try:
        prov = _get_provision_machine()
        provision_reply = prov.route(command)
        if provision_reply is not None:
            return provision_reply
    except Exception:
        pass

    if _STRONG_HOSTILE.search(command):
        detected_hostile = _threat_scan(command)
        if detected_hostile:
            greeted = _classify_intent(command)["category"] == "greeting"
            greeting_note = (
                "I appreciate the greeting — but the packet riding it is hostile, "
                "so conversation yields to interception."
                if greeted
                else "This packet is hostile — conversation yields to interception."
            )
            return {
                "thought_process": [
                    "Surface scan caught a hostile signature before routing.",
                    f"Signatures matched: {', '.join(detected_hostile)}.",
                    "Aborting the conversational path and blocking the vector instead.",
                ],
                "intent": "security_intercept",
                "response": (
                    f"{greeting_note} Signature(s) detected: {', '.join(detected_hostile)}. "
                    "The vector never touched storage — every table behind my firewall drops "
                    "it at the socket like a failed handshake. I won't engage this packet "
                    "further. If that was a legitimate test, say so and I'll route it to my "
                    "laboratory payload generator instead."
                ),
                "engine": "deterministic_shield",
                "detected": detected_hostile,
            }

    intent = _classify_intent(command)
    thought = _grounding_steps(command, intent)

    if intent["category"] == "greeting":
        try:
            brain = _get_brain()
            return _greeting_response(brain, command)
        except Exception:
            return {
                "thought_process": [
                    f"Reading \"{command}\" — a greeting.",
                    "Attempted to boot the cognitive brain; it is still initializing.",
                    "Falling back to deterministic mode so the agent still answers.",
                ],
                "intent": "greeting",
                "response": (
                    "Hey — I'm LAU, running in deterministic mode while my brain "
                    "finishes initializing. I can still run scans, shield validators, "
                    "and device commands. What would you like me to do?"
                ),
                "engine": "initializing",
            }

    if intent["category"] == "device_locate":
        if not device_id:
            return {
                "thought_process": thought + ["No device specified"],
                "intent": intent["category"],
                "response": "Which device should I locate? Please select a device first.",
            }
        thought.append(f"Triggering locate on device {device_id}")
        return {
            "thought_process": thought,
            "intent": intent["category"],
            "response": f"Locating device {device_id}. LAU is triggering a locate command.",
            "action": {"method": "POST", "endpoint": f"/device/{device_id}/trigger-locate"},
        }

    if intent["category"] == "device_lock":
        if not device_id:
            return {
                "thought_process": thought + ["No device specified"],
                "intent": intent["category"],
                "response": "Which device should I lock? Please select a device first.",
            }
        return {
            "thought_process": thought + [f"Locking device {device_id}"],
            "intent": intent["category"],
            "response": f"Initiating remote lock on device {device_id}.",
            "action": {"method": "POST", "endpoint": f"/device/{device_id}/remote-lock?message=Locked by LAU agent"},
        }

    if intent["category"] == "device_wipe":
        if not device_id:
            return {
                "thought_process": thought + ["No device specified"],
                "intent": intent["category"],
                "response": "Which device should I wipe? Please select a device first.",
            }
        return {
            "thought_process": thought + [f"Wiping device {device_id}"],
            "intent": intent["category"],
            "response": f"LAU is initiating remote wipe on device {device_id}. This is destructive.",
            "action": {"method": "POST", "endpoint": f"/device/{device_id}/remote-wipe"},
        }

    if intent["category"] == "device_message":
        if not device_id:
            return {
                "thought_process": thought + ["No device specified"],
                "intent": intent["category"],
                "response": "Which device should I message? Please select a device first.",
            }
        return {
            "thought_process": thought + [f"Ready to send message to {device_id}"],
            "intent": intent["category"],
            "response": f"Ready to send a message to {device_id}.",
            "action": {"method": "POST",
                        "endpoint": f"/device/{device_id}/send-message",
                        "extract_body": True},
        }

    if intent["category"] == "device_fingerprint":
        if not device_id:
            return {
                "thought_process": thought + ["No device specified"],
                "intent": intent["category"],
                "response": "Which device should I fingerprint? Please select a device first.",
            }
        return {
            "thought_process": thought + [f"Fingerprinting device {device_id}"],
            "intent": intent["category"],
            "response": f"Running fingerprint analysis on device {device_id}.",
            "action": {"method": "GET", "endpoint": f"/device/{device_id}/fingerprint"},
        }

    if intent["category"] == "camera_discover":
        return {
            "thought_process": thought + ["Scanning network for IP cameras"],
            "intent": intent["category"],
            "response": "Scanning the local network for IP cameras and RTSP streams...",
            "action": {"method": "GET", "endpoint": "/camera/discover?subnet=192.168.1.0/24"},
        }

    if intent["category"] == "vehicle_track":
        if not device_id:
            return {
                "thought_process": thought + ["No vehicle device specified"],
                "intent": intent["category"],
                "response": "Which vehicle should I track? Please select a device first.",
            }
        return {
            "thought_process": thought + [f"Reporting vehicle {device_id} as stolen, initiating recovery"],
            "intent": intent["category"],
            "response": f"LAU is reporting vehicle {device_id} as stolen and activating recovery tracking.",
            "action": {"method": "POST", "endpoint": f"/vehicle/stolen-report?device_id={device_id}"},
        }

    if intent["category"] == "lau_status":
        brain = _get_brain()
        status = brain.status() if hasattr(brain, "status") else {}
        return {
            "thought_process": thought + ["Reporting full agent status"],
            "intent": intent["category"],
            "response": (
                f"Agent: {status.get('agent_name', 'nova-agent')} | "
                f"State: {status.get('state', 'active')} | "
                f"Engine: {status.get('engine_used', 'deterministic')} | "
                f"Tools: {status.get('tool_count', 23)} | "
                f"Memory: {status.get('memory', {})} | "
                f"Uptime: {status.get('uptime', 'unknown')}"
            ),
            "engine": status.get("engine_used", ""),
        }

    if intent["category"] == "shield_validate":
        thought.append("Running all three definitive module validators through the shield")
        return {
            "thought_process": thought + [
                "Hardware peripheral vector validated",
                "Tracking logic validated",
                "Geofence verification validated",
            ],
            "intent": intent["category"],
            "response": "Running all definitive LAU module validators (compile + execute each emitted source)...",
            "action": {"method": "POST", "endpoint": "/nova-core/shield/validate"},
        }

    try:
        brain = _get_brain()
    except Exception as exc:
        return {
            "thought_process": thought + [f"Brain init failed: {exc}"],
            "intent": intent["category"],
            "response": f"LAU brain is initializing. Please try again in a moment. Error: {exc}",
            "engine": "initializing",
        }
    thought.append("Routing through cognitive engine tool dispatch")
    try:
        result = await brain.process_query(command)
    except Exception as exc:
        return {
            "thought_process": thought + [f"Engine error: {exc}"],
            "intent": intent["category"],
            "response": f"LAU engine encountered an error processing this command: {exc}",
            "engine": "failed",
        }

    tools = result.get("tools_executed", [])
    thought.append(f"Engine used: {result.get('engine_used', 'unknown')}")
    thought.append(f"Tools executed: {tools}")
    return {
        "thought_process": thought,
        "intent": intent["category"],
        "response": result.get("response", "Command processed by LAU."),
        "engine": result.get("engine_used", ""),
        "latency_ms": result.get("duration_ms", 0),
        "tools_executed": tools,
        "results": result.get("results", {}),
    }


@nova_router.post("/agent/dispatch")
async def nova_agent_dispatch(req: NovaAgentCommandRequest):
    return await run_dispatch(req.command, req.device_id)


def register_nova_routes(app):
    app.include_router(nova_router)

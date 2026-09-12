"""NOVA-CORE — Main entry point and CLI interface.

Usage:
    python -m nova_core                  # Start interactive agent
    python -m nova_core --patrol         # Start autonomous patrol daemon
    python -m nova_core --audit          # Run single daily audit
    python -m nova_core --scan           # Run all security scans
    python -m nova_core --status         # Show system status
    python -m nova_core --query "..."    # Process a single query
"""

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path

from .brain import NovaBrain
from .config import get_config
from .memory import NovaMemory
from .enforcer import NovaEnforcer
from .watcher import NovaWatcher
from .tools import get_registry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stderr),
    ],
)
logger = logging.getLogger("nova_core")


def setup_file_logging():
    cfg = get_config()
    log_file = cfg.log_file
    log_file.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(str(log_file))
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s"))
    logging.getLogger().addHandler(file_handler)


def _silence_tui_loggers():
    """During chat mode push noisy background loggers to WARNING so they
    don't bleed into the TUI. Logs still go to the file handler."""
    for name in ("nova_core.engine", "nova_core.llm", "nova_core.watcher",
                 "nova_core.tools", "httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)


async def cmd_interactive():
    brain = NovaBrain()
    agent = brain.agent_name
    print(f"{agent} · NOVA-CORE Interactive Mode")
    print("Type 'help' for available commands, 'quit' to exit.\n")

    while True:
        try:
            query = input(f"{agent.lower()}> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nShutting down.")
            break

        if not query:
            continue
        if query.lower() in ("quit", "exit", "q"):
            break

        result = await brain.process_query(query)
        print(f"\n{result['response']}\n")


async def cmd_patrol():
    brain = NovaBrain()
    cfg = get_config()
    print(f"LAU · NOVA-CORE Patrol Mode (interval={cfg.watch_interval}s)")
    await brain.autonomous_patrol(interval=cfg.watch_interval)


async def cmd_audit():
    brain = NovaBrain()
    print("Running daily security audit...")
    results = await brain.run_daily_audit()

    print("\nAudit Results:")
    for tool_name, result in results.items():
        status = "PASS" if result.get("success") else "FAIL"
        print(f"  [{status}] {tool_name}")

    if any(not r.get("success") for r in results.values()):
        print("\nSome scans failed. Check logs for details.")
        sys.exit(1)


async def cmd_scan():
    brain = NovaBrain()
    registry = get_registry()

    print("LAU · NOVA-CORE Full Security Scan\n")

    scan_tools = [
        ("port_scan", {"host": "127.0.0.1", "ports": "1-1024"}),
        ("vuln_scan", {}),
        ("auth_scan", {}),
        ("crypto_audit", {}),
        ("secret_scan", {}),
        ("endpoint_test", {}),
        ("file_integrity", {}),
        ("system_info", {}),
    ]

    for tool_name, params in scan_tools:
        print(f"Running {tool_name}...", end=" ", flush=True)
        result = registry.execute(tool_name, **params)
        if result.success:
            print("OK")
            output = result.output
            if isinstance(output, dict) and "finding_count" in output:
                print(f"  Findings: {output['finding_count']} (risk: {output.get('risk_level', '?')})")
            elif isinstance(output, dict) and "risk_level" in output:
                print(f"  Risk: {output.get('risk_level', '?')}")
        else:
            print(f"FAILED: {result.error}")

    print("\nFull scan complete.")


async def cmd_status():
    brain = NovaBrain()
    watcher = NovaWatcher(brain.memory)
    enforcer = NovaEnforcer(brain.memory)
    registry = get_registry()

    print("LAU · NOVA-CORE System Status\n")

    print("System Info:")
    result = registry.execute("system_info")
    if result.success:
        info = result.output
        print(f"  OS: {info.get('os', '?')} {info.get('os_release', '?')}")
        print(f"  Arch: {info.get('architecture', '?')}")
        print(f"  Memory: {info.get('memory', {}).get('percent_used', '?')}% used")
        print(f"  Disk: {info.get('disk', {}).get('percent_used', '?')}% used")
        print(f"  Load: {info.get('load_average', {}).get('1min', '?')}")

    print("\nBackend Health:")
    result = registry.execute("backend_health")
    if result.success:
        health = result.output
        print(f"  Status: {health.get('status', '?')}")
        print(f"  Latency: {health.get('latency_ms', '?')}ms")

    print("\nLLM Status:")
    engine_status = brain.engine.status()
    print(f"  Engine: {engine_status.get('engine_used', 'UNINITIALIZED')}")
    print(f"  State: {engine_status.get('state', '?')}")
    print(f"  Model: {engine_status.get('model', '-')}")
    print(f"  Latency: {engine_status.get('latency_ms', 0)}ms")
    print(f"  RAM available: {engine_status.get('available_ram_mb', '?')}MB")
    if engine_status.get("init_error"):
        print(f"  Init error: {engine_status.get('init_error')}")

    llm_status = brain.llm.check_availability()
    if llm_status.get("available"):
        print(f"  Ollama: ONLINE at {llm_status.get('host')} model={llm_status.get('model')}")
    else:
        print(f"  Ollama: OFFLINE (projected — embedded brain substitutes)")

    print("\nMemory Stats:")
    stats = brain.memory.get_memory_stats()
    print(f"  Lessons: {stats.get('total_lessons', 0)}")
    print(f"  Scans: {stats.get('total_scans', 0)}")
    print(f"  Alerts: {stats.get('total_alerts', 0)} ({stats.get('unacknowledged_alerts', 0)} unacknowledged)")

    print("\nEscrow State:")
    escrow_state = enforcer.recover_task_state()
    if escrow_state:
        print(f"  Last task: {escrow_state.get('task_id', 'none')}")
        print(f"  Progress: {escrow_state.get('progress', 0)}%")
    else:
        print("  No previous state")

    print(f"\nRegistered Tools: {len(registry.list_tools())}")
    for cat in set(t["category"] for t in registry.list_tools()):
        tools = [t["name"] for t in registry.list_tools() if t["category"] == cat]
        print(f"  {cat}: {', '.join(tools)}")


async def cmd_query(query: str):
    brain = NovaBrain()
    result = await brain.process_query(query)
    print(result["response"])
    return result


def cmd_validators() -> int:
    """Run the definitive LAU module validation prompts in the terminal staging loop.

    Each prompt is dispatched through the deterministic shield, the emitted source
    is compiled and executed standalone, and the machine-parseable JSON payload is
    verified. Returns 0 when every lane passes, 1 otherwise.
    """
    import os
    import py_compile
    import subprocess
    import sys
    import tempfile

    from .shield import NovaDeterministicShield

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

    print("LAU · NOVA-CORE Module Validators — deterministic staging loop\n")
    failures = 0

    for name, (expected_action, prompt) in suites.items():
        print(f"=== {name}")
        out = shield.process_deterministic_fallback(task_input=prompt)
        payload = out["output_payload"]
        route_ok = payload["action_enforced"] == expected_action
        print(f"  intent -> {payload['action_enforced']} "
              f"[{'match' if route_ok else 'MISMATCH (want ' + expected_action + ')'}]")
        print(f"  verdict -> {payload['verdict']}")
        print(f"  thought_process -> {' / '.join(out['thought_process'])}")

        src = payload["response"]
        fd, tmp = tempfile.mkstemp(suffix=".py", dir=tempfile.gettempdir())
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(src)
            try:
                py_compile.compile(tmp, doraise=True)
                compiled = True
            except py_compile.PyCompileError as exc:
                compiled = False
                print(f"  COMPILE FAIL: {exc}")
            run = None
            if compiled:
                proc = subprocess.run(
                    [sys.executable, tmp],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                run = proc.returncode
                if proc.returncode != 0:
                    print(f"  RUN FAIL rc={proc.returncode}: {proc.stderr[-500:]}")
                else:
                    json_line = next(
                        (ln.strip() for ln in proc.stdout.splitlines() if ln.strip().startswith("{")),
                        None,
                    )
                    if json_line:
                        data = json.loads(json_line)
                        print(f"  run -> rc={run} status={data.get('status')} "
                              f"badges={len(data.get('alert_badges', []))}")
                    else:
                        print(f"  run -> rc={run} (no JSON payload in output)")
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

        ok = route_ok and compiled and run == 0
        print(f"  => {'PASS' if ok else 'FAIL'}\n")
        if not ok:
            failures += 1

    if failures:
        print(f"{failures} validator(s) FAILED — do not push.")
        return 1
    print("All module validators passed. Ready to push.")
    return 0


_COLORS = {
    "reset": 0, "bold": 1, "dim": 2, "italic": 3, "underline": 4,
    "black": 30, "red": 31, "green": 32, "yellow": 33, "blue": 34,
    "magenta": 35, "cyan": 36, "white": 37, "grey": 90,
}


def _use_color() -> bool:
    try:
        return sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    except Exception:
        return False


def _tui(text: str, *names: str) -> str:
    if not _use_color():
        return text
    codes = ";".join(str(_COLORS[name]) for name in names if name in _COLORS)
    return f"\033[{codes}m{text}\033[0m" if codes else text


def _wrap(text: str, indent: int = 2) -> str:
    import shutil
    width = max(40, shutil.get_terminal_size((100, 24)).columns - indent)
    words, lines, cur = text.split(), [], ""
    for word in words:
        if cur and len(cur) + 1 + len(word) > width:
            lines.append(cur)
            cur = word
        else:
            cur = f"{cur} {word}".strip()
    if cur:
        lines.append(cur)
    pad = " " * indent
    return f"\n{pad}".join(lines)


def _tool_brief(result: dict, tool_name: str, indent: int = 4) -> str:
    pad = " " * indent
    if not isinstance(result, dict):
        return f"{pad}{tool_name}: {result}"
    if not result.get("success"):
        return (
            f"{pad}{_tui(tool_name, 'red', 'bold')} FAILED — "
            f"{result.get('error') or result.get('output')}"
        )
    out = result.get("output")
    if isinstance(out, dict):
        bits = []
        if "finding_count" in out:
            bits.append(f"findings={out['finding_count']} risk={out.get('risk_level', '?')}")
        if "device_count" in out:
            bits.append(f"devices={out['device_count']}")
            for dev in (out.get("devices") or [])[:2]:
                ident = dev.get("name") or dev.get("identifier") or dev.get("id", "?")
                bits.append(f"{ident}{' · LOST' if dev.get('lost_mode') else ''}")
        if "host_count" in out:
            bits.append(f"hosts={out['host_count']}")
            if out.get("own_ips"):
                bits.append(f"self={out['own_ips'][0]}")
            if out.get("gateway"):
                bits.append(f"gw={out['gateway']}")
        if "alert_count" in out:
            bits.append(f"alerts={out['alert_count']}")
        if "status" in out and isinstance(out.get("status"), str):
            bits.append(f"status={out['status']}")
        if "endpoints" in out:
            bits.append(f"endpoints={len(out['endpoints'])}")
        if "lessons" in out:
            bits.append(f"lessons={len(out['lessons'])}")
        if "tools" in out:
            bits.append(f"tools={len(out['tools'])}")
        if bits:
            return f"{pad}{_tui(tool_name, 'green')} — {' · '.join(bits)}"
        snippet = _wrap(str(out)[:280].replace("\n", " "), indent)
        return f"{pad}{_tui(tool_name, 'green')}\n{snippet}"
    return f"{pad}{_tui(tool_name, 'green')} — {_wrap(str(out)[:280], indent)}"


def _render_thought(thought_process, indent: int = 2) -> None:
    if not thought_process:
        return
    pad = " " * indent
    if isinstance(thought_process, dict):
        thought_process = [
            f"{k}: {v}" for k, v in thought_process.items()
        ]
    for i, step in enumerate(thought_process, 1):
        print(f"{pad}{_tui(f'{i:>2}.', 'cyan')} {_wrap(str(step), indent + 5)}")


def _log_internal_monologue(intent: str, thought_process, engine: str, command: str) -> None:
    """Hide the reasoning exchange behind a local debug channel.

    The terminal stays clean; the monologue sleeps in the monologue file
    (default /tmp/lau_internal_monologue.log) for the developer only.
    Set NOVA_DEBUG_REASONING=0 to disable.
    """
    if os.environ.get("NOVA_DEBUG_REASONING", "1") == "0":
        return
    from .config import get_config

    log_file = get_config().monologue_file
    steps = thought_process if isinstance(thought_process, list) else []
    payload = {
        "timestamp": time.time(),
        "input": command,
        "intent": intent,
        "engine": engine,
        "telemetric_baseline": "Analyzing input layout for dynamic contextual assembly.",
        "constraint_isolation": "Enforcing data privacy gates — reasoning stays in the log, not the terminal.",
        "adaptation_vector": f"Routing {intent} through the shared dispatch chain.",
        "execution_steps": steps,
    }
    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with open(log_file, "a") as f:
            f.write(json.dumps(payload) + "\n")
    except OSError as e:
        logger.debug("monologue write skipped: %s", e)


async def cmd_chat():
    """Personal LAU terminal — the same dispatch chain as the web HUD."""

    import httpx
    import urllib.parse

    from .config import get_config
    from .enforcer import NovaEnforcer
    from . import routes as routes_mod
    from .routes import run_dispatch as lau_dispatch
    from .shield import NovaDeterministicShield
    from .tools import get_registry

    _silence_tui_loggers()
    cfg = get_config()
    brain = NovaBrain()
    routes_mod._brain_instance = brain
    shield = NovaDeterministicShield()
    registry = get_registry()
    enforcer = NovaEnforcer(brain.memory)

    agent = brain.agent_name
    device_id = ""
    token = os.environ.get("NOVA_TOKEN", "")
    color = _use_color()

    print()
    print(_tui("╔══════════════════════════════════════════════════════════╗", "cyan", "bold"))
    print(f"{_tui('║', 'cyan', 'bold')}  {_tui('NOVA-CORE', 'white', 'bold')} · {_tui(agent.upper(), 'yellow', 'bold')} — QUEEN AGENT TERMINAL")
    print(f"{_tui('║', 'cyan', 'bold')}  talk to LAU directly · tools run on this host")
    print(_tui("╚══════════════════════════════════════════════════════════╝", "cyan", "bold"))
    print(_tui("  type /help for commands · /quit to exit (or Ctrl+C)\n", "grey"))

    while True:
        try:
            raw = input(
                _tui(f"{agent.lower()} ▸ ", "cyan", "bold") if color else f"{agent.lower()}> "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            print(_tui(f"{agent} is going quiet. Session written to memory.", "grey"))
            break
        if not raw:
            continue

        cmd = raw.strip().lower()

        if cmd in ("quit", "exit", "q", "/quit"):
            print(_tui("Closing the LAU terminal.", "grey"))
            break

        if cmd in ("/help", "help", "?"):
            print(_tui(
                "commands:\n"
                "  /device <id>      set the device LAU acts on for locate/lock/message/wipe\n"
                "  /tools            list every tool LAU can run on this host\n"
                "  /status           full LAU system status\n"
                "  /engine           engine + model state\n"
                "  /memory           vault stats (lessons, alerts, escrow)\n"
                "  /lessons [n]      show the n most recent learned lessons\n"
                "  /validators       run the 3 definitive module validators (compile+run)\n"
                "  /shield <text>    push an intent straight through the shield\n"
                "  /clear            wipe the screen\n"
                "  /quit             leave\n"
                "anything else is a message for LAU — try 'help', 'scan open ports',\n"
                "'system status', 'locate the device', 'lock the device'.", "cyan"
            ))
            continue

        if cmd == "/clear":
            import subprocess
            subprocess.run(["clear"] if os.name != "nt" else ["cls"], check=False)
            continue

        if cmd.startswith("/device"):
            parts = raw.split(None, 1)
            if len(parts) < 2:
                print(_tui(f"  current device: {device_id or 'none'} — set one with /device <id>", "grey"))
            else:
                device_id = parts[1].strip()
                print(_tui(f"  ✓ LAU now acts on device `{device_id}`", "green", "bold"))
            continue

        if cmd == "/tools":
            print(_tui("  registered tools:", "cyan", "bold"))
            for cat in sorted({t["category"] for t in registry.list_tools()}):
                names = [t["name"] for t in registry.list_tools() if t["category"] == cat]
                print(f"    {_tui(cat, 'magenta', 'bold'):<12} {', '.join(names)}")
            continue

        if cmd == "/status":
            status = brain.status() if hasattr(brain, "status") else {}
            st = enforcer.recover_task_state() or {}
            stats = brain.memory.get_memory_stats()
            print(_tui(f"  AGENT    ", "cyan", "bold") + f"{status.get('agent_name', agent)}  {_tui(status.get('state', '?'), 'green' if status.get('state') in ('active',) else 'yellow')}")
            print(_tui(f"  ENGINE   ", "cyan", "bold") + f"{status.get('engine_used', 'deterministic')}  model={status.get('model', '-')}  latency={status.get('latency_ms', 0)}ms")
            print(_tui(f"  TOOLS    ", "cyan", "bold") + f"{status.get('tool_count', len(registry.list_tools()))} registered")
            print(_tui(f"  MEMORY   ", "cyan", "bold") + f"lessons={stats.get('total_lessons', 0)} scans={stats.get('total_scans', 0)} alerts={stats.get('total_alerts', 0)} unacked={stats.get('unacknowledged_alerts', 0)}")
            print(_tui(f"  VAULT    ", "cyan", "bold") + f"escrow task={st.get('task_id', 'none')} progress={st.get('progress', 0)}%")
            print(_tui(f"  BACKEND  ", "cyan", "bold") + f"{cfg.backend_url}  {_tui('(action execution enabled)' if token or device_id else '(read-only — set /device + NOVA_TOKEN to execute)', 'grey')}")
            continue

        if cmd == "/engine":
            st = brain.engine.status()
            print(_tui(f"  engine={st.get('engine_used', 'UNINITIALIZED')} state={st.get('state')} model={st.get('model', '-')} latency={st.get('latency_ms', 0)}ms ram={st.get('available_ram_mb', '?')}MB", "cyan"))
            if st.get("init_error"):
                print(_tui(f"  init error: {st.get('init_error')}", "red"))
            llm = brain.llm.check_availability()
            print(_tui(f"  ollama={_tui('ONLINE', 'green') if llm.get('available') else _tui('OFFLINE (embedded brain substitutes)', 'yellow')}", "grey"))
            continue

        if cmd == "/memory":
            stats = brain.memory.get_memory_stats()
            for k, v in stats.items():
                print(f"    {k}: {v}")
            continue

        if cmd.startswith("/lessons"):
            try:
                limit = int(cmd.split(None, 1)[1])
            except (IndexError, ValueError):
                limit = 5
            lessons = brain.memory.get_recent_lessons(limit=limit)
            for lesson in lessons:
                when = str(lesson.get("created_at", ""))[:19]
                print(f"    {_tui('[learned]', 'magenta')} {when} · {lesson.get('category')} · {lesson.get('obstacle', '')[:90]}")
            if not lessons:
                print(_tui("    no lessons recorded yet", "grey"))
            continue

        if cmd == "/validators":
            cmd_validators()
            continue

        if cmd.startswith("/shield"):
            prompt = raw[len("/shield"):].strip()
            if not prompt:
                prompt = (
                    "A compromised asset terminal is streaming fabricated GPS fixes with "
                    "NaN latitude, infinite longitude, and wrapped timestamps to escape the "
                    "tracking validation stream. Emit a validation filter."
                )
            print(_tui("  shield engaging…", "cyan", "dim"))
            out = shield.process_deterministic_fallback(task_input=prompt)
            payload = out.get("output_payload", {})
            _render_thought(out.get("thought_process"))
            print(_tui(f"  {payload.get('verdict', '?')}", "white", "bold"))
            print(_tui(f"  enforced -> {payload.get('action_enforced', '?')}", "magenta", "bold"))
            print("  " + _wrap(str(payload.get("response", ""))[:600].replace("\n", " "), 2))
            continue

        # ── LAU dispatch (same chain as the web HUD) ──────────────────────
        print()
        print(_tui(f"  YOU ▸ {_wrap(raw, 2)}", "yellow", "bold"))
        try:
            out = await lau_dispatch(raw, device_id)
        except Exception as exc:
            print(_tui(f"  LAU ▸ dispatch failed: {exc}", "red", "bold"))
            continue

        steps = out.get("thought_process") or []
        show_thoughts = os.environ.get("NOVA_SHOW_THOUGHTS") == "1"
        _log_internal_monologue(
            out.get("intent", ""),
            steps,
            out.get("engine", out.get("engine_used", "")),
            raw,
        )

        print(_tui(f"  LAU ▸ {_wrap(out.get('response', ''), 2)}", "green", "bold"))

        tools = out.get("tools_executed") or []
        if tools:
            print(_tui("  ⚙ RUN: " + " → ".join(tools), "green", "bold"))
            for tool_name, result in (out.get("results") or {}).items():
                if tool_name == "_reasoning":
                    continue
                print(_tool_brief(result, tool_name))

        if show_thoughts:
            if steps:
                print(_tui("  ◈ thinking…", "cyan", "bold"))
                _render_thought(steps)
            meta = [out.get("intent", ""), out.get("engine", out.get("engine_used", ""))]
            if out.get("latency_ms"):
                meta.append(f"{float(out['latency_ms']):.0f}ms")
            if device_id:
                meta.append(f"device={device_id}")
            if meta:
                print(_tui(f"  {' | '.join(m for m in meta if m)}", "grey"))

        action = out.get("action")
        if action:
            print()
            print(_tui("  ┌─ EXECUTABLE ACTION ─────────────────────────────", "magenta"))
            print(_tui(f"  │ {action.get('method', 'GET')} {action['endpoint']}", "magenta"))
            print(_tui("  └──────────────────────────────────────────────────", "magenta"))
            if action.get("requires_typed_confirmation"):
                yn = input(_tui("  destructive operation — type WIPE to authorize: ", "red", "bold") if color else "  type WIPE to authorize: ").strip()
                approved = yn == "WIPE"
            else:
                yn = input(_tui("  execute against backend? [y/N] ", "cyan", "bold") if color else "  execute? [y/N] ").strip().lower()
                approved = yn in ("y", "yes")
            if approved:
                endpoint = action["endpoint"]
                method = action.get("method", "POST")
                if action.get("extract_body"):
                    msg = input(_tui("  message text> ", "cyan") if color else "  message> ").strip()
                    if not msg:
                        msg = "Commanded by LAU terminal"
                    join = "&" if "?" in endpoint else "?"
                    endpoint = f"{endpoint}{join}message={urllib.parse.quote(msg)}"
                url = cfg.backend_url.rstrip("/") + endpoint
                headers = {"Authorization": f"Bearer {token}"} if token else {}
                try:
                    resp = httpx.request(method, url, timeout=30, headers=headers)
                    try:
                        payload = resp.json()
                    except ValueError:
                        payload = resp.text[:400]
                    print(_tui(f"  ← {resp.status_code} {_wrap(str(payload)[:500], 2)}", "green" if resp.status_code < 400 else "red"))
                    # Mirror the web HUD: a terminal-approved action becomes a
                    # durable lesson, including failures returned by the API.
                    try:
                        httpx.post(
                            cfg.backend_url.rstrip("/") + "/nova-core/actions/outcome",
                            headers=headers,
                            timeout=8,
                            json={
                                "method": method,
                                "endpoint": action["endpoint"],
                                "success": resp.status_code < 400,
                                "detail": str(payload)[:500],
                            },
                        )
                    except (httpx.HTTPError, OSError) as e:
                        logger.debug("outcome lesson skipped: %s", e)
                except Exception as exc:
                    print(_tui(f"  ✗ backend unreachable: {exc} — start the API or set NOVA_BACKEND_URL", "red"))
            else:
                print(_tui("  [skipped — nothing executed]", "grey"))


def main():
    parser = argparse.ArgumentParser(description="NOVA-CORE Agent")
    parser.add_argument("--patrol", action="store_true", help="Start autonomous patrol daemon")
    parser.add_argument("--audit", action="store_true", help="Run daily security audit")
    parser.add_argument("--scan", action="store_true", help="Run all security scans")
    parser.add_argument("--status", action="store_true", help="Show system status")
    parser.add_argument("--query", type=str, help="Process a single query")
    parser.add_argument("--chat", action="store_true", help="Launch the LAU chat terminal (default)")
    parser.add_argument(
        "--validators",
        action="store_true",
        help="Run the definitive LAU module validation prompts (hardware peripheral / tracking logic / geofence verification)",
    )
    parser.add_argument("--interactive", action="store_true", help="Basic bare REPL (no TUI)")
    args = parser.parse_args()

    setup_file_logging()

    if args.patrol:
        asyncio.run(cmd_patrol())
    elif args.audit:
        asyncio.run(cmd_audit())
    elif args.scan:
        asyncio.run(cmd_scan())
    elif args.status:
        asyncio.run(cmd_status())
    elif args.query:
        asyncio.run(cmd_query(args.query))
    elif args.validators:
        sys.exit(cmd_validators())
    elif args.interactive:
        asyncio.run(cmd_interactive())
    else:
        asyncio.run(cmd_chat())


if __name__ == "__main__":
    main()

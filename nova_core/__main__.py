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
import sys
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
        logging.StreamHandler(),
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


def main():
    parser = argparse.ArgumentParser(description="NOVA-CORE Agent")
    parser.add_argument("--patrol", action="store_true", help="Start autonomous patrol daemon")
    parser.add_argument("--audit", action="store_true", help="Run daily security audit")
    parser.add_argument("--scan", action="store_true", help="Run all security scans")
    parser.add_argument("--status", action="store_true", help="Show system status")
    parser.add_argument("--query", type=str, help="Process a single query")
    parser.add_argument("--interactive", action="store_true", help="Interactive mode (default)")
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
    else:
        asyncio.run(cmd_interactive())


if __name__ == "__main__":
    main()

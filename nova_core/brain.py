"""NOVA-CORE agent brain — the orchestrator.

Ties together memory, tools, watcher, and enforcer into
a coherent agent loop. Can operate in autonomous mode
(watchdog loop) or interactive mode (single query response).
"""

import asyncio
import json
import logging
import time
from typing import Optional, List, Dict, Any
from pathlib import Path

from .config import get_config
from .memory import NovaMemory
from .enforcer import NovaEnforcer
from .watcher import NovaWatcher
from .llm import NovaLLM
from .engine import get_engine
from .tools import get_registry, ToolRegistry

logger = logging.getLogger("nova_core.brain")


class AgentContext:
    def __init__(self):
        self.current_task: Optional[str] = None
        self.task_history: List[dict] = []
        self.environment_state: dict = {}
        self.last_thought: str = ""
        self.cycle_count: int = 0


class NovaBrain:
    def __init__(self):
        self.cfg = get_config()
        self.memory = NovaMemory()
        self.enforcer = NovaEnforcer(self.memory)
        self.watcher = NovaWatcher(self.memory)
        self.tools = get_registry()
        self.llm = NovaLLM()
        self.engine = get_engine()
        self.engine.start_async()
        self.context = AgentContext()
        self._system_prompt = self._load_system_prompt()
        self.agent_name = self.cfg.agent_name

    @property
    def llm_available(self) -> bool:
        return self.engine.state == "ready"

    @property
    def engine_used(self) -> str:
        return self.engine.engine_used if self.engine.engine_used != "UNINITIALIZED" else (
            "DETERMINISTIC_SHIELD" if self.engine.state == "shield_only" else "UNINITIALIZED"
        )

    def _load_system_prompt(self) -> str:
        prompt_path = Path(__file__).parent / "prompts" / "system_prompt.md"
        if prompt_path.exists():
            return prompt_path.read_text()
        return f"You are {self.agent_name}, the security agent of NOVA-CORE for NovaGPS."

    async def process_query(self, query: str) -> dict:
        start = time.time()

        self.context.current_task = query
        self.context.cycle_count += 1

        recent_lessons = self.memory.get_recent_lessons(limit=10)
        system_state = self.watcher.get_current_snapshot()
        pending_alerts = self.memory.get_alerts(acknowledged=False, limit=5)

        results = {}

        if self.llm_available:
            results = await self._process_with_engine(query, recent_lessons, system_state)
        elif self.llm.is_available():
            results = await self._process_with_ollama(query, recent_lessons, system_state)
        else:
            parsed = self._parse_request(query)

            for action in parsed.get("actions", []):
                tool_name = action.get("tool")
                params = action.get("params", {})

                if tool_name:
                    result = self.tools.execute(tool_name, **params)
                    results[tool_name] = result.to_dict()

            if not results and parsed.get("intent") == "status":
                results = await self._status_response()
            elif not results and parsed.get("intent") == "help":
                results = {"help": {"text": self._help_text()}}

            results["_reasoning"] = {
                "success": True,
                "output": self.engine.execute_reasoning_loop(
                    self._system_prompt,
                    f"Query: {query}\n\nTools running offline fallback; confirm posture.",
                ),
            }

        reasoning_doc = results.get("_reasoning", {})
        if isinstance(reasoning_doc, dict):
            reasoning_doc = reasoning_doc.get("output", {})

        response = self._synthesize_response(query, results, recent_lessons)

        self.memory.record_lesson(
            "agent_query",
            f"Query: {query[:100]}",
            f"Executed {len(results)} tool calls",
            json.dumps(results, default=str)[:500],
            severity="info",
            engine_used=self.engine_used,
        )

        if isinstance(reasoning_doc, dict):
            payload = reasoning_doc
            lesson_delta = payload.get("output_payload", {}).get("response", "")
            self.memory.record_lesson(
                "learned_reasoning",
                f"Cycle {self.context.cycle_count} reasoning on: {query[:100]}",
                f"{payload.get('engine', 'ENGINE')} verdict: "
                f"{payload.get('output_payload', {}).get('verdict', '')}",
                str(lesson_delta)[:500],
                severity="info",
                tags=self.agent_name,
                engine_used=self.engine_used,
            )

        duration_ms = (time.time() - start) * 1000

        return {
            "query": query,
            "response": response,
            "tools_executed": list(results.keys()),
            "results": results,
            "duration_ms": round(duration_ms, 2),
            "cycle": self.context.cycle_count,
            "llm_enabled": self.llm_available,
            "engine_used": self.engine_used,
            "agent": self.agent_name,
        }

    def _route_reasoning(self, query: str, state_summary: str) -> dict:
        task_input = (
            f"Query: {query}\n\n"
            f"Observed context:\n{state_summary}\n\n"
            "Provide a concise security verdict and any directives for the operator."
        )
        result = self.engine.execute_reasoning_loop(self._system_prompt, task_input)
        return {"success": True, "output": result}

    async def _process_with_engine(self, query: str, lessons: list, system_state: dict) -> dict:
        """Embedded llama-cpp primary path: rule-based tool dispatch + native reasoning."""
        parsed = self._parse_request(query)
        results = {}

        for action in parsed.get("actions", []):
            tool_name = action.get("tool")
            params = action.get("params", {})
            if tool_name:
                result = self.tools.execute(tool_name, **params)
                results[tool_name] = result.to_dict()

        if not results and parsed.get("intent") == "status":
            results = await self._status_response()
        elif not results and parsed.get("intent") == "help":
            results = {"help": {"text": self._help_text()}}

        state_summary = json.dumps({
            "lessons": [l.get("obstacle", "")[:100] for l in lessons[:3]],
            "system_state": system_state,
            "tools_run": list(results.keys()),
            "results": {k: (v.get("output", {}) if isinstance(v, dict) else v) for k, v in results.items()},
        }, default=str)[:1500]

        loop = asyncio.get_event_loop()
        results["_reasoning"] = await loop.run_in_executor(
            None,
            lambda: self._route_reasoning(query, state_summary),
        )
        return results

    async def _process_with_ollama(self, query: str, lessons: list, system_state: dict) -> dict:
        tool_schemas = self.tools.get_schema()
        selected = self.llm.select_tool(query, tool_schemas)

        results = {}
        if not selected:
            loop = asyncio.get_event_loop()
            ok, answer = await loop.run_in_executor(None, lambda: self.llm.generate(
                query,
                system=self._system_prompt,
            ))
            results["llm_response"] = {"success": ok, "output": answer}
            return results

        for tool_name in selected:
            result = self.tools.execute(tool_name)
            results[tool_name] = result.to_dict()

        state_summary = json.dumps({
            "lessons": [l.get("obstacle", "")[:100] for l in lessons[:3]],
            "system_state": system_state,
            "tools_run": selected,
            "results": {k: v.get("output", {}) for k, v in results.items()},
        }, default=str)[:1500]

        loop = asyncio.get_event_loop()
        ok, reasoning = await loop.run_in_executor(
            None,
            lambda: self.llm.reason(state_summary, query),
        )
        results["_reasoning"] = {"success": ok, "output": reasoning}

        return results

    async def _status_response(self) -> dict:
        results = {}
        for tool_name in ["system_info", "backend_health"]:
            result = self.tools.execute(tool_name)
            results[tool_name] = result.to_dict()
        results["memory_stats"] = {"success": True, "output": self.memory.get_memory_stats()}
        results["pending_alerts"] = {"success": True, "output": self.memory.get_alerts(acknowledged=False, limit=5)}
        results["engine_status"] = {
            "success": True,
            "output": self.engine.status(),
        }
        return results

    def _parse_request(self, query: str) -> dict:
        query_lower = query.lower()
        actions = []

        tool_mappings = {
            "port scan": "port_scan",
            "scan ports": "port_scan",
            "open ports": "port_scan",
            "vulnerability": "vuln_scan",
            "vuln scan": "vuln_scan",
            "security scan": "vuln_scan",
            "auth test": "auth_scan",
            "test auth": "auth_scan",
            "crypto audit": "crypto_audit",
            "secret scan": "secret_scan",
            "find secrets": "secret_scan",
            "leaked keys": "secret_scan",
            "fuzz": "api_fuzzer",
            "fuzz api": "api_fuzzer",
            "injection test": "injection_test",
            "test injection": "injection_test",
            "system info": "system_info",
            "system status": "system_info",
            "server status": "system_info",
            "process list": "process_list",
            "running processes": "process_list",
            "read log": "log_reader",
            "check logs": "log_reader",
            "file integrity": "file_integrity",
            "integrity check": "file_integrity",
            "network test": "connectivity_probe",
            "connectivity": "connectivity_probe",
            "dns": "dns_resolve",
            "resolve dns": "dns_resolve",
            "backend health": "backend_health",
            "health check": "backend_health",
            "check health": "backend_health",
            "list devices": "device_enum",
            "devices": "device_enum",
            "alerts": "alert_check",
            "check alerts": "alert_check",
            "metrics": "metrics_collect",
            "prometheus": "metrics_collect",
            "test endpoints": "endpoint_test",
            "endpoint test": "endpoint_test",
            "complexity": "complexity_scan",
            "code complexity": "complexity_scan",
            "dependencies": "dependency_audit",
            "check deps": "dependency_audit",
            "duplicate exports": "duplicate_export_scan",
            "traceroute": "traceroute",
            "mtu test": "mtu_test",
            "bandwidth": "bandwidth_test",
            "payload": "payload_gen",
            "generate payload": "payload_gen",
        }

        for phrase, tool_name in tool_mappings.items():
            if phrase in query_lower:
                params = {}
                if tool_name == "port_scan":
                    import re
                    port_match = re.search(r"ports?\s+(\d+[\-\d,]*)", query_lower)
                    if port_match:
                        params["ports"] = port_match.group(1)
                if tool_name == "dns_resolve":
                    import re
                    domain_match = re.search(r"(?:dns|resolve)\s+(\S+)", query_lower)
                    if domain_match:
                        params["domain"] = domain_match.group(1)
                if tool_name == "log_reader":
                    import re
                    search_match = re.search(r"(?:search|grep|find)\s+(.+?)(?:\s+in\s+log|\s*$)", query_lower)
                    if search_match:
                        params["search"] = search_match.group(1)
                if tool_name == "payload_gen":
                    params["category"] = "sqli" if "sqli" in query_lower else \
                                         "xss" if "xss" in query_lower else \
                                         "cmdi" if "cmd" in query_lower else "sqli"

                actions.append({"tool": tool_name, "params": params})

        if not actions:
            if any(w in query_lower for w in ["status", "overview", "dashboard", "summary"]):
                return {"intent": "status", "actions": []}
            elif any(w in query_lower for w in ["help", "what can you do", "capabilities"]):
                return {"intent": "help", "actions": []}

        return {"intent": "execute", "actions": actions}

    def _synthesize_response(self, query: str, results: dict, lessons: list) -> str:
        if not results:
            return self._help_text()

        parts = []

        if "llm_response" in results:
            llm_resp = results["llm_response"]
            if llm_resp.get("success"):
                parts.append(str(llm_resp.get("output", "")).strip())
            else:
                parts.append(f"LLM error: {llm_resp.get('error')}")

        if "_reasoning" in results:
            only_reasoning = len(results) == 1
            reasoning = results.pop("_reasoning")
            if only_reasoning and reasoning.get("success"):
                output = reasoning.get("output")
                if isinstance(output, dict):
                    engine = output.get("engine", "")
                    payload = output.get("output_payload") or {}
                    verdict = str(payload.get("verdict", ""))
                    benign = "NOMINAL" in verdict and not payload.get("alert_badges")
                    if engine != "EMBEDDED_LLM" and benign:
                        # No model online and no threat raised — answer like a person,
                        # not like a log sink.
                        return self._conversational_response(query)
            if reasoning.get("success"):
                output = reasoning.get("output")
                if isinstance(output, dict):
                    payload = output.get("output_payload", {}) or {}
                    parts.append(
                        f"[{output.get('engine', 'ENGINE')} · {output.get('latency_ms', 0)}ms]\n"
                        f"{payload.get('response', 'NOVA processed.')}"
                    )
                else:
                    parts.append(f"NOVA-CORE reasoning:\n{output}")
            else:
                parts.append(f"Reasoning stream error: {reasoning.get('error')}")

        for tool_name, result in results.items():
            if not isinstance(result, dict):
                parts.append(f"**{tool_name}:** {result}")
                continue
            if not result.get("success"):
                parts.append(f"Tool '{tool_name}' failed: {result.get('error', 'unknown error')}")
                continue

            output = result.get("output", {})
            if isinstance(output, dict):
                formatted = self._format_output(tool_name, output)
                if formatted:
                    parts.append(f"**{tool_name}:** {formatted}")
            elif output:
                parts.append(f"**{tool_name}:** {output}")

        if lessons:
            query_words = [w for w in query.lower().split() if len(w) > 3][:4]
            relevant = [l for l in lessons if any(
                kw in l.get("obstacle", "").lower() for kw in query_words
            )]
            if relevant:
                parts.append(f"\nRelevant lessons learned:")
                for l in relevant[:3]:
                    parts.append(f"  - {l['obstacle'][:80]}")

        return "\n\n".join(parts)

    def _conversational_response(self, query: str) -> str:
        """Deterministic-mode chit-chat: echo, stay in character, stay honest."""
        q = query.strip()
        lowered = q.lower()
        stats = self.memory.get_memory_stats()

        if any(p in lowered for p in (
            "how are you", "how's it going", "how's life", "how are things",
            "are you ok", "are you okay", "you alive", "you awake",
        )):
            return (
                f"I'm sharp — all systems green, running on the {self.engine_used} engine, "
                f"{stats.get('total_lessons', 0)} lessons banked in memory. "
                f"What do you want me to tackle, boss?"
            )

        if any(p in lowered for p in ("thank", "thanks", "appreciate", "good job", "nice work")):
            return "Any time. Keep the platform healthy and nobody can touch it. What's next?"

        if any(p in lowered for p in (
            "what do you do", "what can you do", "what are you capable", "your skills",
            "show me what", "capabilities",
        )):
            return self._help_text()

        if any(p in lowered for p in ("are you there", "you there", "are you alive", "are you awake")):
            return "Always. I'm awake, memory intact, engines warm. Give me a target and I'm yours."

        tool_names = ", ".join(t["name"] for t in self.tools.list_tools()[:10])
        return (
            f"I heard you say: \"{q}\". "
            f"The reasoning model isn't connected right now, so I won't fake a free-form answer — "
            f"but I'm fully operational on tools. Ask me to \"scan open ports\", \"system status\", "
            f"\"run the shield validators\", or name any of these and I'll execute it: {tool_names}."
        )

    def _format_output(self, tool_name: str, output: dict) -> str:
        formatters = {
            "port_scan": lambda o: f"Scanned {o.get('scanned', 0)} ports on {o.get('host', '?')}. {o.get('open_count', 0)} open: {[p['port'] for p in o.get('open_ports', [])]}",
            "vuln_scan": lambda o: f"{o.get('finding_count', 0)} findings (risk: {o.get('risk_level', '?')}). " + "; ".join(f.get("check", "") for f in o.get("findings", [])[:5]),
            "auth_scan": lambda o: f"{o.get('finding_count', 0)} auth findings. Risk: {o.get('risk_level', '?')}",
            "crypto_audit": lambda o: f"{o.get('finding_count', 0)} crypto findings",
            "secret_scan": lambda o: f"Scanned {o.get('files_scanned', 0)} files. {o.get('finding_count', 0)} secrets found. Risk: {o.get('risk_level', '?')}",
            "system_info": lambda o: f"OS: {o.get('os', '?')}, Arch: {o.get('architecture', '?')}, Memory: {o.get('memory', {}).get('percent_used', '?')}%, Disk: {o.get('disk', {}).get('percent_used', '?')}%",
            "backend_health": lambda o: f"Backend: {o.get('status', '?')}, Latency: {o.get('latency_ms', '?')}ms",
            "device_enum": lambda o: f"{o.get('device_count', 0)} devices registered",
            "endpoint_test": lambda o: f"{o.get('passed', 0)}/{o.get('total', 0)} endpoints passing. Health: {o.get('health', '?')}",
            "memory_stats": lambda o: f"Lessons: {o.get('total_lessons', 0)}, Scans: {o.get('total_scans', 0)}, Alerts: {o.get('total_alerts', 0)} ({o.get('unacknowledged_alerts', 0)} unacknowledged)",
            "pending_alerts": lambda o: f"{len(o)} pending alerts" if isinstance(o, list) else f"{o.get('count', 0)} alerts",
            "engine_status": lambda o: f"LLM {'ONLINE' if o.get('state') == 'ready' else 'OFFLINE'} engine={o.get('engine_used', '?')} model={o.get('model', '-')} latency={o.get('latency_ms', 0)}ms state={o.get('state', '?')}",
            "log_reader": lambda o: f"{o.get('total_matching', 0)} lines match. Errors: {o.get('errors_found', 0)}, Warnings: {o.get('warnings_found', 0)}",
            "process_list": lambda o: f"{o.get('count', 0)} processes running",
            "connectivity_probe": lambda o: f"{o.get('successes', 0)}/{o.get('retries', 0)} attempts. Latency: {o.get('latency_ms', {}).get('avg', '?')}ms avg",
            "file_integrity": lambda o: f"Checked {o.get('checked', 0)} files for integrity",
            "injection_test": lambda o: f"{o.get('finding_count', 0)} injection vectors found. Risk: {o.get('risk_level', '?')}",
            "api_fuzzer": lambda o: f"{o.get('rounds', 0)} rounds. Server errors: {o.get('server_errors', 0)}, Unexpected: {o.get('unexpected_responses', 0)}",
            "metrics_collect": lambda o: f"{o.get('metric_count', 0)} metrics collected",
            "alert_check": lambda o: f"{o.get('alert_count', 0)} alerts",
            "complexity_scan": lambda o: f"{o.get('total_functions', 0)} functions analyzed. {len(o.get('high_complexity', []))} high complexity",
            "dependency_audit": lambda o: f"{o.get('total', 0)} dependencies audited ({o.get('python_deps', 0)} Python, {o.get('js_deps', 0)} JS)",
            "duplicate_export_scan": lambda o: f"Scanned {o.get('files_scanned', 0)} files. {o.get('duplicates_found', 0)} duplicate exports",
            "dns_resolve": lambda o: f"DNS resolved: {o.get('domain', '')}",
            "traceroute": lambda o: f"Traced {o.get('hop_count', 0)} hops to {o.get('host', '')}",
            "mtu_test": lambda o: f"Effective MTU: {o.get('effective_mtu', 0)}",
            "bandwidth_test": lambda o: f"{o.get('bandwidth_mbps', 0)} Mbps to {o.get('host', '')}",
            "payload_gen": lambda o: f"Generated {o.get('count', 0)} {o.get('category', '')} payloads",
        }

        formatter = formatters.get(tool_name)
        if formatter:
            try:
                return formatter(output)
            except Exception:
                pass

        return json.dumps(output, indent=2, default=str)[:500]

    def _help_text(self) -> str:
        tools = self.tools.list_tools()
        categories = {}
        for t in tools:
            cat = t["category"]
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(t["name"])

        parts = [f"{self.agent_name} · NOVA-CORE Agent — learning persists in /var/data/nova_vault. Available Commands:"]
        for cat, tool_names in sorted(categories.items()):
            parts.append(f"\n{cat.upper()}: {', '.join(tool_names)}")

        parts.append("\nExample queries:")
        parts.append("  'scan open ports on 127.0.0.1'")
        parts.append("  'run vulnerability scan'")
        parts.append("  'check backend health'")
        parts.append("  'scan for leaked secrets'")
        parts.append("  'system status overview'")
        parts.append("  'fuzz the API'")

        return "\n".join(parts)

    async def autonomous_patrol(self, interval: int = 300):
        logger.info("NOVA-CORE autonomous patrol starting (interval=%ds)", interval)

        self.enforcer.save_task_state("patrol", "Starting autonomous patrol cycle")

        while True:
            try:
                self.context.cycle_count += 1

                health = await self.watcher.run_single_scan()

                if any(a.get("severity") == "critical" for a in health.get("anomalies", [])):
                    logger.warning("Critical anomaly detected — running emergency scan")
                    await self._emergency_scan()

                self.enforcer.save_task_state(
                    "patrol",
                    f"Cycle {self.context.cycle_count} complete",
                    progress=min(1.0, self.context.cycle_count / 100),
                )

            except Exception as e:
                logger.error("Patrol cycle error: %s", e)
                self.memory.record_lesson(
                    "patrol_error",
                    f"Patrol cycle {self.context.cycle_count} failed: {e}",
                    "Will retry next cycle",
                    f"consecutive_errors={self.context.cycle_count}",
                    severity="error",
                )

            await asyncio.sleep(interval)

    async def _emergency_scan(self):
        critical_tools = ["vuln_scan", "auth_scan", "secret_scan", "backend_health"]
        results = {}
        for tool_name in critical_tools:
            try:
                result = self.tools.execute(tool_name)
                results[tool_name] = result.to_dict()
            except Exception as e:
                results[tool_name] = {"error": str(e)}

        self.memory.record_lesson(
            "emergency_scan",
            "Emergency scan triggered by critical anomaly",
            f"Executed {len(results)} scans",
            json.dumps(results, default=str)[:500],
            severity="critical",
        )

    async def run_daily_audit(self):
        logger.info("Running daily security audit")

        audit_tools = [
            ("secret_scan", {}),
            ("vuln_scan", {}),
            ("auth_scan", {}),
            ("crypto_audit", {}),
            ("file_integrity", {}),
            ("endpoint_test", {}),
            ("dependency_audit", {}),
            ("complexity_scan", {}),
        ]

        all_results = {}
        for tool_name, params in audit_tools:
            try:
                result = self.tools.execute(tool_name, **params)
                all_results[tool_name] = result.to_dict()
            except Exception as e:
                all_results[tool_name] = {"error": str(e)}

        self.enforcer.take_integrity_snapshot()
        self.memory.record_lesson(
            "daily_audit",
            f"Completed daily audit: {len(audit_tools)} scans",
            json.dumps({k: v.get("success", False) for k, v in all_results.items()}),
            json.dumps(all_results, default=str)[:1000],
            severity="info",
        )

        self.enforcer.force_memory_flush()
        return all_results

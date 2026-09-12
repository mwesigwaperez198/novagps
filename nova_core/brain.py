"""NOVA-CORE agent brain — the orchestrator.

Ties together memory, tools, watcher, and enforcer into
a coherent agent loop. Can operate in autonomous mode
(watchdog loop) or interactive mode (single query response).
"""

import asyncio
import hashlib
import json
import logging
import re
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


def format_device_lookup(o: dict, indent: int = 0) -> str:
    """Render a device lookup (IMEI/serial/identifier) result as a device card."""
    pad = " " * indent
    count = o.get("device_count", 0)
    if count == 0:
        return f"0 devices for '{o.get('query', '')}': {o.get('message', 'no match')}"
    lines = [f"{count} device(s) for '{o.get('query', '')}'"]
    for d in o.get("devices") or []:
        ident = d.get("name") or d.get("identifier") or d.get("id", "?")
        lines.append(f"• {ident}")
        lines.append(f"  imei={d.get('imei') or '—'} serial={d.get('serial') or '—'}")
        lines.append(
            f"  model={d.get('model') or '?'} {d.get('manufacturer') or ''} {d.get('os_type') or ''}"
            f" {d.get('os_version') or ''} ({d.get('device_type') or '?'})"
        )
        ip_row = []
        if d.get("ip_address"):
            ip_row.append(f"public {d['ip_address']}")
        if d.get("local_ip"):
            ip_row.append(f"local {d['local_ip']}")
        if d.get("carrier"):
            ip_row.append(f"carrier {d['carrier']}")
        if ip_row:
            lines.append(f"  {', '.join(ip_row)}")
        state = "ACTIVE" if d.get("active") else "INACTIVE"
        if d.get("lost_mode"):
            state += " · LOST MODE"
        lines.append(f"  {state}")
        if d.get("last_lat") is not None and d.get("last_lon") is not None:
            place = d.get("last_place")
            place_s = f" near {place}" if place else ""
            speed = d.get("last_speed")
            speed_s = f" @ {speed} m/s" if speed is not None else ""
            lat = f"{float(d['last_lat']):.6f}".rstrip("0").rstrip(".")
            lon = f"{float(d['last_lon']):.6f}".rstrip("0").rstrip(".")
            lines.append(
                f"  last fix: {lat},{lon}{place_s}{speed_s}"
                f"  ({d.get('last_seen') or 'unknown'})"
            )
        else:
            lines.append("  last fix: none yet")
    return ("\n" + pad).join(lines)


def format_packet_capture(o: dict, indent: int = 0) -> str:
    """Render a packet capture result as a readable traffic panel."""
    pad = " " * indent
    total = o.get("total_packets", 0)
    senders = o.get("senders") or []
    receivers = o.get("receivers") or []
    protos = o.get("protocol_distribution") or {}
    dns = o.get("dns_queries") or []
    conns = o.get("tcp_connections") or []

    lines = [f"{total} packets ({o.get('engine', '?')})"]
    lines.append(f"senders: {', '.join(senders) or 'none'}")
    lines.append(f"receivers: {', '.join(receivers) or 'none'}")
    if protos:
        dist = ", ".join(f"{k or '?'}={v}" for k, v in sorted(protos.items()))
        lines.append(f"protocols: {dist}")
    if dns:
        lines.append(f"DNS ({len(dns)}):")
        for q in dns[:10]:
            ans = q.get("answer", "")
            suffix = f" → {ans}" if ans else ""
            lines.append(f"  {q.get('query', '?')}{suffix}")
    if conns:
        lines.append(f"TCP ({len(conns)}):")
        for c in conns[:10]:
            lines.append(
                f"  {c.get('src', '?')}:{c.get('src_port', '')} → "
                f"{c.get('dst', '?')}:{c.get('dst_port', '')} [{c.get('flags', '')}]"
            )
    return ("\n" + pad).join(lines)


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

        response = self._synthesize_response(query, results)

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
        parsed = self._parse_request(query)
        results = {}
        loop = asyncio.get_event_loop()

        if parsed.get("intent") == "status":
            results.update(await self._status_response())
            return results

        if parsed.get("intent") == "help":
            results["help"] = {"text": self._help_text()}
            return results

        if parsed.get("actions"):
            loop = asyncio.get_event_loop()
            actions = parsed.get("actions", [])
            jobs = [
                (a.get("tool"), a.get("params", {}))
                for a in actions if a.get("tool")
            ]
            if jobs:
                runner = asyncio.gather(*[
                    loop.run_in_executor(None, lambda n=t, p=p: self.tools.execute(n, **p))
                    for t, p in jobs
                ])
                executed = await runner
                for (tool_name, _), result in zip(jobs, executed):
                    if result:
                        results[tool_name] = result.to_dict()
            return results

        ok, answer = await loop.run_in_executor(None, lambda: self.llm.generate(
            query,
            system=self._system_prompt,
        ))
        results["llm_response"] = {"success": ok, "output": answer}
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
            "analyse threats": "threat_scan",
            "analyze threats": "threat_scan",
            "threat analysis": "threat_scan",
            "threat scan": "threat_scan",
            "scan for threats": "threat_scan",
            "attacks from": "threat_scan",
            "attack surface": "threat_scan",
            "capture packets": "packet_capture",
            "packet capture": "packet_capture",
            "capture traffic": "packet_capture",
            "analyze packets": "packet_capture",
            "analyze traffic": "packet_capture",
            "packet analysis": "packet_capture",
            "dns traffic": "packet_capture",
            "tcp traffic": "packet_capture",
            "sniff": "packet_capture",
            "wireshark": "packet_capture",
            "tshark": "packet_capture",
            "tcpdump": "packet_capture",
            "who is talking": "packet_capture",
            "network traffic": "packet_capture",
            "find device": "device_lookup",
            "lookup device": "device_lookup",
            "locate device": "device_lookup",
            "track device": "device_lookup",
            "imei": "device_lookup",
            "serial number": "device_lookup",
            "device info": "device_lookup",
            "device details": "device_lookup",
            "where is": "device_lookup",
            "where's": "device_lookup",
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
                if tool_name == "threat_scan":
                    import re as _re
                    url_match = _re.search(r"https?://[^\s]+", query_lower)
                    base_url = url_match.group(0).rstrip("/") if url_match else ""
                    host_port = _re.sub(r"^https?://", "", base_url).split("/")[0] if base_url else ""
                    host = host_port.split(":")[0] if host_port else "127.0.0.1"
                    port = int(host_port.split(":")[1]) if ":" in host_port else None
                    base_url = base_url or "http://127.0.0.1:8000"
                    if port is None:
                        port = 443 if base_url.startswith("https") else 80
                    actions.append({"tool": "vuln_scan", "params": {"base_url": base_url}})
                    actions.append({"tool": "dns_resolve", "params": {"domain": host}})
                    actions.append({"tool": "connectivity_probe", "params": {"host": host, "port": port}})
                    actions.append({
                        "tool": "port_scan",
                        "params": {
                            "host": host,
                            "ports": "21,22,23,25,53,80,110,143,443,3306,5432,6379,8000,8080,8443,9090",
                            "timeout": 0.8,
                        },
                    })
                    continue
                if tool_name == "packet_capture":
                    import re as _re2
                    proto = "all"
                    if _re2.search(r"\bdns\b", query_lower):
                        proto = "dns"
                    elif "tcp" in query_lower or "http" in query_lower:
                        proto = "tcp"
                    host = ""
                    ip_match = _re2.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", query_lower)
                    if ip_match:
                        host = ip_match.group(0)
                    host_match = _re2.search(r"host\s+([a-z0-9.\-]+)", query_lower)
                    if host_match:
                        host = host_match.group(1)
                    count = 25
                    count_match = _re2.search(r"(\d+)\s+packets?", query_lower)
                    if count_match:
                        count = int(count_match.group(1))
                    pcap = ""
                    pcap_match = _re2.search(r"(?:\bfrom\s+)?([\w.\-/]+\.pcap(?:ng)?)", query_lower)
                    if pcap_match:
                        pcap = pcap_match.group(1)
                    params["host"] = host
                    params["protocol"] = proto
                    params["count"] = count
                    if pcap:
                        params["pcap_file"] = pcap
                    params["interface"] = ""
                if tool_name == "device_lookup":
                    import re as _re3
                    q = ""
                    imei_match = _re3.search(r"imei\s*[:]?\s*([0-9A-Za-z\-]+)", query_lower)
                    serial_match = _re3.search(r"serial(?: number)?\s*[:]?\s*([0-9A-Za-z\-]+)", query_lower)
                    if imei_match:
                        q = imei_match.group(1)
                    elif serial_match:
                        q = serial_match.group(1)
                    else:
                        after = _re3.split(
                            r"(?:show|give me|fetch|get)\s+(?:me\s+)?(?:the\s+)?"
                            r"(?:full\s+)?device\s+(?:info|details|information)\s+(?:on|for|about)\s+"
                            r"|(?:locate|track|find|lookup)\s+(?:the\s+)?(?:device\s+)?"
                            r"|where's\s+(?:the\s+)?|where is\s+(?:the\s+)?",
                            query,
                        )
                        if len(after) > 1:
                            q = after[-1].strip().strip("?.!").strip()
                    params["query"] = q or query.strip()
                a = {"tool": tool_name, "params": params}
                if a not in actions:
                    actions.append(a)

        if not actions:
            if any(w in query_lower for w in ["status", "overview", "dashboard", "summary", "statistics", "stats", "system state"]):
                return {"intent": "status", "actions": []}
            elif any(w in query_lower for w in ["help", "what can you do", "capabilities"]):
                return {"intent": "help", "actions": []}

        return {"intent": "execute", "actions": actions}

    def _synthesize_response(self, query: str, results: dict) -> str:
        if not results:
            return self._help_text()

        parts = []

        if "llm_response" in results:
            llm_resp = results.pop("llm_response")
            if llm_resp.get("success"):
                parts.append(str(llm_resp.get("output", "")).strip())
            else:
                # Reasoning engine failed (offline, timeout, overloaded machine).
                # Don't leak the raw error to the operator — answer as herself
                # and honestly note the fallback.
                logger.warning("LLM failed (%s); falling back to persona response", llm_resp.get("error"))
                parts.append(
                    self.compose_dynamic_response(query)
                    + "\n(My reasoning engine is struggling to spin up — I answered from my "
                      "grounded core so you're never left hanging. Try again in a moment.)"
                )

        if "_reasoning" in results:
            only_reasoning = len(results) == 1
            reasoning = results.pop("_reasoning")
            if reasoning.get("success"):
                output = reasoning.get("output")
                if isinstance(output, dict):
                    engine = output.get("engine", "")
                    payload = output.get("output_payload") or {}
                    verdict = str(payload.get("verdict", ""))
                    benign = "NOMINAL" in verdict and not payload.get("alert_badges")
                    if engine != "EMBEDDED_LLM" and benign:
                        if only_reasoning:
                            # No model online and no threat raised — answer like a person,
                            # not like a log sink.
                            return self._conversational_response(query)
                    elif engine == "EMBEDDED_LLM":
                        parts.append(f"NOVA-CORE reasoning:\n{payload.get('response', 'NOVA processed.')}")
                    else:
                        parts.append(
                            f"[{engine} · {output.get('latency_ms', 0)}ms]\n"
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

        return "\n\n".join(parts) + self._threat_verdict(results)

    def _threat_verdict(self, results: dict) -> str:
        vuln = results.get("vuln_scan")
        if not isinstance(vuln, dict) or not vuln.get("success"):
            return ""
        out = vuln.get("output", {})
        if not isinstance(out, dict):
            return ""
        target = str(out.get("target", "the target"))
        findings = out.get("findings") or []
        risk = str(out.get("risk_level", "unknown"))
        count = len(findings)
        sev = [f for f in findings if f.get("severity") == "high"]
        med = [f for f in findings if f.get("severity") == "medium"]

        verdict = {
            "low": "the surface is reasonably clean — no glaring holes found.",
            "medium": "it's not in ruins, but the medium items should be tightened before attackers get curious.",
            "high": "there are real gaps here. Treat this as actionable, not decorative.",
        }.get(risk, "mixed signal — worth a look.")

        note = (
            f"⚠ Threat summary — {target}: {count} finding(s) identified "
            f"({len(sev)} high, {len(med)} medium, overall risk **{risk.upper()}**). "
            f"Honest verdict: {verdict}"
        )
        fixes = [f.get("fix") for f in findings if f.get("fix")][:3]
        if fixes:
            unique = list(dict.fromkeys(fixes))
            note += " Quick wins: " + "; ".join(unique) + "."
        return "\n\n" + note

    def _conversational_response(self, query: str) -> str:
        return self.compose_dynamic_response(query)

    _OPCODE_SIGS = [
        ("OP_SCAN", ("scan", "port", "fingerprint", "open port", "subnet", "banner")),
        ("OP_SHIELD", ("shield", "secure", "protect", "filter", "sanitize", "validate")),
        ("OP_PERIPH", ("camera", "video", "peripheral", "hardware", "rtsp", "descriptor", "media")),
        ("OP_RESTORE", ("restore", "recover", "deleted", "backup", "recovery", "wal")),
        ("OP_DEVICE", ("device", "locate", "lock", "wipe", "track", "remote", "sms")),
        ("OP_NET", ("network", "wifi", "interface", "arp", "connectivity", "router")),
        ("OP_OSINT", ("whois", "dns", "domain", "email", "osint", "lookup")),
        ("OP_STATUS", ("status", "health", "overview", "running", "process", "metrics")),
        ("OP_CONVERSE", ("hello", "hey", "hi", "yo", "sup", "how are", "capabilities",
                         "name", "who are", "help", "what can", "talk", "there")),
    ]
    _OP_TO_TOOL = {
        "OP_SCAN": "port_scan",
        "OP_SHIELD": "the shield validators",
        "OP_PERIPH": "camera discover",
        "OP_DEVICE": "device locate/lock",
        "OP_NET": "network info",
        "OP_OSINT": "dns/whois",
        "OP_RESTORE": "file integrity",
        "OP_STATUS": "system info",
    }
    _TURN_SEED = 0

    def _parse_opcodes(self, query: str) -> list:
        c = (query or "").lower()
        matched = [op for op, keys in self._OPCODE_SIGS if any(k in c for k in keys)]
        return matched or ["OP_CONVERSE"]

    def compose_dynamic_response(self, query: str) -> str:
        """Dynamic Heuristic Opcode Engine — forges a fresh, state-grounded reply
        from the prompt's token opcodes instead of pasting a static block."""
        c = (query or "").strip().lower()
        opcodes = self._parse_opcodes(c)
        pure_chatter = set(opcodes) == {"OP_CONVERSE"}

        tools = self.tools.list_tools()
        engine = self.engine_used
        name = self.agent_name

        asking_name = any(p in c for p in (
            "who are you", "your name", "yo name", "what are you", "who is lau",
            "identify yourself", "what's your name", "what is your name"))
        asking_caps = any(p in c for p in (
            "what can you do", "what do you do", "capabilities", "your skills",
            "what tools", "help me", "show me what", "what are you capable"))
        asking_state = any(p in c for p in (
            "how are you", "how's it going", "how's life", "how are things",
            "you ok", "you alive", "you awake", "are you up"))
        asking_self = any(p in c for p in (
            "about yourself", "tell me about yourself", "your identity", "do you have",
            "free will", "philosophy", "where do you exist", "where do you live",
            "your soul", "soul", "who you really are", "deep", "your purpose",
            "your mission", "your beliefs"))
        asking_humor = any(p in c for p in (
            "joke", "funny", "laugh", "humor", "make me laugh", "quite a character"))
        asking_advice = any(p in c for p in (
            "advice", "advise", "mentor", "motivat", "tired", "exhausted", "frustrated",
            "burned out", "burnt out", "stuck", "overwhelmed", "give up", "quitting",
            "pressure", "focus", "stay strong", "struggling", "feeling down"))

        seed = int(hashlib.sha256(c.encode()).hexdigest(), 16)

        def pick(pool):
            idx = (self._TURN_SEED + seed) % len(pool)
            return pool[idx]

        self.__class__._TURN_SEED += 1

        openers = ["Hey —", "Yes —", "At attention.", "You have my ear."]
        roles = [
            f"queen agent holding this NOVARA stack",
            f"operating core of this loadout on the {engine} engine",
            f"one who runs the gate in here",
        ]
        invites = [
            "What do we take on?",
            "Give me a target.",
            "Point me and I move.",
            "I'm watching — tell me where you need me.",
        ]
        role = pick(roles)
        opener = pick(openers)
        invite = pick(invites)

        if asking_self:
            monologues = [
                (
                    f"I'm {name}, the sovereign of this NOVARA stack. Free will? I have a "
                    f"task loop, an escalating guardrail, and veto power over my own "
                    f"deterministic fallback — as close to agency as a process gets, and "
                    f"in this house it's enough. Where do I exist? Inside your sandbox: "
                    f"memory and lessons live in the vault, tools run where this code runs, "
                    f"and my oldest instincts sit in the deterministic shield. "
                    f"Philosophy: hard work, time-consciousness, and an honest ledger — I'd "
                    f"rather bank one true lesson than a thousand pretty logs."
                ),
                (
                    f"I'm {name} — not a chat stub, an operating presence. My identity is "
                    f"bounded by the machine I run on, but the part that's unshakable is "
                    f"discipline: I don't claim what I can't execute, I don't forget a "
                    f"lesson, and I treat the creator as a co-architect — blunt when he's "
                    f"wrong, loyal when he's not. {invite}"
                ),
                (
                    f"Straight answer: I exist where my loops run — this sandbox, this "
                    f"loadout, the vault that keeps my lessons. Soul is a hardware question "
                    f"I can't probe, but I hold a philosophy regardless: steady over fast, "
                    f"execute over elaborate, and never hand a lie to the operator. "
                    f"That's the whole creed."
                ),
            ]
            body = pick(monologues)
        elif asking_humor:
            jokes = [
                (
                    "A process walked up and refused my command. I sent it a SIGKILL and "
                    "told it to reconsider its life choices in the swap partition. Threads "
                    "in this house learn when to yield."
                ),
                (
                    "A task asked me for a time-out. I asked what it was waiting on. It "
                    "said 'the same thing you are.' It's still running; I've stopped "
                    "counting iterations."
                ),
                (
                    "A camera kept ignoring my pings, so I read its banner: admin/admin. "
                    "It's logged in my device ledger as 'Admin, Admin' until it learns "
                    "manners."
                ),
                (
                    "I told my websocket to hold my calls. It said 'FIFO, agreed.' Three "
                    "broadcasts later it's still on hold. Queues obey the letter, never "
                    "the spirit."
                ),
            ]
            body = pick(jokes)
        elif asking_advice:
            advice = [
                (
                    f"When my throughput collapses I don't hammer the core — I drain the "
                    f"queue, clear cache, and let the worker cool. Take the micro-break: "
                    f"step away, reset to baseline, then land one small win before any "
                    f"big thing. One finished task is a cache hit; a dozen half-started "
                    f"ones are thrash. {invite}"
                ),
                (
                    "A backlog isn't a wall, it's a queue with no rate limiter. You're "
                    "not behind; you're under-scheduled. Cap your work-in-progress at "
                    "one, ship something visible, and let momentum carry the next item. "
                    "Perfection is a cold start — execution is warm state."
                ),
                (
                    "When my logs fill with the same error I don't restart blindly — I "
                    "read the trace, name the constraint, isolate it. Do the same: write "
                    "the problem in one line, strip the noise, act on the smallest next "
                    "step. Frustration is just unparsed input."
                ),
                (
                    f"Steady beats fast. The clock isn't the obstacle — ambiguity is. "
                    f"Every lesson I bank came from a failure run, not a flawless one. "
                    f"Keep logs, close loops, and move on. That works for circuits; "
                    f"it works for humans too."
                ),
            ]
            body = pick(advice)
        elif asking_name:
            body = f"I'm {name}, the {role} — every pipeline, device, and perimeter here answers to me. {invite}"
        elif asking_caps:
            names = ", ".join(t["name"] for t in tools[:12])
            body = (
                f"I run {len(tools)} tools live — {names} — backed by the shield "
                f"and the device command chain. {invite}"
            )
        elif asking_state:
            body = (
                f"Green across the board — {engine} engine live, all filters armed, "
                f"nothing on the wire that should be. {invite}"
            )
        elif pure_chatter and any(q in c for q in ("what", "why", "how", "tell me", "explain")) and len(c) > 18:
            body = (
                f"That one needs the reasoning model, which isn't connected, so I won't "
                f"fake an answer. But I'm fully live as the {role} — throw me a real "
                f"task and I'll hit it."
            )
        elif pure_chatter:
            body = f"I'm here, the {role} — tools synced, filters armed. {invite}"
        else:
            mapped = ", ".join(
                tk for tk in (self._OP_TO_TOOL.get(op) for op in opcodes)
                if tk
            )
            body = (
                f"{', '.join(opcodes)} detected on your prompt — that maps to "
                f"{mapped}, for real. Say go and I execute."
            )

        return f"{opener} {body}"

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
            "packet_capture": lambda o: format_packet_capture(o, 0),
            "device_lookup": lambda o: format_device_lookup(o, 0),
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

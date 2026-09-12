"""Security scanning tools for NOVA-CORE."""

import json
import os
import re
import socket
import subprocess
import time
from typing import Optional

from ..tools import Tool, ToolResult, ToolRegistry


def _api(base_url: str) -> str:
    return base_url


class PortScanner(Tool):
    name = "port_scan"
    description = "Scan TCP ports on a target host. Returns open ports and detected services."
    category = "scanner"

    def execute(self, host: str = "127.0.0.1", ports: str = "1-1024", timeout: float = 1.0, **kwargs) -> ToolResult:
        open_ports = []
        port_list = self._parse_ports(ports)

        for port in port_list:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    result = sock.connect_ex((host, port))
                    if result == 0:
                        service = self._guess_service(port)
                        open_ports.append({"port": port, "state": "open", "service": service})
            except (socket.error, OSError):
                pass

        return ToolResult(
            success=True,
            output={
                "host": host,
                "scanned": len(port_list),
                "open_ports": open_ports,
                "open_count": len(open_ports),
            },
        )

    def _parse_ports(self, ports: str) -> list:
        result = []
        for part in ports.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                result.extend(range(int(start), int(end) + 1))
            elif part.isdigit():
                result.append(int(part))
        return result

    def _guess_service(self, port: int) -> str:
        services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https",
            993: "imaps", 995: "pop3s", 3306: "mysql", 5432: "postgresql",
            6379: "redis", 8080: "http-proxy", 8443: "https-alt",
            8765: "websocket", 9090: "prometheus", 1883: "mqtt",
        }
        return services.get(port, "unknown")


class VulnerabilityScanner(Tool):
    name = "vuln_scan"
    description = "Scan for common web application vulnerabilities on the NovaGPS backend."
    category = "scanner"

    def execute(self, base_url: str = "http://127.0.0.1:8000", **kwargs) -> ToolResult:
        findings = []
        checks = [
            self._check_headers,
            self._check_error_leaks,
            self._check_cors,
            self._check_rate_limiting,
            self._check_debug_endpoints,
        ]

        for check in checks:
            try:
                result = check(base_url)
                if result:
                    findings.extend(result)
            except Exception as e:
                findings.append({"check": check.__name__, "error": str(e)})

        risk_level = "high" if any(f.get("severity") == "high" for f in findings) else \
                     "medium" if any(f.get("severity") == "medium" for f in findings) else "low"

        return ToolResult(
            success=True,
            output={
                "target": base_url,
                "findings": findings,
                "finding_count": len(findings),
                "risk_level": risk_level,
            },
        )

    def _check_headers(self, url: str) -> list:
        import httpx
        findings = []
        try:
            resp = httpx.get(f"{url}/health", timeout=10)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            security_headers = [
                "x-content-type-options", "x-frame-options",
                "x-xss-protection", "strict-transport-security",
                "content-security-policy",
            ]
            for h in security_headers:
                if h not in headers:
                    findings.append({
                        "check": "missing_security_header",
                        "header": h,
                        "severity": "medium",
                        "fix": f"Add '{h}' header to responses",
                    })

            if "server" in headers:
                findings.append({
                    "check": "server_info_leak",
                    "detail": f"Server header reveals: {headers['server']}",
                    "severity": "low",
                    "fix": "Remove or obfuscate Server header",
                })
        except Exception:
            findings.append({"check": "connection_failed", "severity": "info"})
        return findings

    def _check_error_leaks(self, url: str) -> list:
        import httpx
        findings = []
        try:
            resp = httpx.get(f"{url}/__nova_nonexistent__", timeout=10)
            body = resp.text.lower()
            leak_patterns = ["traceback", "stack trace", "traceback (most recent", "file \"/app/", "internal server error"]
            for pattern in leak_patterns:
                if pattern in body:
                    findings.append({
                        "check": "error_trace_leak",
                        "detail": f"Response contains: {pattern}",
                        "severity": "high",
                        "fix": "Ensure error handlers return generic messages, not stack traces",
                    })
                    break
        except Exception:
            pass
        return findings

    def _check_cors(self, url: str) -> list:
        import httpx
        findings = []
        try:
            resp = httpx.options(
                f"{url}/health",
                headers={
                    "Origin": "https://evil.com",
                    "Access-Control-Request-Method": "POST",
                },
                timeout=10,
            )
            acao = resp.headers.get("access-control-allow-origin", "")
            if acao == "*":
                findings.append({
                    "check": "cors_wildcard",
                    "detail": "CORS allows all origins (wildcard)",
                    "severity": "medium",
                    "fix": "Restrict CORS to known frontend origins",
                })
            elif "evil.com" in acao:
                findings.append({
                    "check": "cors_reflection",
                    "detail": "CORS reflects arbitrary origins",
                    "severity": "high",
                    "fix": "Whitelist specific allowed origins",
                })
        except Exception:
            pass
        return findings

    def _check_rate_limiting(self, url: str) -> list:
        import httpx
        findings = []
        try:
            blocked = False
            for i in range(15):
                resp = httpx.get(f"{url}/health", timeout=5)
                if resp.status_code == 429:
                    blocked = True
                    break
            if not blocked:
                findings.append({
                    "check": "no_rate_limiting",
                    "detail": "15 rapid requests did not trigger rate limiting",
                    "severity": "medium",
                    "fix": "Implement rate limiting (e.g., slowapi or middleware)",
                })
        except Exception:
            pass
        return findings

    def _check_debug_endpoints(self, url: str) -> list:
        import httpx
        findings = []
        debug_paths = ["/debug", "/debug/vars", "/admin", "/.env", "/metrics", "/docs", "/openapi.json"]
        for path in debug_paths:
            try:
                resp = httpx.get(f"{url}{path}", timeout=5)
                if resp.status_code == 200 and path not in ("/metrics", "/docs", "/openapi.json"):
                    findings.append({
                        "check": "debug_endpoint_exposed",
                        "path": path,
                        "severity": "high" if path in ("/.env", "/debug/vars") else "medium",
                        "fix": f"Disable or protect {path} in production",
                    })
            except Exception:
                pass
        return findings


class AuthScanner(Tool):
    name = "auth_scan"
    description = "Test authentication mechanisms for weaknesses."
    category = "scanner"

    def execute(self, base_url: str = "http://127.0.0.1:8000", **kwargs) -> ToolResult:
        import httpx
        findings = []

        try:
            resp = httpx.get(f"{_api(base_url)}/auth/login", timeout=10)
            if resp.status_code != 405:
                findings.append({
                    "check": "get_on_login",
                    "detail": f"GET /auth/login returned {resp.status_code}",
                    "severity": "low",
                })
        except Exception:
            pass

        try:
            resp = httpx.post(
                f"{_api(base_url)}/auth/login",
                json={"email": "' OR 1=1--", "password": "anything"},
                timeout=10,
            )
            if resp.status_code == 200:
                findings.append({
                    "check": "sql_injection_login",
                    "detail": "SQL injection payload accepted on login",
                    "severity": "critical",
                })
        except Exception:
            pass

        try:
            resp = httpx.get(f"{_api(base_url)}/devices", timeout=10)
            if resp.status_code != 401:
                findings.append({
                    "check": "unauthenticated_me",
                    "detail": f"/devices returned {resp.status_code} without token",
                    "severity": "high",
                })
        except Exception:
            pass

        try:
            resp = httpx.post(
                f"{_api(base_url)}/auth/login",
                json={"email": "admin@test.com", "password": "admin"},
                timeout=10,
            )
            if resp.status_code == 200:
                findings.append({
                    "check": "weak_default_password",
                    "detail": "Common admin credentials accepted",
                    "severity": "high",
                })
        except Exception:
            pass

        risk = "critical" if any(f.get("severity") == "critical" for f in findings) else \
               "high" if any(f.get("severity") == "high" for f in findings) else \
               "medium" if findings else "low"

        return ToolResult(
            success=True,
            output={
                "target": base_url,
                "findings": findings,
                "finding_count": len(findings),
                "risk_level": risk,
            },
        )


class CryptoAudit(Tool):
    name = "crypto_audit"
    description = "Audit cryptographic configurations (JWT, hashing, TLS)."
    category = "scanner"

    def execute(self, base_url: str = "http://127.0.0.1:8000", **kwargs) -> ToolResult:
        import httpx
        findings = []

        try:
            resp = httpx.get(f"{base_url}/health", timeout=10, follow_redirects=True)
            if base_url.startswith("http://"):
                findings.append({
                    "check": "no_tls",
                    "detail": "Backend accessible over plain HTTP",
                    "severity": "high",
                    "fix": "Enforce HTTPS in production (Render provides this automatically)",
                })
        except Exception:
            pass

        try:
            from ..config import get_config
            cfg = get_config()
            if cfg.secret_key in ("", "replace_with_secure_random"):
                findings.append({
                    "check": "weak_jwt_secret",
                    "detail": "SECRET_KEY is default/empty — JWT tokens can be forged",
                    "severity": "critical",
                    "fix": "Set SECRET_KEY to a strong random value (64+ hex chars)",
                })
        except Exception:
            pass

        try:
            resp = httpx.post(
                f"{_api(base_url)}/auth/login",
                json={"email": "test@test.com", "password": "test"},
                timeout=10,
            )
            if resp.status_code == 200:
                token = resp.json().get("access_token", "")
                if token:
                    parts = token.split(".")
                    if len(parts) == 3:
                        import base64
                        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
                        if header.get("alg") == "none":
                            findings.append({
                                "check": "jwt_none_algorithm",
                                "detail": "JWT accepts 'none' algorithm — tokens can be forged",
                                "severity": "critical",
                            })
                        elif header.get("alg") == "HS256":
                            findings.append({
                                "check": "jwt_hs256",
                                "detail": "Using HS256 (symmetric). Consider RS256 for production.",
                                "severity": "info",
                            })
        except Exception:
            pass

        return ToolResult(
            success=True,
            output={"findings": findings, "finding_count": len(findings)},
        )


def register_scanner_tools(registry: ToolRegistry):
    for tool_cls in [PortScanner, VulnerabilityScanner, AuthScanner, CryptoAudit]:
        registry.register(tool_cls())

"""NovaGPS backend integration tools."""

import json
import time
from pathlib import Path
from typing import Optional

from ..tools import Tool, ToolResult, ToolRegistry
from ..config import get_config


class BackendHealthCheck(Tool):
    name = "backend_health"
    description = "Check NovaGPS backend health, latency, and uptime."
    category = "backend"

    def execute(self, **kwargs) -> ToolResult:
        import httpx
        cfg = get_config()

        try:
            start = time.time()
            resp = httpx.get(f"{cfg.backend_url}/health", timeout=10)
            latency_ms = (time.time() - start) * 1000

            return ToolResult(
                success=True,
                output={
                    "status": "healthy" if resp.status_code == 200 else "degraded",
                    "status_code": resp.status_code,
                    "latency_ms": round(latency_ms, 2),
                    "response": resp.json() if resp.status_code == 200 else resp.text[:500],
                },
            )
        except httpx.ConnectError:
            return ToolResult(success=True, output={"status": "unreachable", "error": "Connection refused"})
        except Exception as e:
            return ToolResult(success=False, output=None, error=str(e))


class DeviceEnumerator(Tool):
    name = "device_enum"
    description = "List all registered devices with their status, last seen, and IP info."
    category = "backend"

    def execute(self, **kwargs) -> ToolResult:
        import httpx
        cfg = get_config()

        try:
            resp = httpx.get(f"{cfg.backend_url}/devices", timeout=10)
            if resp.status_code == 200:
                devices = resp.json()
                return ToolResult(
                    success=True,
                    output={
                        "device_count": len(devices) if isinstance(devices, list) else 0,
                        "devices": devices if isinstance(devices, list) else [],
                    },
                )
            else:
                return ToolResult(success=True, output={"status_code": resp.status_code, "body": resp.text[:500]})
        except Exception as e:
            return ToolResult(success=False, output=None, error=str(e))


class AlertChecker(Tool):
    name = "alert_check"
    description = "Check recent alerts from the NovaGPS system."
    category = "backend"

    def execute(self, limit: int = 20, **kwargs) -> ToolResult:
        import httpx
        cfg = get_config()

        try:
            resp = httpx.get(
                f"{cfg.backend_url}/alerts",
                params={"limit": limit},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                alerts = data.get("alerts", []) if isinstance(data, dict) else data
                return ToolResult(
                    success=True,
                    output={
                        "alert_count": len(alerts) if isinstance(alerts, list) else 0,
                        "alerts": alerts if isinstance(alerts, list) else [],
                    },
                )
            else:
                return ToolResult(success=True, output={"status_code": resp.status_code})
        except Exception as e:
            return ToolResult(success=False, output=None, error=str(e))


class MetricsCollector(Tool):
    name = "metrics_collect"
    description = "Collect Prometheus metrics from the NovaGPS backend."
    category = "backend"

    def execute(self, **kwargs) -> ToolResult:
        import httpx
        cfg = get_config()

        try:
            resp = httpx.get(f"{cfg.backend_url}/metrics", timeout=10)
            if resp.status_code == 200:
                metrics_text = resp.text
                parsed = {}
                for line in metrics_text.strip().split("\n"):
                    if line.startswith("#") or not line.strip():
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[0].split("{")[0]
                        value = parts[1]
                        try:
                            parsed[name] = float(value)
                        except ValueError:
                            parsed[name] = value

                return ToolResult(
                    success=True,
                    output={
                        "metric_count": len(parsed),
                        "key_metrics": {k: v for k, v in list(parsed.items())[:30]},
                    },
                )
            else:
                return ToolResult(success=True, output={"status_code": resp.status_code})
        except Exception as e:
            return ToolResult(success=False, output=None, error=str(e))


class EndpointTester(Tool):
    name = "endpoint_test"
    description = "Test a batch of critical NovaGPS API endpoints for correctness."
    category = "backend"

    def execute(self, **kwargs) -> ToolResult:
        import httpx
        cfg = get_config()

        endpoints = [
            ("GET", "/health", None, [200]),
            ("GET", "/metrics", None, [200]),
            ("POST", "/auth/login", {"email": "test", "password": "test"}, [401, 422]),
            ("GET", "/devices", None, [401, 200]),
            ("GET", "/geofences", None, [401, 200]),
            ("GET", "/alerts", None, [401, 200]),
            ("GET", "/analytics/dashboard", None, [401, 200]),
            ("GET", "/consent/verify-chain", None, [401, 200]),
            ("GET", "/webhooks", None, [401, 200]),
            ("POST", "/traccar", {"id": "test", "lat": 0, "lon": 0}, [200, 401]),
        ]

        results = []
        passed = 0
        failed = 0

        for method, path, body, expected_codes in endpoints:
            try:
                url = f"{cfg.backend_url}{path}"
                start = time.time()
                if method == "GET":
                    resp = httpx.get(url, timeout=10)
                else:
                    resp = httpx.post(url, json=body, timeout=10)
                latency = (time.time() - start) * 1000

                ok = resp.status_code in expected_codes
                results.append({
                    "method": method,
                    "path": path,
                    "status": resp.status_code,
                    "expected": expected_codes,
                    "pass": ok,
                    "latency_ms": round(latency, 1),
                })
                if ok:
                    passed += 1
                else:
                    failed += 1
            except Exception as e:
                results.append({"method": method, "path": path, "error": str(e), "pass": False})
                failed += 1

        return ToolResult(
            success=True,
            output={
                "total": len(endpoints),
                "passed": passed,
                "failed": failed,
                "health": "healthy" if failed == 0 else "degraded" if passed > failed else "critical",
                "results": results,
            },
        )


def register_backend_tools(registry: ToolRegistry):
    for tool_cls in [BackendHealthCheck, DeviceEnumerator, AlertChecker, MetricsCollector, EndpointTester]:
        registry.register(tool_cls())

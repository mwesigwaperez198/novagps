"""NovaGPS backend integration tools."""

import json
import time
from pathlib import Path
from typing import Optional

import httpx

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
            resp = httpx.get(
                f"{cfg.backend_url}/devices",
                headers=_auth_headers(),
                timeout=10,
            )
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


class DeviceLookup(Tool):
    name = "device_lookup"
    description = (
        "Resolve a registered device by IMEI, serial number, identifier, or name and "
        "return its identity, status, IPs, and latest GPS position. Pass "
        "trigger_locate=True to also push a fresh live-locate command to the device."
    )
    category = "backend"

    def execute(self, query: str = "", trigger_locate: bool = False, **kwargs) -> ToolResult:
        import httpx
        cfg = get_config()
        if not query:
            return ToolResult(success=False, output=None, error="No IMEI/serial/identifier given")
        try:
            try:
                resp = httpx.get(
                    f"{cfg.backend_url}/search",
                    params={"q": query.strip()},
                    headers=_auth_headers(),
                    timeout=8,
                )
            except httpx.RequestError as exc:
                diag = _backend_diagnosis(cfg, query.strip())
                return ToolResult(
                    success=True,
                    output={
                        "query": query.strip(),
                        "device_count": 0,
                        "devices": [],
                        "backend_status": diag["backend_status"] or "unreachable",
                        "healthy": False,
                        "total_devices": diag["device_count"],
                        "analysis": (
                            diag["analysis"]
                            or [f"Cannot reach backend at {cfg.backend_url} ({type(exc).__name__}). "
                                "Check the NOVA_BACKEND_URL, network, or Render cold start."]
                        ),
                        "message": f"Backend unreachable: {type(exc).__name__}.",
                    },
                )
            if resp.status_code == 200:
                devices = resp.json()
                matches = devices if isinstance(devices, list) else []
                if not matches:
                    diag = _backend_diagnosis(cfg, query.strip())
                    if diag["healthy"]:
                        reasons = [
                            "No registered device matches that IMEI/serial on the backend.",
                            "If the device phones home via the Traccar app, it is enrolled under its",
                            "Traccar device id (the /traccar 'id' param) — NOT necessarily the IMEI.",
                            "Provide the identifier shown on the dashboard, or search the device name.",
                        ]
                    else:
                        reasons = [
                            f"The backend answered {diag['backend_status']} — the service may be cold-",
                            "starting (Render free tier spins down after idle) or unreachable.",
                            "Try again in ~60s, or use a paid instance so it never sleeps.",
                        ]
                    if diag["device_count"] is not None:
                        reasons.insert(
                            0 if diag["healthy"] else 1,
                            f"{diag['device_count']} device(s) are registered on the backend.",
                        )
                    return ToolResult(
                        success=True,
                        output={
                            "query": query.strip(),
                            "device_count": 0,
                            "devices": [],
                            "backend_status": diag["backend_status"],
                            "healthy": diag["healthy"],
                            "total_devices": diag["device_count"],
                            "analysis": (diag["analysis"] or reasons),
                            "message": f"No device matches '{query.strip()}'.",
                        },
                    )
                briefs = [device_brief(d) for d in matches]
                result: dict = {
                    "query": query.strip(),
                    "device_count": len(matches),
                    "devices": briefs,
                }
                if trigger_locate:
                    locate = _trigger_locate(matches[0].get("id", ""))
                    result["locate"] = locate
                return ToolResult(success=True, output=result)
            else:
                diag = _backend_diagnosis(cfg, query.strip())
                out = {
                    "status_code": resp.status_code,
                    "backend_status": diag["backend_status"],
                    "healthy": diag["healthy"],
                    "device_count": 0,
                    "devices": [],
                }
                if diag["healthy"]:
                    out["analysis"] = (
                        diag["analysis"]
                        or [
                            "Backend is healthy but returned HTTP "
                            f"{resp.status_code} for this search — the query may need the API token.",
                        ]
                    )
                else:
                    out["analysis"] = [
                        f"Backend unreachable ({diag['backend_status']}); "
                        "Render spins the free tier down after idle. Wait ~60s or use a paid instance."
                    ]
                out["message"] = f"Backend returned HTTP {resp.status_code}."
                return ToolResult(success=True, output=out)
        except Exception as e:
            return ToolResult(success=False, output=None, error=str(e))


def _backend_diagnosis(cfg, query: str) -> dict:
    """Probe backend health + device count, return a structured analysis."""
    result: dict = {"backend_status": "unknown", "healthy": False, "device_count": None, "analysis": []}
    hdrs = _auth_headers()
    # 1) health check
    try:
        hr = httpx.get(f"{cfg.backend_url}/health", headers=hdrs, timeout=6)
        if hr.status_code == 200:
            result["backend_status"] = "healthy"
            result["healthy"] = True
        else:
            result["backend_status"] = f"unhealthy (HTTP {hr.status_code})"
    except httpx.RequestError:
        result["backend_status"] = "unreachable"
    # 2) device count
    try:
        dr = httpx.get(f"{cfg.backend_url}/devices", headers=hdrs, timeout=8)
        if dr.status_code == 200:
            devs = dr.json() if isinstance(dr.json(), list) else []
            result["device_count"] = len(devs)
            # look for imei match in any device
            if query:
                q = query.strip()
                for d in devs:
                    if d.get("imei") == q:
                        result["analysis"].append(
                            f"Found IMEI {q} on device identifier={d.get('identifier')!r}; "
                            "it may be registered under its Traccar device id, not by IMEI."
                        )
                    if d.get("serial") == q:
                        result["analysis"].append(
                            f"Found serial {q} on device identifier={d.get('identifier')!r}."
                        )
    except httpx.RequestError:
        pass
    return result


def _auth_headers() -> dict:
    """Bearer header when NOVA_TOKEN is configured; empty for dev bypass."""
    cfg = get_config()
    if cfg.backend_token:
        return {"Authorization": f"Bearer {cfg.backend_token}"}
    return {}


def _trigger_locate(device_id: str) -> dict:
    """Queue a live-locate command for a resolved device. Never raises."""
    import httpx
    cfg = get_config()
    if not device_id:
        return {"ok": False, "error": "No device id resolved"}
    try:
        resp = httpx.post(
            f"{cfg.backend_url}/device/{device_id}/trigger-locate",
            headers=_auth_headers(),
            timeout=10,
        )
        body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text[:300]
        return {"ok": resp.status_code == 200, "status_code": resp.status_code, "result": body}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def device_brief(d: dict) -> dict:
    loc = d.get("latest_location") or {}
    return {
        "id": d.get("id", ""),
        "name": d.get("name", ""),
        "identifier": d.get("identifier", ""),
        "imei": d.get("imei"),
        "serial": d.get("serial"),
        "model": d.get("model"),
        "manufacturer": d.get("manufacturer"),
        "os_type": d.get("os_type"),
        "os_version": d.get("os_version"),
        "device_type": d.get("device_type"),
        "ip_address": d.get("ip_address"),
        "local_ip": d.get("local_ip"),
        "carrier": d.get("carrier"),
        "active": d.get("is_active", False),
        "lost_mode": d.get("is_lost_mode", False),
        "last_lat": loc.get("latitude"),
        "last_lon": loc.get("longitude"),
        "last_speed": loc.get("speed"),
        "last_place": loc.get("place_name"),
        "last_seen": loc.get("recorded_at"),
    }


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
                headers=_auth_headers(),
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
            resp = httpx.get(
                f"{cfg.backend_url}/metrics",
                headers=_auth_headers(),
                timeout=10,
            )
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
            ("GET", "/metrics", None, [200, 401, 403]),
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
        headers = _auth_headers()

        for method, path, body, expected_codes in endpoints:
            try:
                url = f"{cfg.backend_url}{path}"
                start = time.time()
                if method == "GET":
                    resp = httpx.get(url, headers=headers, timeout=10)
                else:
                    resp = httpx.post(url, json=body, headers=headers, timeout=10)
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
    for tool_cls in [BackendHealthCheck, DeviceEnumerator, DeviceLookup, AlertChecker, MetricsCollector, EndpointTester]:
        registry.register(tool_cls())

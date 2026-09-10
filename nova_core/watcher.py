"""NOVA-CORE system monitoring daemon.

Continuously monitors system health, logs, network status,
and application state. Records anomalies to persistent memory.
"""

import asyncio
import json
import os
import time
import random
import subprocess
import logging
from pathlib import Path
from typing import Optional, Callable, List
from dataclasses import dataclass, field

from .config import get_config
from .memory import NovaMemory

logger = logging.getLogger("nova_core.watcher")


@dataclass
class WatcherState:
    last_scan_time: float = 0.0
    last_health_check: float = 0.0
    consecutive_failures: int = 0
    alerts_today: int = 0
    system_snapshot: dict = field(default_factory=dict)


class NovaWatcher:
    def __init__(self, memory: Optional[NovaMemory] = None):
        self.cfg = get_config()
        self.memory = memory or NovaMemory()
        self.state = WatcherState()
        self._running = False
        self._callbacks: List[Callable] = []

    def on_anomaly(self, callback: Callable):
        self._callbacks.append(callback)

    async def start(self, interval: Optional[int] = None):
        self._running = True
        interval = interval or self.cfg.watch_interval
        logger.info("NOVA Watcher starting (interval=%ds)", interval)

        while self._running:
            try:
                await self._watch_cycle()
            except Exception as e:
                logger.error("Watcher cycle error: %s", e)
                self.state.consecutive_failures += 1
                if self.state.consecutive_failures > 5:
                    self.memory.create_alert(
                        "watcher_degradation",
                        f"Watcher failed {self.state.consecutive_failures} consecutive cycles: {e}",
                        "nova_watcher",
                    )

            jitter = random.uniform(0.8, 1.2)
            await asyncio.sleep(interval * jitter)

    def stop(self):
        self._running = False
        logger.info("NOVA Watcher stopped")

    async def _watch_cycle(self):
        snapshot = {}

        snapshot["system"] = self._check_system_health()
        snapshot["network"] = self._check_network()
        snapshot["disk"] = self._check_disk()
        snapshot["processes"] = self._check_critical_processes()
        snapshot["backend"] = await self._check_backend()
        snapshot["timestamp"] = time.time()

        self.state.system_snapshot = snapshot
        self.state.last_scan_time = time.time()

        anomalies = self._detect_anomalies(snapshot)
        if anomalies:
            for anomaly in anomalies:
                self.memory.create_alert(anomaly["type"], anomaly["message"], "nova_watcher")
                self.state.alerts_today += 1
                for cb in self._callbacks:
                    try:
                        cb(anomaly)
                    except Exception:
                        pass

        self.memory.set_state("last_watch_snapshot", json.dumps({
            "timestamp": snapshot["timestamp"],
            "anomaly_count": len(anomalies),
            "health": "ok" if not anomalies else "degraded",
        }))

    def _check_system_health(self) -> dict:
        info = {"load_avg": [0, 0, 0], "uptime": 0, "memory_percent": 0}

        try:
            with open("/proc/loadavg") as f:
                parts = f.read().split()
                info["load_avg"] = [float(parts[0]), float(parts[1]), float(parts[2])]
        except Exception:
            pass

        try:
            with open("/proc/uptime") as f:
                info["uptime"] = float(f.read().split()[0])
        except Exception:
            pass

        try:
            with open("/proc/meminfo") as f:
                lines = f.readlines()
            mem = {}
            for line in lines:
                parts = line.split(":")
                if len(parts) == 2:
                    key = parts[0].strip()
                    val = parts[1].strip().split()[0]
                    mem[key] = int(val)
            total = mem.get("MemTotal", 1)
            available = mem.get("MemAvailable", total)
            info["memory_percent"] = round(((total - available) / total) * 100, 1)
            info["memory_total_mb"] = round(total / 1024, 1)
            info["memory_available_mb"] = round(available / 1024, 1)
        except Exception:
            pass

        return info

    def _check_network(self) -> dict:
        result = {"reachable": False, "latency_ms": 0}
        try:
            start = time.time()
            sock = __import__("socket").socket(__import__("socket").AF_INET, __import__("socket").SOCK_STREAM)
            sock.settimeout(3)
            sock.connect(("8.8.8.8", 53))
            sock.close()
            result["reachable"] = True
            result["latency_ms"] = round((time.time() - start) * 1000, 2)
        except Exception:
            pass
        return result

    def _check_disk(self) -> dict:
        try:
            st = os.statvfs("/var/data" if os.path.exists("/var/data") else "/")
            total = st.f_blocks * st.f_frsize
            free = st.f_bavail * st.f_frsize
            used_pct = round(((total - free) / total) * 100, 1) if total else 0
            return {"total_gb": round(total / (1024**3), 2), "free_gb": round(free / (1024**3), 2), "used_percent": used_pct}
        except Exception:
            return {"error": "unable to read"}

    def _check_critical_processes(self) -> dict:
        try:
            result = subprocess.run(["pgrep", "-a", "uvicorn"], capture_output=True, text=True, timeout=5)
            running = result.returncode == 0
            return {"uvicorn_running": running, "details": result.stdout.strip()[:200] if running else "not found"}
        except Exception:
            return {"uvicorn_running": None}

    async def _check_backend(self) -> dict:
        try:
            import httpx
            start = time.time()
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{self.cfg.backend_url}/health", timeout=10)
                latency = (time.time() - start) * 1000
                return {
                    "status_code": resp.status_code,
                    "healthy": resp.status_code == 200,
                    "latency_ms": round(latency, 2),
                }
        except Exception as e:
            return {"healthy": False, "error": str(e)}

    def _detect_anomalies(self, snapshot: dict) -> list:
        anomalies = []

        sys_data = snapshot.get("system", {})
        load = sys_data.get("load_avg", [0, 0, 0])
        if load[0] > 4.0:
            anomalies.append({
                "type": "high_load",
                "severity": "warning",
                "message": f"System load average {load[0]} exceeds threshold (4.0)",
            })

        mem_pct = sys_data.get("memory_percent", 0)
        if mem_pct > 90:
            anomalies.append({
                "type": "memory_critical",
                "severity": "critical",
                "message": f"Memory usage at {mem_pct}% — risk of OOM",
            })
        elif mem_pct > 80:
            anomalies.append({
                "type": "memory_warning",
                "severity": "warning",
                "message": f"Memory usage at {mem_pct}%",
            })

        disk = snapshot.get("disk", {})
        if disk.get("used_percent", 0) > 90:
            anomalies.append({
                "type": "disk_critical",
                "severity": "critical",
                "message": f"Disk usage at {disk['used_percent']}% — risk of write failure",
            })

        net = snapshot.get("network", {})
        if not net.get("reachable", True):
            anomalies.append({
                "type": "network_down",
                "severity": "critical",
                "message": "External network unreachable",
            })
        elif net.get("latency_ms", 0) > 5000:
            anomalies.append({
                "type": "high_latency",
                "severity": "warning",
                "message": f"Network latency {net['latency_ms']}ms exceeds 5s threshold",
            })

        backend = snapshot.get("backend", {})
        if not backend.get("healthy", True):
            anomalies.append({
                "type": "backend_down",
                "severity": "critical",
                "message": f"Backend health check failed: {backend.get('error', 'unhealthy')}",
            })

        procs = snapshot.get("processes", {})
        if procs.get("uvicorn_running") is False:
            anomalies.append({
                "type": "process_down",
                "severity": "critical",
                "message": "uvicorn process not found — backend may be crashed",
            })

        return anomalies

    def get_current_snapshot(self) -> dict:
        return self.state.system_snapshot

    async def run_single_scan(self) -> dict:
        await self._watch_cycle()
        return self.state.system_snapshot

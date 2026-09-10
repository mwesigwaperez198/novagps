"""System information and diagnostic tools."""

import os
import platform
import time
import json
import subprocess
from pathlib import Path

from ..tools import Tool, ToolResult, ToolRegistry


class SystemInfo(Tool):
    name = "system_info"
    description = "Get current system information (OS, CPU, memory, disk, uptime)."
    category = "system"

    def execute(self, **kwargs) -> ToolResult:
        info = {
            "os": platform.system(),
            "os_release": platform.release(),
            "architecture": platform.machine(),
            "hostname": platform.node(),
            "python_version": platform.python_version(),
            "uptime_seconds": self._get_uptime(),
            "disk": self._get_disk_usage(),
            "memory": self._get_memory_info(),
            "load_average": self._get_load_average(),
            "environment": os.environ.get("ENVIRONMENT", "unknown"),
            "nova_mode": os.environ.get("NOVA_MODE", "unknown"),
        }
        return ToolResult(success=True, output=info)

    def _get_uptime(self) -> float:
        try:
            with open("/proc/uptime") as f:
                return float(f.read().split()[0])
        except Exception:
            return 0.0

    def _get_disk_usage(self) -> dict:
        try:
            st = os.statvfs("/var/data" if os.path.exists("/var/data") else "/")
            total = st.f_blocks * st.f_frsize
            free = st.f_bavail * st.f_frsize
            used = total - free
            return {
                "total_gb": round(total / (1024**3), 2),
                "used_gb": round(used / (1024**3), 2),
                "free_gb": round(free / (1024**3), 2),
                "percent_used": round((used / total) * 100, 1) if total else 0,
            }
        except Exception:
            return {"error": "unable to read disk usage"}

    def _get_memory_info(self) -> dict:
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
            total = mem.get("MemTotal", 0)
            available = mem.get("MemAvailable", 0)
            return {
                "total_mb": round(total / 1024, 1),
                "available_mb": round(available / 1024, 1),
                "used_mb": round((total - available) / 1024, 1),
                "percent_used": round(((total - available) / total) * 100, 1) if total else 0,
            }
        except Exception:
            return {"error": "unable to read memory info"}

    def _get_load_average(self) -> dict:
        try:
            load1, load5, load15 = os.getloadavg()
            return {"1min": round(load1, 2), "5min": round(load5, 2), "15min": round(load15, 2)}
        except Exception:
            return {"error": "unable to read load average"}


class ProcessList(Tool):
    name = "process_list"
    description = "List running processes with CPU/memory usage."
    category = "system"

    def execute(self, filter_name: str = "", top_n: int = 15, **kwargs) -> ToolResult:
        try:
            result = subprocess.run(
                ["ps", "aux", "--sort=-pcpu"],
                capture_output=True, text=True, timeout=10,
            )
            lines = result.stdout.strip().split("\n")
            if not lines:
                return ToolResult(success=True, output={"processes": []})

            header = lines[0]
            processes = []
            for line in lines[1:top_n + 1]:
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    proc = {
                        "user": parts[0],
                        "pid": parts[1],
                        "cpu": parts[2],
                        "mem": parts[3],
                        "command": parts[10][:120],
                    }
                    if filter_name and filter_name.lower() not in proc["command"].lower():
                        continue
                    processes.append(proc)

            return ToolResult(success=True, output={"processes": processes, "count": len(processes)})
        except Exception as e:
            return ToolResult(success=False, output=None, error=str(e))


class LogReader(Tool):
    name = "log_reader"
    description = "Read and analyze application log files."
    category = "system"

    def execute(self, log_path: str = "/var/data/nova_vault/agent.log", lines: int = 100, search: str = "", **kwargs) -> ToolResult:
        log_file = Path(log_path)
        if not log_file.exists():
            return ToolResult(success=True, output={"lines": [], "total": 0, "message": f"Log file not found: {log_path}"})

        try:
            with open(log_file, "r", errors="replace") as f:
                all_lines = f.readlines()

            if search:
                all_lines = [l for l in all_lines if search.lower() in l.lower()]

            recent = all_lines[-lines:]

            errors = [l.strip() for l in recent if "error" in l.lower() or "exception" in l.lower() or "traceback" in l.lower()]
            warnings = [l.strip() for l in recent if "warning" in l.lower() or "warn" in l.lower()]

            return ToolResult(
                success=True,
                output={
                    "lines": [l.strip() for l in recent[-20:]],
                    "total_matching": len(all_lines),
                    "errors_found": len(errors),
                    "warnings_found": len(warnings),
                    "recent_errors": errors[-5:],
                },
            )
        except Exception as e:
            return ToolResult(success=False, output=None, error=str(e))


class FileIntegrityChecker(Tool):
    name = "file_integrity"
    description = "Check file integrity by computing SHA-256 hashes of critical system files."
    category = "system"

    def execute(self, files: str = "", **kwargs) -> ToolResult:
        import hashlib

        critical_files = [
            "/app/backend/main.py",
            "/app/backend/config.py",
            "/app/backend/auth.py",
            "/app/backend/models.py",
            "/app/backend/schemas.py",
            "/app/Dockerfile",
        ]

        if files:
            critical_files = [f.strip() for f in files.split(",")]

        results = []
        for fpath in critical_files:
            try:
                path = Path(fpath)
                if path.exists():
                    sha = hashlib.sha256(path.read_bytes()).hexdigest()
                    results.append({
                        "file": fpath,
                        "exists": True,
                        "sha256": sha,
                        "size_bytes": path.stat().st_size,
                        "modified": path.stat().st_mtime,
                    })
                else:
                    results.append({"file": fpath, "exists": False})
            except Exception as e:
                results.append({"file": fpath, "error": str(e)})

        return ToolResult(success=True, output={"files": results, "checked": len(results)})


class NetworkInterfaces(Tool):
    name = "network_interfaces"
    description = "List all network interfaces and their IP addresses."
    category = "system"

    def execute(self, **kwargs) -> ToolResult:
        try:
            result = subprocess.run(
                ["ip", "-j", "addr"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                interfaces = json.loads(result.stdout)
                simplified = []
                for iface in interfaces:
                    simplified.append({
                        "name": iface.get("ifname"),
                        "state": iface.get("operstate"),
                        "addresses": [
                            {"addr": a.get("addr"), "family": a.get("family")}
                            for a in iface.get("addr_info", [])
                        ],
                    })
                return ToolResult(success=True, output={"interfaces": simplified})
        except Exception:
            pass

        try:
            result = subprocess.run(["ip", "addr"], capture_output=True, text=True, timeout=5)
            return ToolResult(success=True, output={"raw": result.stdout[:2000]})
        except Exception as e:
            return ToolResult(success=False, output=None, error=str(e))


def register_system_tools(registry: ToolRegistry):
    for tool_cls in [SystemInfo, ProcessList, LogReader, FileIntegrityChecker, NetworkInterfaces]:
        registry.register(tool_cls())

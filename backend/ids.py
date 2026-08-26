import logging
import subprocess
import json
from pathlib import Path

logger = logging.getLogger("nova.ids")

SURICATA_LOG = "/var/log/suricata/eve.json"
SURICATA_RULES = "/var/lib/suricata/rules/"


def get_ids_status() -> dict:
    status = {"suricata": {"installed": False, "running": False, "rules_count": 0}}
    try:
        completed = subprocess.run(
            ["which", "suricata"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
        status["suricata"]["installed"] = completed.returncode == 0
    except FileNotFoundError:
        status["suricata"]["installed"] = False

    try:
        completed = subprocess.run(
            ["pgrep", "suricata"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
        status["suricata"]["running"] = completed.returncode == 0
    except FileNotFoundError:
        pass

    rules_dir = Path(SURICATA_RULES)
    if rules_dir.exists():
        rules_files = list(rules_dir.glob("*.rules"))
        status["suricata"]["rules_count"] = len(rules_files)

    return status


def get_recent_alerts(limit: int = 50) -> list[dict]:
    log_path = Path(SURICATA_LOG)
    if not log_path.exists():
        return [{"info": "suricata eve.json not found", "path": SURICATA_LOG}]
    try:
        alerts = []
        lines = log_path.read_text(encoding="utf-8", errors="replace").strip().splitlines()
        for line in reversed(lines[-limit * 3:]):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                if entry.get("event_type") == "alert":
                    alerts.append({
                        "timestamp": entry.get("timestamp"),
                        "src_ip": entry.get("src_ip"),
                        "dest_ip": entry.get("dest_ip"),
                        "alert": entry.get("alert", {}).get("signature"),
                        "severity": entry.get("alert", {}).get("severity"),
                        "category": entry.get("alert", {}).get("category"),
                    })
                    if len(alerts) >= limit:
                        break
            except json.JSONDecodeError:
                continue
        return alerts
    except Exception as exc:
        return [{"error": f"failed to read alerts: {exc}"}]


def update_rules() -> dict:
    try:
        completed = subprocess.run(
            ["suricata-update", "update"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
            check=False,
        )
        output = completed.stdout.decode("utf-8", errors="replace")
        if completed.returncode == 0:
            return {"status": "updated", "output": output[-500:]}
        return {"error": "update failed", "output": output[-500:]}
    except FileNotFoundError:
        return {"error": "suricata-update not installed"}
    except subprocess.TimeoutExpired:
        return {"error": "update timed out"}

import logging
import subprocess
import re

logger = logging.getLogger("nova.osint")

DOMAIN_PATTERN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")
IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def whois_lookup(domain: str) -> dict:
    if not DOMAIN_PATTERN.fullmatch(domain):
        return {"error": "invalid domain format"}
    try:
        completed = subprocess.run(
            ["whois", domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=15,
            check=False,
        )
        output = completed.stdout.decode("utf-8", errors="replace")
        result = {"domain": domain, "raw": output[:4096]}
        for line in output.splitlines():
            lower = line.lower().strip()
            if "registrar:" in lower:
                result["registrar"] = line.split(":", 1)[1].strip()
            elif "creation date:" in lower:
                result["created"] = line.split(":", 1)[1].strip()
            elif "expir" in lower and "date" in lower:
                result["expires"] = line.split(":", 1)[1].strip()
            elif "name server:" in lower and "nameservers" not in result:
                result.setdefault("nameservers", []).append(line.split(":", 1)[1].strip())
        return result
    except FileNotFoundError:
        return {"error": "whois not installed"}


def dns_bruteforce(domain: str) -> dict:
    if not DOMAIN_PATTERN.fullmatch(domain):
        return {"error": "invalid domain format"}
    try:
        completed = subprocess.run(
            ["nmap", "--script", "dns-brute", "--script-args", "dns-brute.threads=5", domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        output = completed.stdout.decode("utf-8", errors="replace")
        subdomains = []
        for line in output.splitlines():
            if "dns-brute" in line and "." in line and domain in line:
                parts = line.strip().split()
                for part in parts:
                    if domain in part:
                        subdomains.append(part.rstrip(","))
                        break
        return {"domain": domain, "subdomains": subdomains, "count": len(subdomains), "raw": output[-2048:]}
    except FileNotFoundError:
        return {"error": "nmap not installed"}


def reverse_dns(ip: str) -> dict:
    if not IP_PATTERN.fullmatch(ip):
        return {"error": "invalid IP format"}
    try:
        completed = subprocess.run(
            ["dig", "-x", ip, "+short"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
            check=False,
        )
        hostname = completed.stdout.decode("utf-8", errors="replace").strip()
        return {"ip": ip, "hostname": hostname or "no PTR record"}
    except FileNotFoundError:
        try:
            completed = subprocess.run(
                ["nslookup", ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=10,
                check=False,
            )
            output = completed.stdout.decode("utf-8", errors="replace")
            hostname = ""
            for line in output.splitlines():
                if "name =" in line.lower():
                    hostname = line.split("=", 1)[1].strip().rstrip(".")
                    break
            return {"ip": ip, "hostname": hostname or "no PTR record"}
        except FileNotFoundError:
            return {"error": "dig and nslookup not installed"}


def http_headers(url: str) -> dict:
    if not url.lower().startswith(("http://", "https://")):
        return {"error": "url must start with http:// or https://"}
    try:
        completed = subprocess.run(
            ["curl", "-sSI", "--max-time", "12", url],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=15,
            check=False,
        )
        output = completed.stdout.decode("utf-8", errors="replace")
        headers = {}
        security_headers = [
            "strict-transport-security", "x-content-type-options",
            "x-frame-options", "x-xss-protection", "content-security-policy",
            "referrer-policy", "permissions-policy",
        ]
        for line in output.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        missing = [h for h in security_headers if h not in headers]
        return {"url": url, "headers": headers, "security_headers_missing": missing, "status_code": headers.get("status", "").split()[0] if "status" in headers else "unknown"}
    except FileNotFoundError:
        return {"error": "curl not installed"}


def scan_nikto(target: str) -> dict:
    if not DOMAIN_PATTERN.fullmatch(target) and not IP_PATTERN.fullmatch(target):
        return {"error": "target must be a domain or IP"}
    try:
        completed = subprocess.run(
            ["nikto", "-h", target, "-maxtime", "60s"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=90,
            check=False,
        )
        output = completed.stdout.decode("utf-8", errors="replace")
        vulnerabilities = []
        for line in output.splitlines():
            if line.startswith("+") and "OSVDB" in line:
                vulnerabilities.append(line.strip())
        return {"target": target, "vulnerabilities": vulnerabilities, "count": len(vulnerabilities), "raw": output[-4096:]}
    except FileNotFoundError:
        return {"error": "nikto not installed"}


def scan_sqlmap(url: str) -> dict:
    if not url.lower().startswith(("http://", "https://")):
        return {"error": "url must start with http:// or https://"}
    try:
        completed = subprocess.run(
            ["sqlmap", "-u", url, "--batch", "--level=1", "--risk=1", "--threads=4"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
            check=False,
        )
        output = completed.stdout.decode("utf-8", errors="replace")
        injectable = "is vulnerable" in output.lower() or "injectable" in output.lower()
        return {"url": url, "injectable": injectable, "raw": output[-4096:]}
    except FileNotFoundError:
        return {"error": "sqlmap not installed"}

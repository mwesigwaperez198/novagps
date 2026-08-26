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


def scan_theharvester(domain: str) -> dict:
    if not DOMAIN_PATTERN.fullmatch(domain):
        return {"error": "invalid domain format"}
    try:
        completed = subprocess.run(
            ["theHarvester", "-d", domain, "-b", "all"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
            check=False,
        )
        output = completed.stdout.decode("utf-8", errors="replace")
        emails = []
        subdomains = []
        for line in output.splitlines():
            if "@" in line and domain in line:
                emails.append(line.strip())
            elif domain in line and " " not in line and line.strip():
                subdomains.append(line.strip())
        return {"domain": domain, "emails": emails, "subdomains": subdomains, "raw": output[-4096:]}
    except FileNotFoundError:
        return {"error": "theHarvester not installed"}


def scan_whatweb(url: str) -> dict:
    if not url.lower().startswith(("http://", "https://")):
        return {"error": "url must start with http:// or https://"}
    try:
        completed = subprocess.run(
            ["whatweb", "-a", "3", "--color=never", url],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        output = completed.stdout.decode("utf-8", errors="replace")
        technologies = []
        for line in output.splitlines():
            if "[" in line:
                techs = re.findall(r"\[([^\]]+)\]", line)
                technologies.extend(techs)
        return {"url": url, "technologies": technologies, "raw": output[-4096:]}
    except FileNotFoundError:
        return {"error": "whatweb not installed"}


def scan_wpscan(url: str) -> dict:
    if not url.lower().startswith(("http://", "https://")):
        return {"error": "url must start with http:// or https://"}
    try:
        completed = subprocess.run(
            ["wpscan", "--url", url, "--enumerate", "vp,vt,u", "--no-banner"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
            check=False,
        )
        output = completed.stdout.decode("utf-8", errors="replace")
        plugins = re.findall(r"Title: ([^\n]+)", output)
        return {"url": url, "plugins": plugins, "raw": output[-4096:]}
    except FileNotFoundError:
        return {"error": "wpscan not installed"}


def scan_dirb(url: str) -> dict:
    if not url.lower().startswith(("http://", "https://")):
        return {"error": "url must start with http:// or https://"}
    try:
        completed = subprocess.run(
            ["dirb", url],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
            check=False,
        )
        output = completed.stdout.decode("utf-8", errors="replace")
        found = re.findall(r"\+ ([^\n]+)", output)
        return {"url": url, "directories": found, "count": len(found), "raw": output[-4096:]}
    except FileNotFoundError:
        return {"error": "dirb not installed"}


def scan_nmap_vuln(target: str) -> dict:
    if not DOMAIN_PATTERN.fullmatch(target) and not IP_PATTERN.fullmatch(target):
        return {"error": "target must be a domain or IP"}
    try:
        completed = subprocess.run(
            ["nmap", "-Pn", "--script", "vuln", target],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=300,
            check=False,
        )
        output = completed.stdout.decode("utf-8", errors="replace")
        vulns = []
        for line in output.splitlines():
            if "VULNERABLE" in line or "CVE-" in line:
                vulns.append(line.strip())
        return {"target": target, "vulnerabilities": vulns, "count": len(vulns), "raw": output[-4096:]}
    except FileNotFoundError:
        return {"error": "nmap not installed"}


def scan_nmap_auth(target: str) -> dict:
    if not DOMAIN_PATTERN.fullmatch(target) and not IP_PATTERN.fullmatch(target):
        return {"error": "target must be a domain or IP"}
    try:
        completed = subprocess.run(
            ["nmap", "-Pn", "--script", "auth", target],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=300,
            check=False,
        )
        output = completed.stdout.decode("utf-8", errors="replace")
        auth_issues = []
        for line in output.splitlines():
            if "anonymous" in line.lower() or "default" in line.lower() or "no auth" in line.lower():
                auth_issues.append(line.strip())
        return {"target": target, "auth_issues": auth_issues, "raw": output[-4096:]}
    except FileNotFoundError:
        return {"error": "nmap not installed"}


def scan_sublist3r(domain: str) -> dict:
    if not DOMAIN_PATTERN.fullmatch(domain):
        return {"error": "invalid domain format"}
    try:
        completed = subprocess.run(
            ["sublist3r", "-d", domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        output = completed.stdout.decode("utf-8", errors="replace")
        subdomains = [line.strip() for line in output.splitlines() if domain in line and line.strip()]
        return {"domain": domain, "subdomains": subdomains, "count": len(subdomains), "raw": output[-4096:]}
    except FileNotFoundError:
        return {"error": "sublist3r not installed"}


def scan_nikto_full(target: str) -> dict:
    return scan_nikto(target)


def run_tool_command(command_id: str, args: dict) -> dict:
    import shutil
    from tool_registry import TOOL_REGISTRY, resolve_host_argv

    spec = TOOL_REGISTRY.get(command_id)
    if not spec:
        return {"error": f"Unknown tool: {command_id}"}
    if not any(shutil.which(b) for b in spec.host_binaries):
        return {"error": f"Tool not installed: {command_id}", "binaries": spec.host_binaries}
    try:
        argv = resolve_host_argv(spec, args)
        completed = subprocess.run(
            list(argv),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=spec.timeout_seconds,
            check=False,
        )
        output = completed.stdout.decode("utf-8", errors="replace")
        return {
            "command_id": command_id,
            "exit_code": completed.returncode,
            "output": output[-8192:],
            "truncated": len(output) > 8192,
        }
    except subprocess.TimeoutExpired:
        return {"command_id": command_id, "error": "timeout", "timeout": spec.timeout_seconds}
    except Exception as exc:
        return {"command_id": command_id, "error": str(exc)}

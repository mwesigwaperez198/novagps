import logging
import re
import subprocess
from typing import Any

logger = logging.getLogger("nova.osint")

DOMAIN_PATTERN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")
IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _run(cmd: list[str], timeout: int = 30) -> str:
    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        return completed.stdout.decode("utf-8", errors="replace")
    except FileNotFoundError:
        return f"ERROR: {cmd[0]} not installed"
    except subprocess.TimeoutExpired:
        return f"ERROR: command timed out after {timeout}s"


def whois_lookup(domain: str) -> dict[str, Any]:
    if not DOMAIN_PATTERN.fullmatch(domain):
        return {"error": "invalid domain format"}
    output = _run(["whois", domain], timeout=15)
    if output.startswith("ERROR:"):
        return {"error": output}
    result: dict[str, Any] = {"domain": domain, "raw": output[:4096]}
    for line in output.splitlines():
        lower = line.lower().strip()
        if "registrar:" in lower:
            result["registrar"] = line.split(":", 1)[1].strip()
        elif "creation date:" in lower or "created:" in lower:
            result["created"] = line.split(":", 1)[1].strip()
        elif "expir" in lower and "date" in lower:
            result["expires"] = line.split(":", 1)[1].strip()
        elif ("name server:" in lower or "nameserver:" in lower) and "nameservers" not in result:
            result.setdefault("nameservers", []).append(line.split(":", 1)[1].strip().lower())
        elif "org" in lower and "organization" in lower:
            result["organization"] = line.split(":", 1)[1].strip()
        elif "country:" in lower:
            result.setdefault("country", line.split(":", 1)[1].strip())
        elif "state:" in lower and "state" not in result:
            result["state"] = line.split(":", 1)[1].strip()
    return result


def dns_bruteforce(domain: str) -> dict[str, Any]:
    if not DOMAIN_PATTERN.fullmatch(domain):
        return {"error": "invalid domain format"}
    output = _run(["nmap", "--script", "dns-brute", "--script-args", "dns-brute.threads=5", domain], timeout=60)
    if output.startswith("ERROR:"):
        return {"error": output}
    subdomains = []
    for line in output.splitlines():
        if "dns-brute" in line and domain in line:
            parts = line.strip().split()
            for part in parts:
                if domain in part:
                    subdomains.append(part.rstrip(","))
                    break
    return {"domain": domain, "subdomains": subdomains, "count": len(subdomains), "raw": output[-2048:]}


def reverse_dns(ip: str) -> dict[str, Any]:
    if not IP_PATTERN.fullmatch(ip):
        return {"error": "invalid IP format"}
    output = _run(["dig", "-x", ip, "+short"], timeout=10)
    hostname = output.strip().rstrip(".")
    if not hostname or "timed out" in output.lower():
        output = _run(["nslookup", ip], timeout=10)
        for line in output.splitlines():
            if "name =" in line.lower():
                hostname = line.split("=", 1)[1].strip().rstrip(".")
                break
    return {"ip": ip, "hostname": hostname or "no PTR record"}


def http_headers(url: str) -> dict[str, Any]:
    if not url.lower().startswith(("http://", "https://")):
        return {"error": "url must start with http:// or https://"}
    output = _run(["curl", "-sSI", "--max-time", "12", url], timeout=15)
    if output.startswith("ERROR:"):
        return {"error": output}
    headers: dict[str, str] = {}
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
    status = headers.get("status", "").split()[0] if "status" in headers else "unknown"
    return {"url": url, "headers": headers, "security_headers_missing": missing, "status_code": status}


def scan_nikto(target: str) -> dict[str, Any]:
    if not DOMAIN_PATTERN.fullmatch(target) and not IP_PATTERN.fullmatch(target):
        return {"error": "target must be a domain or IP"}
    output = _run(["nikto", "-h", target, "-maxtime", "60s"], timeout=90)
    if output.startswith("ERROR:"):
        return {"error": output}
    vulnerabilities = []
    info_items = []
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("+"):
            if "OSVDB" in stripped or "vulnerability" in stripped.lower():
                vulnerabilities.append(stripped)
            elif "Server:" in stripped or "target" in stripped.lower():
                info_items.append(stripped)
    return {
        "target": target,
        "vulnerabilities": vulnerabilities,
        "vuln_count": len(vulnerabilities),
        "info": info_items,
        "raw": output[-4096:],
    }


def scan_sqlmap(url: str) -> dict[str, Any]:
    if not url.lower().startswith(("http://", "https://")):
        return {"error": "url must start with http:// or https://"}
    output = _run(["sqlmap", "-u", url, "--batch", "--level=1", "--risk=1", "--threads=4"], timeout=120)
    if output.startswith("ERROR:"):
        return {"error": output}
    injectable = "is vulnerable" in output.lower() or "injectable" in output.lower()
    findings = []
    for line in output.splitlines():
        if "injectable" in line.lower() or "payload" in line.lower() or "parameter" in line.lower():
            findings.append(line.strip())
    return {"url": url, "injectable": injectable, "findings": findings, "raw": output[-4096:]}


def scan_whatweb(url: str) -> dict[str, Any]:
    if not url.lower().startswith(("http://", "https://")):
        return {"error": "url must start with http:// or https://"}
    output = _run(["whatweb", "-a", "3", "--color=never", url], timeout=30)
    if output.startswith("ERROR:"):
        return {"error": output}
    technologies = []
    for line in output.splitlines():
        if "[" in line:
            techs = re.findall(r"\[([^\]]+)\]", line)
            technologies.extend(techs)
    return {"url": url, "technologies": technologies, "raw": output[-4096:]}


def scan_wpscan(url: str) -> dict[str, Any]:
    if not url.lower().startswith(("http://", "https://")):
        return {"error": "url must start with http:// or https://"}
    output = _run(["wpscan", "--url", url, "--enumerate", "vp,vt,u", "--no-banner"], timeout=120)
    if output.startswith("ERROR:"):
        return {"error": output}
    plugins = re.findall(r"Title: ([^\n]+)", output)
    return {"url": url, "plugins": plugins, "raw": output[-4096:]}


def scan_dirb(url: str) -> dict[str, Any]:
    if not url.lower().startswith(("http://", "https://")):
        return {"error": "url must start with http:// or https://"}
    output = _run(["dirb", url], timeout=120)
    if output.startswith("ERROR:"):
        return {"error": output}
    found = re.findall(r"\+ ([^\n]+)", output)
    return {"url": url, "directories": found, "count": len(found), "raw": output[-4096:]}


def scan_nmap_vuln(target: str) -> dict[str, Any]:
    if not DOMAIN_PATTERN.fullmatch(target) and not IP_PATTERN.fullmatch(target):
        return {"error": "target must be a domain or IP"}
    output = _run(["nmap", "-Pn", "--script", "vuln", target], timeout=300)
    if output.startswith("ERROR:"):
        return {"error": output}
    vulns = []
    for line in output.splitlines():
        if "VULNERABLE" in line or "CVE-" in line:
            vulns.append(line.strip())
    return {"target": target, "vulnerabilities": vulns, "vuln_count": len(vulns), "raw": output[-4096:]}


def scan_nmap_auth(target: str) -> dict[str, Any]:
    if not DOMAIN_PATTERN.fullmatch(target) and not IP_PATTERN.fullmatch(target):
        return {"error": "target must be a domain or IP"}
    output = _run(["nmap", "-Pn", "--script", "auth", target], timeout=300)
    if output.startswith("ERROR:"):
        return {"error": output}
    auth_issues = []
    for line in output.splitlines():
        if "anonymous" in line.lower() or "default" in line.lower() or "no auth" in line.lower():
            auth_issues.append(line.strip())
    return {"target": target, "auth_issues": auth_issues, "raw": output[-4096:]}


def scan_sublist3r(domain: str) -> dict[str, Any]:
    if not DOMAIN_PATTERN.fullmatch(domain):
        return {"error": "invalid domain format"}
    output = _run(["sublist3r", "-d", domain], timeout=60)
    if output.startswith("ERROR:"):
        return {"error": output}
    subdomains = [line.strip() for line in output.splitlines() if domain in line and line.strip()]
    return {"domain": domain, "subdomains": subdomains, "count": len(subdomains), "raw": output[-4096:]}


def scan_theharvester(domain: str) -> dict[str, Any]:
    if not DOMAIN_PATTERN.fullmatch(domain):
        return {"error": "invalid domain format"}
    output = _run(["theHarvester", "-d", domain, "-b", "all"], timeout=120)
    if output.startswith("ERROR:"):
        return _email_harvest_dns(domain)
    emails = []
    subdomains = []
    for line in output.splitlines():
        if "@" in line and domain in line:
            emails.append(line.strip())
        elif domain in line and " " not in line and line.strip():
            subdomains.append(line.strip())
    if not emails and not subdomains:
        return _email_harvest_dns(domain)
    return {"domain": domain, "emails": list(set(emails)), "subdomains": list(set(subdomains)), "raw": output[-4096:]}


def _email_harvest_dns(domain: str) -> dict[str, Any]:
    emails: list[str] = []
    subdomains: list[str] = []

    output = _run(["dig", "MX", domain, "+short"], timeout=10)
    mx_records = [line.split()[-1].rstrip(".") for line in output.splitlines() if line.strip()]

    output = _run(["dig", "TXT", domain, "+short"], timeout=10)
    for line in output.splitlines():
        spf_match = re.search(r"include:([^\s\"]+)", line)
        if spf_match:
            spf_domain = spf_match.group(1).rstrip(".")
            subdomains.append(f"SPF include: {spf_domain}")
        if "v=spf1" in line:
            emails.append(f"SPF record found for {domain}")

    output = _run(["dig", "DMARC", f"_dmarc.{domain}", "+short"], timeout=10)
    if output.strip():
        subdomains.append(f"DMARC: _dmarc.{domain}")

    common_prefixes = ["info", "admin", "support", "sales", "contact", "help", "webmaster", "postmaster", "abuse", "noreply", "no-reply"]
    email_pattern_domains = [f"{prefix}@{domain}" for prefix in common_prefixes]
    emails.extend(email_pattern_domains)

    common_web = ["www", "mail", "webmail", "portal", "api", "admin", "login", "dev", "staging", "test", "shop", "blog"]
    for sub in common_web:
        try:
            test_output = _run(["dig", "+short", f"{sub}.{domain}"], timeout=5)
            if test_output.strip() and not test_output.startswith("ERROR:"):
                subdomains.append(f"{sub}.{domain}")
        except Exception:
            pass

    return {
        "domain": domain,
        "emails": emails,
        "subdomains": subdomains,
        "mx_records": mx_records,
        "count": len(subdomains),
        "method": "dns_harvest",
        "note": "theHarvester not installed — used DNS enumeration",
    }


def phone_lookup(phone: str, country_code: str = "") -> dict[str, Any]:
    clean = re.sub(r"[^\d+]", "", phone)
    if not clean.startswith("+"):
        if country_code:
            clean = f"+{country_code}{clean}"
        elif clean.startswith("0"):
            clean = f"+256{clean[1:]}"

    result: dict[str, Any] = {
        "phone": clean,
        "original": phone,
    }

    prefix_map = {
        "+25670": ("MTN Uganda", "Mobile"),
        "+25671": ("MTN Uganda", "Mobile"),
        "+25672": ("MTN Uganda", "Mobile"),
        "+25673": ("MTN Uganda", "Mobile"),
        "+25674": ("MTN Uganda", "Mobile"),
        "+25675": ("MTN Uganda", "Mobile"),
        "+25676": ("MTN Uganda", "Mobile"),
        "+25677": ("MTN Uganda", "Mobile"),
        "+25678": ("MTN Uganda", "Mobile"),
        "+25679": ("MTN Uganda", "Mobile"),
        "+25631": ("Airtel Uganda", "Mobile"),
        "+25632": ("Airtel Uganda", "Mobile"),
        "+25633": ("Airtel Uganda", "Mobile"),
        "+25634": ("Airtel Uganda", "Mobile"),
        "+25635": ("Airtel Uganda", "Mobile"),
        "+25636": ("Airtel Uganda", "Mobile"),
        "+25639": ("Airtel Uganda", "Mobile"),
        "+25620": ("Uganda Telecom", "Mobile"),
        "+25621": ("Uganda Telecom", "Mobile"),
        "+25622": ("Lycamobile Uganda", "Mobile"),
        "+25623": (" Smile Communications", "Mobile"),
        "+25641": ("Airtel Uganda", "Mobile"),
        "+1": ("United States/Canada", "Unknown"),
        "+44": ("United Kingdom", "Unknown"),
        "+91": ("India", "Unknown"),
        "+254": ("Kenya", "Unknown"),
        "+255": ("Tanzania", "Unknown"),
        "+256": ("Uganda", "Unknown"),
    }

    carrier = "Unknown"
    line_type = "Unknown"
    country = "Unknown"
    for prefix in sorted(prefix_map.keys(), key=len, reverse=True):
        if clean.startswith(prefix):
            carrier, line_type = prefix_map[prefix]
            break

    country_codes = {
        "+256": "Uganda", "+1": "USA/Canada", "+44": "UK", "+91": "India",
        "+254": "Kenya", "+255": "Tanzania", "+234": "Nigeria", "+27": "South Africa",
        "+33": "France", "+49": "Germany", "+81": "Japan", "+86": "China",
        "+61": "Australia", "+55": "Brazil", "+52": "Mexico", "+7": "Russia",
    }
    for code in sorted(country_codes.keys(), key=len, reverse=True):
        if clean.startswith(code):
            country = country_codes[code]
            break

    result["carrier"] = carrier
    result["line_type"] = line_type
    result["country"] = country
    result["international"] = clean
    result["local"] = clean.replace("+256", "0") if clean.startswith("+256") else clean
    result["valid"] = len(clean) >= 8

    if country == "Uganda" and carrier != "Unknown":
        carrier_domains = {
            "MTN Uganda": "mtn.co.ug",
            "Airtel Uganda": "ug.airtel.com",
            "Uganda Telecom": "utl.co.ug",
        }
        if carrier in carrier_domains:
            domain = carrier_domains[carrier]
            result["carrier_domain"] = domain
            mx_output = _run(["dig", "MX", domain, "+short"], timeout=10)
            if mx_output.strip() and not mx_output.startswith("ERROR:"):
                result["mx_records"] = [line.split()[-1].rstrip(".") for line in mx_output.splitlines()]
                if result["mx_records"]:
                    result["email_provider"] = _detect_email_provider(result["mx_records"][0])

    return result


def _detect_email_provider(mx_record: str) -> str:
    mx_lower = mx_record.lower()
    if "google" in mx_lower or "gmail" in mx_lower or "googlemail" in mx_lower:
        return "Google Workspace / Gmail"
    if "outlook" in mx_lower or "microsoft" in mx_lower or "office365" in mx_lower:
        return "Microsoft 365 / Outlook"
    if "protonmail" in mx_lower:
        return "ProtonMail"
    if "zoho" in mx_lower:
        return "Zoho Mail"
    if "mimecast" in mx_lower:
        return "Mimecast (email security gateway)"
    if "barracuda" in mx_lower:
        return "Barracuda (email security gateway)"
    return "Unknown provider"


def email_lookup(email: str) -> dict[str, Any]:
    if "@" not in email:
        return {"error": "invalid email format"}
    _, domain = email.split("@", 1)
    result: dict[str, Any] = {"email": email, "domain": domain}

    whois_data = whois_lookup(domain)
    if "error" not in whois_data:
        result["domain_registrar"] = whois_data.get("registrar")
        result["domain_created"] = whois_data.get("created")
        result["domain_expires"] = whois_data.get("expires")
        result["domain_organization"] = whois_data.get("organization")

    mx_output = _run(["dig", "MX", domain, "+short"], timeout=10)
    mx_records = [line.split()[-1].rstrip(".") for line in mx_output.splitlines() if line.strip()]
    result["mx_records"] = mx_records
    if mx_records:
        result["email_provider"] = _detect_email_provider(mx_records[0])

    spf_output = _run(["dig", "TXT", domain, "+short"], timeout=10)
    for line in spf_output.splitlines():
        if "v=spf1" in line:
            result["spf_record"] = line.strip().strip('"')
            break

    dmarc_output = _run(["dig", "TXT", f"_dmarc.{domain}", "+short"], timeout=10)
    for line in dmarc_output.splitlines():
        if "v=DMARC" in line:
            result["dmarc_record"] = line.strip().strip('"')
            break

    tls_output = _run(["dig", "TLSA", f"_25._tcp.{domain}", "+short"], timeout=10)
    if tls_output.strip() and not tls_output.startswith("ERROR:"):
        result["dane_tlsa"] = True

    return result


def run_tool_command(command_id: str, args: dict[str, str]) -> dict[str, Any]:
    import shutil
    from tool_registry import TOOL_REGISTRY, resolve_host_argv

    spec = TOOL_REGISTRY.get(command_id)
    if not spec:
        return {"error": f"Unknown tool: {command_id}"}
    if not any(shutil.which(b) for b in spec.host_binaries):
        return {"error": f"Tool not installed: {command_id}", "binaries": list(spec.host_binaries)}
    try:
        argv = resolve_host_argv(spec, args)
        output = _run(list(argv), timeout=spec.timeout_seconds)
        return {
            "command_id": command_id,
            "exit_code": 0 if not output.startswith("ERROR:") else 1,
            "output": output[-8192:],
            "truncated": len(output) > 8192,
        }
    except ValueError as exc:
        return {"command_id": command_id, "error": str(exc)}
    except Exception as exc:
        return {"command_id": command_id, "error": str(exc)}

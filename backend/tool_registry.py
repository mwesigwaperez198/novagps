import concurrent.futures
import json
import platform
import re
import shutil
import socket
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Mapping

from config import get_settings


ROLE_RANK = {"viewer": 10, "auditor": 20, "operator": 30, "admin": 40}
ARG_PATTERN = re.compile(r"^[a-zA-Z0-9_.:/@=-]{0,160}$")
FILE_PATH_PATTERN = re.compile(r"^[a-zA-Z0-9_.:/\\ @=-]{1,240}$")
IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$")
DOMAIN_PATTERN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")


@dataclass(frozen=True)
class ToolSpec:
    command_id: str
    description: str
    kind: str
    allowed_roles: tuple[str, ...]
    allowed_args: tuple[str, ...] = ()
    timeout_seconds: int = 15
    host_binaries: tuple[str, ...] = ()
    per_platform_argv: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    validators: Mapping[str, Callable[[str], None]] = field(default_factory=dict)


def _validate_http_url(value: str) -> None:
    if not value.lower().startswith(("http://", "https://")):
        raise ValueError("url must start with http:// or https://")


def _validate_path_within_data_dir(value: str) -> None:
    if not FILE_PATH_PATTERN.fullmatch(value):
        raise ValueError("path contains forbidden characters")
    candidate = Path(value).expanduser()
    data_root = Path(get_settings().data_dir or "data").resolve()
    resolved = candidate.resolve() if candidate.exists() else Path(str(candidate))
    inside = data_root in resolved.parents or resolved == data_root
    if not inside and not candidate.is_absolute():
        joined = (data_root / candidate).resolve()
        if data_root not in joined.parents:
            raise ValueError("path must stay inside DATA_DIR")
        return
    if not inside:
        raise ValueError("path must stay inside DATA_DIR")


def _validate_target(value: str) -> None:
    if not IP_PATTERN.fullmatch(value) and not DOMAIN_PATTERN.fullmatch(value):
        raise ValueError("target must be a valid IP address or domain name")


def _validate_interface(value: str) -> None:
    if not re.fullmatch(r"^[a-zA-Z0-9_-]{1,32}$", value):
        raise ValueError("invalid interface name")


def builtin_system_info(args: dict[str, str]) -> tuple[int, str]:
    lines = [
        "NOVA BUILTIN",
        f"platform={sys.platform}",
        f"system={platform.system()} {platform.release()}",
        f"machine={platform.machine()}",
        f"python={platform.python_version()}",
        f"time={datetime.now(timezone.utc).isoformat()}",
    ]
    return 0, "\n".join(lines) + "\n"


BUILTINS: Mapping[str, Callable[[dict[str, str]], tuple[int, str]]] = MappingProxyType(
    {
        "system.info": builtin_system_info,
    }
)


# ----------------------------------------------------------------------
# Built-in fallbacks: real (pure-Python) implementations that keep a tool
# usable when its host binary is not installed. They only run when the
# binary is missing, so installed binaries still take priority.
# ----------------------------------------------------------------------

TOP_PORTS = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5900, 8000, 8080, 8443,
)
SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps",
    995: "pop3s", 1723: "pptp", 3306: "mysql", 3389: "ms-wbt-server",
    5900: "vnc", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    554: "rtsp", 161: "snmp",
}


def _resolve_target(target: str) -> str:
    try:
        socket.inet_aton(target)
        return target
    except socket.error:
        return socket.gethostbyname(target)


def _probe_port(target: str, port: int, timeout: float = 0.6) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((target, port)) == 0
    except socket.error:
        return False
    finally:
        sock.close()


def fallback_scan_topports(args: dict[str, str]) -> tuple[int, str]:
    target = _resolve_target(args["target"])
    lines = ["NOVA FALLBACK tcp-connect", f"target={target}", "PORT\tSTATE\tSERVICE"]
    open_ports = []

    def probe(port: int) -> tuple[int, bool]:
        return port, _probe_port(target, port)

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        for port, is_open in pool.map(probe, TOP_PORTS):
            if is_open:
                open_ports.append(port)
    open_ports.sort()
    for port in open_ports:
        lines.append(f"{port}/tcp\topen\t{SERVICE_NAMES.get(port, 'tcp')}")
    lines.append(f"\n{len(open_ports)} open port(s) of {len(TOP_PORTS)} probed")
    return 0, "\n".join(lines) + "\n"


def _grab_banner(target: str, port: int, timeout: float = 1.0) -> str:
    try:
        if port == 443:
            ctx = ssl.create_default_context()
            with socket.create_connection((target, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=target) as tls:
                    return tls.version() or "ssl"
        with socket.create_connection((target, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            return sock.recv(200).decode("utf-8", errors="replace").strip()[:160]
    except (socket.error, ssl.SSLError, ValueError):
        return ""


def fallback_scan_services(args: dict[str, str]) -> tuple[int, str]:
    target = _resolve_target(args["target"])
    probe_set = (22, 25, 80, 110, 143, 443, 3306, 3389, 554, 5900, 8080)
    lines = ["NOVA FALLBACK service-detect", f"target={target}", "PORT\tSERVICE\tBANNER"]

    def probe(port: int) -> tuple[int, str]:
        if not _probe_port(target, port):
            return port, ""
        return port, _grab_banner(target, port)

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        results = {port: banner for port, banner in pool.map(probe, probe_set) if banner}
    for port in sorted(results):
        banner = results[port].replace("\n", "\\n")
        lines.append(f"{port}/tcp\t{SERVICE_NAMES.get(port, 'tcp')}\t{banner[:80]}")
    if not results:
        lines.append("no services detected")
    return 0, "\n".join(lines) + "\n"


def fallback_reverse_dns(args: dict[str, str]) -> tuple[int, str]:
    lines = ["NOVA FALLBACK dns", f"ip={args['ip']}"]
    try:
        host = socket.gethostbyaddr(args["ip"])[0]
        lines.append(f"ptr={host}")
    except (socket.herror, socket.gaierror):
        lines.append("ptr=(no PTR record)")
    return 0, "\n".join(lines) + "\n"


def _http_headers_live(url: str, timeout: int = 12) -> tuple[int, list[str]]:
    request = urllib.request.Request(
        url, method="GET",
        headers={"User-Agent": "nova-fallback/1.0", "Accept": "*/*"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, [f"{key}: {value}" for key, value in response.getheaders()]
    except urllib.error.HTTPError as exc:
        return exc.code, [f"{key}: {value}" for key, value in exc.headers.items()]


def fallback_http_headers(args: dict[str, str]) -> tuple[int, str]:
    url = args["url"]
    status, headers = _http_headers_live(url)
    lines = ["NOVA FALLBACK http-headers", f"url={url}", f"HTTP/1.1 {status}"]
    lines.extend(headers)
    return 0, "\n".join(lines) + "\n"


def fallback_http_tech(args: dict[str, str]) -> tuple[int, str]:
    url = args["url"]
    status, headers = _http_headers_live(url)
    combined = "\n".join(headers).lower()
    hints: list[str] = ["apache", "nginx", "cloudflare", "wordpress", "drupal", "joomla",
                        "express", "next.js", "react", "django", "rails", "iis", "caddy",
                        "openresty", "gunicorn", "uvicorn"]
    found = [hint for hint in hints if hint in combined]
    lines = [
        "NOVA FALLBACK http-tech",
        f"url={url}",
        f"HTTP/1.1 {status}",
    ]
    server = next((h.split(":", 1)[1].strip() for h in headers if h.lower().startswith("server:")), "")
    if server:
        lines.append(f"server={server}")
    inferred = found or ["generic-web-server"]
    lines.append(f"technologies={','.join(inferred)}")
    return 0, "\n".join(lines) + "\n"


def fallback_crypto_info(args: dict[str, str]) -> tuple[int, str]:
    target = args["target"]
    ctx = ssl.create_default_context()
    lines = ["NOVA FALLBACK tls", f"target={target}:443"]
    try:
        with socket.create_connection((target, 443), timeout=8) as raw:
            with ctx.wrap_socket(raw, server_hostname=target) as tls:
                cert = tls.getpeercert()
                cipher, proto, _ = tls.cipher()
                lines.append(f"version={tls.version()}")
                lines.append(f"protocol={proto}")
                lines.append(f"cipher={cipher}")
                subject = cert.get("subject", ())
                issuer = cert.get("issuer", ())
                cn = dict(subject).get("commonName", "?")
                org = dict(subject).get("organizationName", "?")
                lines.append(f"subject_cn={cn}")
                lines.append(f"subject_org={org}")
                lines.append(f"issuer_cn={dict(issuer).get('commonName', '?')}")
                lines.append(f"not_after={cert.get('notAfter', '?')}")
    except (socket.error, ssl.SSLError, ValueError) as exc:
        lines.append(f"error={exc}")
    return 0, "\n".join(lines) + "\n"


def fallback_whois_domain(args: dict[str, str]) -> tuple[int, str]:
    domain = args["domain"]
    lines = ["NOVA FALLBACK rdap", f"domain={domain}"]
    try:
        request = urllib.request.Request(
            f"https://rdap.org/domain/{domain}",
            headers={"Accept": "application/rdap+json", "User-Agent": "nova-fallback/1.0"},
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))
        lines.append(f"handle={data.get('handle', '?')}")
        lines.append(f"status={','.join(data.get('status', []))}")
        lines.append(f"ldh_name={data.get('ldhName', '?')}")
        for event in data.get("events", []):
            lines.append(f"event={event.get('eventAction')}={event.get('eventDate', '')}")
        for entity in data.get("entities", []):
            if entity.get("roles"):
                lines.append(f"role={','.join(entity['roles'])} vcard={entity.get('vcardArray', ['?', []])}")
        nameservers = [n.get("ldhName", "") for n in data.get("nameservers", [])]
        lines.append(f"nameservers={','.join(nameservers)}")
    except (urllib.error.URLError, socket.timeout, ValueError) as exc:
        lines.append(f"error=RDAP lookup failed: {exc}")
    return 0, "\n".join(lines) + "\n"


FALLBACKS: Mapping[str, Callable[[dict[str, str]], tuple[int, str]]] = MappingProxyType(
    {
        "net.scan.topports": fallback_scan_topports,
        "net.scan.services": fallback_scan_services,
        "net.dns.reverse": fallback_reverse_dns,
        "osint.http.headers": fallback_http_headers,
        "osint.http.tech": fallback_http_tech,
        "web.server.headers": fallback_http_headers,
        "crypto.info": fallback_crypto_info,
        "osint.whois.domain": fallback_whois_domain,
    }
)


TOOL_REGISTRY: Mapping[str, ToolSpec] = MappingProxyType(
    {
        "system.info": ToolSpec(
            command_id="system.info",
            description="Report host platform details (built in, no subprocess).",
            kind="builtin",
            allowed_roles=("viewer", "operator", "admin", "auditor"),
        ),
        "dns.lookup": ToolSpec(
            command_id="dns.lookup",
            description="Resolve an authorized hostname with host resolver tools.",
            kind="host",
            allowed_roles=("auditor", "operator", "admin"),
            allowed_args=("name",),
            host_binaries=("nslookup", "getent"),
            per_platform_argv={
                "windows": ("nslookup", "{name}"),
                "darwin": ("nslookup", "{name}"),
                "linux_getent": ("getent", "hosts", "{name}"),
                "linux_nslookup": ("nslookup", "{name}"),
            },
        ),
        "net.stat.connections": ToolSpec(
            command_id="net.stat.connections",
            description="List active connections on this host (read-only).",
            kind="host",
            allowed_roles=("auditor", "operator", "admin"),
            host_binaries=("ss", "netstat"),
            timeout_seconds=10,
            per_platform_argv={
                "windows": ("netstat", "-ano"),
                "darwin": ("netstat", "-anv"),
                "linux_ss": ("ss", "-tunp"),
                "linux_netstat": ("netstat", "-tunp"),
            },
        ),
        "net.scan.topports": ToolSpec(
            command_id="net.scan.topports",
            description="Nmap top-20 TCP port scan of an in-scope target only.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("target",),
            validators={"target": _validate_target},
            timeout_seconds=60,
            host_binaries=("nmap",),
            per_platform_argv={
                "default": ("nmap", "-Pn", "--top-ports", "20", "{target}"),
            },
        ),
        "net.scan.full": ToolSpec(
            command_id="net.scan.full",
            description="Nmap full TCP port scan of an authorized target.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("target",),
            validators={"target": _validate_target},
            timeout_seconds=300,
            host_binaries=("nmap",),
            per_platform_argv={
                "default": ("nmap", "-Pn", "-sS", "-p-", "{target}"),
            },
        ),
        "net.scan.udp": ToolSpec(
            command_id="net.scan.udp",
            description="Nmap top-20 UDP port scan of an authorized target.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("target",),
            validators={"target": _validate_target},
            timeout_seconds=120,
            host_binaries=("nmap",),
            per_platform_argv={
                "default": ("nmap", "-Pn", "-sU", "--top-ports", "20", "{target}"),
            },
        ),
        "net.scan.services": ToolSpec(
            command_id="net.scan.services",
            description="Nmap service version detection scan of an authorized target.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("target",),
            validators={"target": _validate_target},
            timeout_seconds=180,
            host_binaries=("nmap",),
            per_platform_argv={
                "default": ("nmap", "-Pn", "-sV", "--top-ports", "100", "{target}"),
            },
        ),
        "net.scan.masscan": ToolSpec(
            command_id="net.scan.masscan",
            description="High-speed masscan TCP port scan (10k+ ports/sec).",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("target",),
            validators={"target": _validate_target},
            timeout_seconds=60,
            host_binaries=("masscan",),
            per_platform_argv={
                "default": ("masscan", "-p1-65535", "--rate=1000", "{target}"),
            },
        ),
        "net.capture.interfaces": ToolSpec(
            command_id="net.capture.interfaces",
            description="List capture-capable network interfaces via tshark/dumpcap -D.",
            kind="host",
            allowed_roles=("auditor", "operator", "admin"),
            timeout_seconds=10,
            host_binaries=("tshark", "dumpcap"),
            per_platform_argv={
                "windows_tshark": ("tshark", "-D"),
                "windows_dumpcap": ("dumpcap", "-D"),
                "darwin_tshark": ("tshark", "-D"),
                "linux_dumpcap": ("dumpcap", "-D"),
                "linux_tshark": ("tshark", "-D"),
            },
        ),
        "net.capture.start": ToolSpec(
            command_id="net.capture.start",
            description="Start packet capture on an interface (capture_file path for output).",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("interface", "filter"),
            validators={"interface": _validate_interface},
            timeout_seconds=10,
            host_binaries=("tshark",),
            per_platform_argv={
                "default": ("tshark", "-i", "{interface}", "-a", "duration:30", "-w", "/tmp/nova_capture.pcap"),
            },
        ),
        "net.dns.reverse": ToolSpec(
            command_id="net.dns.reverse",
            description="Reverse DNS lookup for an IP address.",
            kind="host",
            allowed_roles=("auditor", "operator", "admin"),
            allowed_args=("ip",),
            host_binaries=("dig", "nslookup"),
            per_platform_argv={
                "linux_dig": ("dig", "-x", "{ip}", "+short"),
                "linux_nslookup": ("nslookup", "{ip}"),
            },
        ),
        "net.dns.zone": ToolSpec(
            command_id="net.dns.zone",
            description="DNS zone transfer attempt against a domain's nameservers.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("domain",),
            host_binaries=("dig",),
            per_platform_argv={
                "default": ("dig", "axfr", "{domain}"),
            },
        ),
        "osint.http.headers": ToolSpec(
            command_id="osint.http.headers",
            description="Fetch response headers of an authorized http(s) URL.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("url",),
            validators={"url": _validate_http_url},
            timeout_seconds=20,
            host_binaries=("curl",),
            per_platform_argv={
                "default": ("curl", "-sSI", "--max-time", "12", "{url}"),
            },
        ),
        "osint.http.tech": ToolSpec(
            command_id="osint.http.tech",
            description="Fingerprint web technologies used by a target URL.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("url",),
            validators={"url": _validate_http_url},
            timeout_seconds=30,
            host_binaries=("curl",),
            per_platform_argv={
                "default": ("curl", "-sSI", "--max-time", "15", "{url}"),
            },
        ),
        "osint.whois.domain": ToolSpec(
            command_id="osint.whois.domain",
            description="WHOIS lookup for domain registration information.",
            kind="host",
            allowed_roles=("auditor", "operator", "admin"),
            allowed_args=("domain",),
            host_binaries=("whois",),
            per_platform_argv={
                "default": ("whois", "{domain}"),
            },
        ),
        "osint.subdomains": ToolSpec(
            command_id="osint.subdomains",
            description="Discover subdomains for a target domain using DNS brute-force.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("domain",),
            host_binaries=("nmap",),
            per_platform_argv={
                "default": ("nmap", "--script", "dns-brute", "--script-args", "dns-brute.threads=5", "{domain}"),
            },
        ),
        "forensics.hash.file": ToolSpec(
            command_id="forensics.hash.file",
            description="SHA-256 a file under DATA_DIR for chain-of-custody.",
            kind="host",
            allowed_roles=("auditor", "operator", "admin"),
            allowed_args=("path",),
            validators={"path": _validate_path_within_data_dir},
            timeout_seconds=30,
            host_binaries=("sha256sum", "certutil"),
            per_platform_argv={
                "windows_certutil": ("certutil", "-hashfile", "{path}", "SHA256"),
                "posix_sha256sum": ("sha256sum", "{path}"),
            },
        ),
        "forensics.yara.scan": ToolSpec(
            command_id="forensics.yara.scan",
            description="Scan a file or directory with YARA rules for malware detection.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("path",),
            timeout_seconds=60,
            host_binaries=("yara",),
            per_platform_argv={
                "default": ("yara", "-r", "/etc/yara/rules", "{path}"),
            },
        ),
        "vpn.status": ToolSpec(
            command_id="vpn.status",
            description="Show current VPN tunnel status (WireGuard or OpenVPN).",
            kind="host",
            allowed_roles=("viewer", "operator", "admin"),
            host_binaries=("wg",),
            per_platform_argv={
                "default": ("wg", "show"),
            },
        ),
        "ids.status": ToolSpec(
            command_id="ids.status",
            description="Show Suricata IDS status and recent alerts.",
            kind="host",
            allowed_roles=("viewer", "operator", "admin"),
            host_binaries=("suricata",),
            per_platform_argv={
                "default": ("suricata", "--list-keywords"),
            },
        ),
        "wifi.scan": ToolSpec(
            command_id="wifi.scan",
            description="Scan for nearby wireless networks using aircrack-ng.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("interface",),
            validators={"interface": _validate_interface},
            timeout_seconds=30,
            host_binaries=("aircrack-ng",),
            per_platform_argv={
                "default": ("aircrack-ng", "--test", "{interface}"),
            },
        ),
        "mac.change": ToolSpec(
            command_id="mac.change",
            description="Change MAC address of a network interface for anonymity.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("interface",),
            validators={"interface": _validate_interface},
            timeout_seconds=10,
            host_binaries=("macchanger",),
            per_platform_argv={
                "default": ("macchanger", "-r", "{interface}"),
            },
        ),
        "web.server.headers": ToolSpec(
            command_id="web.server.headers",
            description="Analyze HTTP security headers of a web server.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("url",),
            validators={"url": _validate_http_url},
            timeout_seconds=15,
            host_binaries=("curl",),
            per_platform_argv={
                "default": ("curl", "-sSI", "--max-time", "10", "{url}"),
            },
        ),
        "cred.crack.hash": ToolSpec(
            command_id="cred.crack.hash",
            description="Crack a password hash file using John the Ripper.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("path",),
            validators={"path": _validate_path_within_data_dir},
            timeout_seconds=120,
            host_binaries=("john",),
            per_platform_argv={
                "default": ("john", "--show", "{path}"),
            },
        ),
        "crypto.info": ToolSpec(
            command_id="crypto.info",
            description="Show TLS/SSL certificate information for a host.",
            kind="host",
            allowed_roles=("auditor", "operator", "admin"),
            allowed_args=("target",),
            validators={"target": _validate_target},
            timeout_seconds=15,
            host_binaries=("openssl",),
            per_platform_argv={
                "default": ("openssl", "s_client", "-connect", "{target}:443"),
            },
        ),
        "osint.theharvester": ToolSpec(
            command_id="osint.theharvester",
            description="Harvest emails, subdomains, hosts, and IPs using theHarvester.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("domain",),
            host_binaries=("theHarvester",),
            timeout_seconds=120,
            per_platform_argv={
                "default": ("theHarvester", "-d", "{domain}", "-b", "all"),
            },
        ),
        "osint.sublist3r": ToolSpec(
            command_id="osint.sublist3r",
            description="Enumerate subdomains using Sublist3r.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("domain",),
            host_binaries=("sublist3r",),
            timeout_seconds=60,
            per_platform_argv={
                "default": ("sublist3r", "-d", "{domain}"),
            },
        ),
        "osint.amass.enum": ToolSpec(
            command_id="osint.amass.enum",
            description="Attack surface mapping with OWASP Amass.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("domain",),
            host_binaries=("amass",),
            timeout_seconds=300,
            per_platform_argv={
                "default": ("amass", "enum", "-passive", "-d", "{domain}"),
            },
        ),
        "osint.whatweb": ToolSpec(
            command_id="osint.whatweb",
            description="Identify web technologies, CMS, frameworks with WhatWeb.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("url",),
            validators={"url": _validate_http_url},
            timeout_seconds=30,
            host_binaries=("whatweb",),
            per_platform_argv={
                "default": ("whatweb", "-a", "3", "--color=never", "{url}"),
            },
        ),
        "osint.wpscan": ToolSpec(
            command_id="osint.wpscan",
            description="WordPress security scanner - enumerate plugins, themes, users.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("url",),
            validators={"url": _validate_http_url},
            timeout_seconds=120,
            host_binaries=("wpscan",),
            per_platform_argv={
                "default": ("wpscan", "--url", "{url}", "--enumerate", "vp,vt,u"),
            },
        ),
        "osint.dirb": ToolSpec(
            command_id="osint.dirb",
            description="Web content scanner - brute-force directories and files.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("url",),
            validators={"url": _validate_http_url},
            timeout_seconds=120,
            host_binaries=("dirb",),
            per_platform_argv={
                "default": ("dirb", "{url}"),
            },
        ),
        "osint.nikto.scan": ToolSpec(
            command_id="osint.nikto.scan",
            description="Comprehensive web server scanner for vulnerabilities.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("target",),
            validators={"target": _validate_target},
            timeout_seconds=180,
            host_binaries=("nikto",),
            per_platform_argv={
                "default": ("nikto", "-h", "{target}"),
            },
        ),
        "osint.sqlmap": ToolSpec(
            command_id="osint.sqlmap",
            description="SQL injection detection and exploitation tool.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("url",),
            validators={"url": _validate_http_url},
            timeout_seconds=300,
            host_binaries=("sqlmap",),
            per_platform_argv={
                "default": ("sqlmap", "-u", "{url}", "--batch", "--level=1"),
            },
        ),
        "osint.hydra": ToolSpec(
            command_id="osint.hydra",
            description="Network login cracker - brute-force SSH, FTP, HTTP, etc.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("target",),
            validators={"target": _validate_target},
            timeout_seconds=120,
            host_binaries=("hydra",),
            per_platform_argv={
                "default": ("hydra", "-h"),
            },
        ),
        "osint.maltego.transform": ToolSpec(
            command_id="osint.maltego.transform",
            description="Run Maltego CLI transforms for OSINT gathering.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("target",),
            timeout_seconds=120,
            host_binaries=("maltego",),
            per_platform_argv={
                "default": ("maltego",),
            },
        ),
        "osint.reconng": ToolSpec(
            command_id="osint.reconng",
            description="Full-featured web reconnaissance framework.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("domain",),
            host_binaries=("recon-ng",),
            timeout_seconds=120,
            per_platform_argv={
                "default": ("recon-ng",),
            },
        ),
        "osint.spiderfoot": ToolSpec(
            command_id="osint.spiderfoot",
            description="Automated OSINT collection - IPs, domains, emails, names.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("target",),
            validators={"target": _validate_target},
            timeout_seconds=300,
            host_binaries=("spiderfoot",),
            per_platform_argv={
                "default": ("spiderfoot",),
            },
        ),
        "pentest.nmap.vuln": ToolSpec(
            command_id="pentest.nmap.vuln",
            description="Nmap vulnerability scan using NSE scripts.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("target",),
            validators={"target": _validate_target},
            timeout_seconds=300,
            host_binaries=("nmap",),
            per_platform_argv={
                "default": ("nmap", "-Pn", "--script", "vuln", "{target}"),
            },
        ),
        "pentest.nmap.exploit": ToolSpec(
            command_id="pentest.nmap.exploit",
            description="Nmap exploit scan using NSE scripts.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("target",),
            validators={"target": _validate_target},
            timeout_seconds=300,
            host_binaries=("nmap",),
            per_platform_argv={
                "default": ("nmap", "-Pn", "--script", "exploit", "{target}"),
            },
        ),
        "pentest.nmap.auth": ToolSpec(
            command_id="pentest.nmap.auth",
            description="Nmap authentication bypass scan.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("target",),
            validators={"target": _validate_target},
            timeout_seconds=300,
            host_binaries=("nmap",),
            per_platform_argv={
                "default": ("nmap", "-Pn", "--script", "auth", "{target}"),
            },
        ),
        "pentest.nmap.brute": ToolSpec(
            command_id="pentest.nmap.brute",
            description="Nmap brute-force attack scripts.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("target",),
            validators={"target": _validate_target},
            timeout_seconds=300,
            host_binaries=("nmap",),
            per_platform_argv={
                "default": ("nmap", "-Pn", "--script", "brute", "{target}"),
            },
        ),
        "pentest.nmap.dos": ToolSpec(
            command_id="pentest.nmap.dos",
            description="Nmap DoS stress test scripts.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("target",),
            validators={"target": _validate_target},
            timeout_seconds=300,
            host_binaries=("nmap",),
            per_platform_argv={
                "default": ("nmap", "-Pn", "--script", "dos", "{target}"),
            },
        ),
        "pentest.nmap.fuzz": ToolSpec(
            command_id="pentest.nmap.fuzz",
            description="Nmap fuzzing scripts for protocol testing.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("target",),
            validators={"target": _validate_target},
            timeout_seconds=300,
            host_binaries=("nmap",),
            per_platform_argv={
                "default": ("nmap", "-Pn", "--script", "fuzz", "{target}"),
            },
        ),
        "net.intercept.arp": ToolSpec(
            command_id="net.intercept.arp",
            description="ARP spoofing for network traffic interception.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("interface",),
            validators={"interface": _validate_interface},
            timeout_seconds=30,
            host_binaries=("arpspoof",),
            per_platform_argv={
                "default": ("arpspoof", "-i", "{interface}"),
            },
        ),
        "net.intercept.mitmproxy": ToolSpec(
            command_id="net.intercept.mitmproxy",
            description="Start mitmproxy for HTTPS traffic interception.",
            kind="host",
            allowed_roles=("operator", "admin"),
            timeout_seconds=30,
            host_binaries=("mitmproxy",),
            per_platform_argv={
                "default": ("mitmdump", "--listen-port", "8080"),
            },
        ),
        "net.wireless.deauth": ToolSpec(
            command_id="net.wireless.deauth",
            description="Send deauthentication frames to disconnect clients.",
            kind="host",
            allowed_roles=("operator", "admin"),
            allowed_args=("interface",),
            validators={"interface": _validate_interface},
            timeout_seconds=30,
            host_binaries=("aireplay-ng",),
            per_platform_argv={
                "default": ("aireplay-ng", "--deauth", "5", "{interface}"),
            },
        ),
    }
)


def tool_available(spec: ToolSpec) -> bool:
    if spec.kind == "builtin":
        return True
    return any(shutil.which(binary) for binary in spec.host_binaries)


def resolve_host_argv(spec: ToolSpec, args: dict[str, str]) -> tuple[str, ...]:
    system = platform.system().lower()
    platform_candidates = [
        (key, argv)
        for key, argv in spec.per_platform_argv.items()
        if key != "default" and key.startswith(system)
    ]
    default_candidates = [
        (key, argv) for key, argv in spec.per_platform_argv.items() if key == "default"
    ]

    chosen: tuple[str, ...] | None = None
    for _, argv in platform_candidates + default_candidates:
        if shutil.which(argv[0]):
            chosen = argv
            break
    if chosen is None and default_candidates:
        chosen = default_candidates[0][1]
    if chosen is None and platform_candidates:
        chosen = platform_candidates[0][1]
    if chosen is None:
        chosen = spec.per_platform_argv.get("default", ())
    if not chosen:
        raise ValueError(f"No executable argv available for {spec.command_id}")
    return tuple(token.format(**args) for token in chosen)

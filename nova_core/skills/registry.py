"""LAU skill registry.

A flat, auditable index of the external security/OSINT tools the queen agent
can drive. Each entry records what the tool is for, where it comes from, how to
install it, and whether it is present on this host. Nothing here downloads or
executes anything by itself — detection is a plain PATH/module probe.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
from dataclasses import dataclass, field


@dataclass(frozen=True)
class SkillSpec:
    key: str
    name: str
    category: str
    priority: str
    purpose: str
    source: str
    bins: tuple[str, ...] = ()
    modules: tuple[str, ...] = ()
    install: str = ""
    default_args: str = ""
    needs_target: bool = True
    lab_only: bool = False
    doc: str = ""

    def as_dict(self, available: bool) -> dict:
        return {
            "name": self.key,
            "title": self.name,
            "category": self.category,
            "priority": self.priority,
            "purpose": self.purpose,
            "source": self.source,
            "install": self.install,
            "available": available,
            "lab_only": self.lab_only,
        }


SKILLS: tuple[SkillSpec, ...] = (
    SkillSpec(
        key="phoneinfoga",
        name="PhoneInfoga",
        category="osint",
        priority="P0",
        purpose="Phone-number intelligence: carrier, line type, footprint scoping.",
        source="https://github.com/sundowndev/phoneinfoga",
        bins=("phoneinfoga",),
        install="docker run -it sundowndev/phoneinfoga scan -n <number>",
        default_args="scan -n",
        doc="lau skill phoneinfoga +256776335383  -> carrier/line-type/OSINT footprint for a subscriber number.",
    ),
    SkillSpec(
        key="nuclei",
        name="Nuclei",
        category="vuln",
        priority="P0",
        purpose="Template-driven vulnerability scanning of web hosts.",
        source="https://github.com/projectdiscovery/nuclei",
        bins=("nuclei",),
        install="go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        default_args="-silent -u",
        doc="lau skill nuclei https://target  -> runs the curated CVE/exposure template set against a host.",
    ),
    SkillSpec(
        key="httpx",
        name="httpx",
        category="recon",
        priority="P0",
        purpose="Fast HTTP probing: liveness, status, title, tech, TLS metadata.",
        source="https://github.com/projectdiscovery/httpx",
        bins=("httpx",),
        install="go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        default_args="-silent -title -tech-detect -status-code -u",
        doc="lau skill httpx https://target  -> one-line probe of a host's live HTTP surface.",
    ),
    SkillSpec(
        key="theharvester",
        name="theHarvester",
        category="osint",
        priority="P1",
        purpose="Emails, subdomains, hosts and names from public sources for a domain.",
        source="https://github.com/laramies/theHarvester",
        bins=("theHarvester",),
        modules=("theHarvester",),
        install="pipx install git+https://github.com/laramies/theHarvester.git@4.6.0",
        default_args="-b duckduckgo -d",
        doc="lau skill theharvester example.com  -> passive email/subdomain harvest for a domain.",
    ),
    SkillSpec(
        key="sherlock",
        name="Sherlock",
        category="osint",
        priority="P1",
        purpose="Hunt a username across hundreds of social networks.",
        source="https://github.com/sherlock-project/sherlock",
        bins=("sherlock",),
        modules=("sherlock",),
        install="pipx install sherlock-project",
        doc="lau skill sherlock <username>  -> found profiles across social sites.",
    ),
    SkillSpec(
        key="sqlmap",
        name="sqlmap",
        category="vuln",
        priority="P1",
        purpose="Detect and exploit SQL injection (authorised targets only).",
        source="https://github.com/sqlmapproject/sqlmap",
        bins=("sqlmap",),
        modules=("sqlmap",),
        install="pipx install sqlmap",
        default_args="--batch --level 1 --risk 1 -u",
        doc="lau skill sqlmap 'https://target/item?id=1'  -> injection test, batch mode.",
    ),
    SkillSpec(
        key="ffuf",
        name="ffuf",
        category="fuzz",
        priority="P1",
        purpose="High-speed web fuzzing for hidden paths and parameters.",
        source="https://github.com/ffuf/ffuf",
        bins=("ffuf",),
        install="go install github.com/ffuf/ffuf/v2@latest",
        default_args="-s -w /usr/share/wordlists/dirb/common.txt -u",
        doc="lau skill ffuf 'https://target/FUZZ'  -> directory/endpoint fuzz.",
    ),
    SkillSpec(
        key="nmap",
        name="Nmap",
        category="recon",
        priority="P1",
        purpose="Port, service and OS discovery.",
        source="https://github.com/nmap/nmap",
        bins=("nmap",),
        install="apk add nmap   # or: apt-get install nmap",
        default_args="-sT -sV -Pn -T4 --unprivileged",
        doc="lau skill nmap 10.0.0.5  -> service/version scan of a host.",
    ),
    SkillSpec(
        key="maigret",
        name="Maigret",
        category="osint",
        priority="P2",
        purpose="Username OSINT with report generation across 2000+ sites.",
        source="https://github.com/soxoj/maigret",
        bins=("maigret",),
        modules=("maigret",),
        install="pipx install maigret",
        doc="lau skill maigret <username>  -> social footprint report.",
    ),
    SkillSpec(
        key="whatweb",
        name="WhatWeb",
        category="recon",
        priority="P2",
        purpose="Web technology and CMS fingerprinting.",
        source="https://github.com/urbanadventurer/WhatWeb",
        bins=("whatweb",),
        install="apt-get install whatweb",
        default_args="--color=never",
        doc="lau skill whatweb https://target  -> CMS/framework/version fingerprint.",
    ),
    SkillSpec(
        key="mitmproxy",
        name="mitmproxy",
        category="proxy",
        priority="P2",
        purpose="Interactive HTTPS interception for API debugging on owned devices.",
        source="https://github.com/mitmproxy/mitmproxy",
        bins=("mitmproxy", "mitmdump"),
        modules=("mitmproxy",),
        install="pipx install mitmproxy",
        needs_target=False,
        doc="lau skill mitmproxy  -> launch the interception console (owned traffic only).",
    ),
    SkillSpec(
        key="yara",
        name="YARA",
        category="malware",
        priority="P2",
        purpose="Pattern-match files against malware/rule signatures.",
        source="https://github.com/VirusTotal/yara",
        bins=("yara",),
        install="apk add yara   # or: apt-get install yara",
        needs_target=True,
        doc="lau skill yara rules.yar /path/to/scan  -> signature hits.",
    ),
    SkillSpec(
        key="trufflehog",
        name="TruffleHog",
        category="secrets",
        priority="P2",
        purpose="Find committed credentials and secrets in repos/filesystems.",
        source="https://github.com/trufflesecurity/trufflehog",
        bins=("trufflehog",),
        install="go install github.com/trufflesecurity/trufflehog/v3@latest",
        default_args="filesystem --no-update --json",
        doc="lau skill trufflehog /path/to/repo  -> leaked-secret findings.",
    ),
    SkillSpec(
        key="zeek",
        name="Zeek",
        category="network",
        priority="P3",
        purpose="Network security monitor: connection/protocol logs and detections.",
        source="https://github.com/zeek/zeek",
        bins=("zeek",),
        install="apt-get install zeek   # lab network only",
        needs_target=False,
        lab_only=True,
        doc="lau skill zeek -i eth0  -> passive traffic analysis on a monitored interface.",
    ),
    SkillSpec(
        key="suricata",
        name="Suricata",
        category="network",
        priority="P3",
        purpose="IDS/IPS with signature and anomaly detection.",
        source="https://github.com/OISF/suricata",
        bins=("suricata",),
        install="apt-get install suricata   # lab network only",
        needs_target=False,
        lab_only=True,
        doc="lau skill suricata -i eth0  -> IDS run against a monitored interface.",
    ),
    SkillSpec(
        key="bettercap",
        name="bettercap",
        category="network",
        priority="P3",
        purpose="Network attack/monitoring framework (owned lab networks only).",
        source="https://github.com/bettercap/bettercap",
        bins=("bettercap",),
        install="go install github.com/bettercap/bettercap@latest",
        needs_target=False,
        lab_only=True,
        doc="lau skill bettercap  -> interactive console for a lab segment.",
    ),
    SkillSpec(
        key="kismet",
        name="Kismet",
        category="wireless",
        priority="P3",
        purpose="Wireless detector/drone/IDS for authorised spectrum audits.",
        source="https://github.com/kismetwireless/kismet",
        bins=("kismet",),
        install="apt-get install kismet   # lab/authorised only",
        needs_target=False,
        lab_only=True,
        doc="lau skill kismet  -> wireless survey console (authorised only).",
    ),
    SkillSpec(
        key="aircrack-ng",
        name="Aircrack-ng",
        category="wireless",
        priority="P3",
        purpose="Wi-Fi security auditing suite (own networks, written scope only).",
        source="https://github.com/aircrack-ng/aircrack-ng",
        bins=("aircrack-ng",),
        install="apt-get install aircrack-ng   # own networks only",
        needs_target=False,
        lab_only=True,
        doc="lau skill aircrack-ng  -> see suite binaries; run individual tools explicitly.",
    ),
)

_BY_KEY = {skill.key: skill for skill in SKILLS}


def get_skill(key: str) -> SkillSpec | None:
    return _BY_KEY.get(key.lower().strip())


def _module_present(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def is_available(skill: SkillSpec) -> bool:
    if any(shutil.which(binary) for binary in skill.bins):
        return True
    return any(_module_present(module) for module in skill.modules)


def lab_enabled() -> bool:
    return os.environ.get("NOVA_LAB_MODE", "0") == "1"


def list_skills() -> list[dict]:
    return [skill.as_dict(is_available(skill)) for skill in SKILLS]


def resolve_binary(skill: SkillSpec) -> str | None:
    for binary in skill.bins:
        found = shutil.which(binary)
        if found:
            return found
    return None

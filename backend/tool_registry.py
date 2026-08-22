import platform
import re
import shutil
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Mapping

from config import get_settings


ROLE_RANK = {"viewer": 10, "auditor": 20, "operator": 30, "admin": 40}
ARG_PATTERN = re.compile(r"^[a-zA-Z0-9_.:/@=-]{0,160}$")
FILE_PATH_PATTERN = re.compile(r"^[a-zA-Z0-9_.:/\\ @=-]{1,240}$")


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
            timeout_seconds=60,
            host_binaries=("nmap",),
            per_platform_argv={
                "default": ("nmap", "-Pn", "--top-ports", "20", "{target}"),
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

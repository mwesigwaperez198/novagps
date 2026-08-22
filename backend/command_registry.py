import argparse
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Mapping

from config import get_settings
from tool_registry import (
    BUILTINS,
    TOOL_REGISTRY,
    ToolSpec,
    resolve_host_argv,
    tool_available,
)


ROLE_RANK = {"viewer": 10, "auditor": 20, "operator": 30, "admin": 40}
ARG_PATTERN = re.compile(r"^[a-zA-Z0-9_.:/@=-]{0,160}$")


@dataclass(frozen=True)
class CommandSpec:
    command_id: str
    description: str
    image: str
    argv: tuple[str, ...]
    allowed_roles: tuple[str, ...]
    timeout_seconds: int = 8
    allowed_args: tuple[str, ...] = ()


COMMAND_REGISTRY: Mapping[str, CommandSpec] = MappingProxyType(
    {
        "system.health": CommandSpec(
            command_id="system.health",
            description="Show runner health without external network calls.",
            image="alpine:3.20",
            argv=("sh", "-c", "printf 'nova-runner=ok\\ntime=$(date -u +%FT%TZ)\\n'"),
            allowed_roles=("admin", "operator", "auditor"),
        ),
        "dns.config": CommandSpec(
            command_id="dns.config",
            description="Print resolver configuration inside the sandbox.",
            image="alpine:3.20",
            argv=("cat", "/etc/resolv.conf"),
            allowed_roles=("admin", "operator", "auditor"),
        ),
        "route.table": CommandSpec(
            command_id="route.table",
            description="Print the sandbox route table with network disabled.",
            image="alpine:3.20",
            argv=("ip", "route"),
            allowed_roles=("admin", "operator"),
        ),
        "echo.hash": CommandSpec(
            command_id="echo.hash",
            description="Hash a caller-provided label for trace correlation.",
            image="alpine:3.20",
            argv=("sha256sum",),
            allowed_roles=("admin", "operator", "auditor"),
            allowed_args=("label",),
        ),
    }
)


class CommandRegistryError(ValueError):
    pass


def stable_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _role_allowed(role: str, allowed_roles: tuple[str, ...]) -> bool:
    return any(ROLE_RANK.get(role, 0) >= ROLE_RANK[allowed] for allowed in allowed_roles)


def validate_command(command_id: str, args: dict[str, str], role: str) -> "CommandSpec | ToolSpec":
    spec: CommandSpec | ToolSpec | None = COMMAND_REGISTRY.get(command_id)
    if spec is None:
        spec = TOOL_REGISTRY.get(command_id)
    if spec is None:
        raise CommandRegistryError("Unknown command_id")
    if not _role_allowed(role, tuple(spec.allowed_roles)):
        raise CommandRegistryError("Role is not allowed to run this command")
    unexpected = sorted(set(args) - set(spec.allowed_args))
    if unexpected:
        raise CommandRegistryError(f"Unexpected argument(s): {', '.join(unexpected)}")
    validators = getattr(spec, "validators", {})
    for key, value in args.items():
        validator = validators.get(key)
        if validator is not None:
            try:
                validator(value)
            except ValueError as exc:
                raise CommandRegistryError(f"Invalid value for argument: {key}: {exc}") from exc
        elif not ARG_PATTERN.fullmatch(value):
            raise CommandRegistryError(f"Invalid value for argument: {key}")
    return spec


def _mock_output(spec: CommandSpec, args: dict[str, str]) -> tuple[int, str]:
    lines = [
        "NOVA SANDBOX MOCK",
        f"command_id={spec.command_id}",
        f"image={spec.image}",
        f"argv={' '.join(spec.argv)}",
        f"args_hash={stable_hash(args)}",
        f"timestamp={datetime.now(timezone.utc).isoformat()}",
    ]
    if "label" in args:
        lines.append(f"label_hash={hashlib.sha256(args['label'].encode()).hexdigest()}")
    return 0, "\n".join(lines) + "\n"


def _docker_output(spec: CommandSpec, args: dict[str, str]) -> tuple[int, str]:
    command = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--cpus",
        "0.25",
        "--memory",
        "64m",
        "--pids-limit",
        "64",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        spec.image,
        *spec.argv,
    ]
    if spec.command_id == "echo.hash":
        completed = subprocess.run(
            command,
            input=args.get("label", "").encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=spec.timeout_seconds,
            check=False,
        )
    else:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=spec.timeout_seconds,
            check=False,
        )
    return completed.returncode, completed.stdout.decode("utf-8", errors="replace")[:4096]


def _host_output(spec: ToolSpec, args: dict[str, str]) -> tuple[int, str]:
    argv = resolve_host_argv(spec, args)
    completed = subprocess.run(
        list(argv),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=spec.timeout_seconds,
        check=False,
    )
    return completed.returncode, completed.stdout.decode("utf-8", errors="replace")[:4096]


def execute_registered_command(command_id: str, args: dict[str, str], role: str) -> dict[str, object]:
    spec = validate_command(command_id, args, role)
    started_at = datetime.now(timezone.utc)
    try:
        if isinstance(spec, ToolSpec):
            if spec.kind == "builtin":
                exit_code, output = BUILTINS[spec.command_id](args)
            elif tool_available(spec):
                exit_code, output = _host_output(spec, args)
            else:
                exit_code, output = 127, f"NOVA TOOL MISSING: none of {', '.join(spec.host_binaries)} found on PATH\n"
        elif get_settings().sandbox_executor_mode == "docker":
            exit_code, output = _docker_output(spec, args)
        else:
            exit_code, output = _mock_output(spec, args)
    except subprocess.TimeoutExpired:
        exit_code, output = 124, "NOVA SANDBOX TIMEOUT\n"
    except (FileNotFoundError, ValueError) as exc:
        exit_code, output = 126, f"NOVA TOOL ERROR: {exc}\n"
    ended_at = datetime.now(timezone.utc)
    return {
        "command_id": command_id,
        "exit_code": exit_code,
        "output": output,
        "output_hash": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        "args_hash": stable_hash(args),
        "started_at": started_at,
        "ended_at": ended_at,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--health", action="store_true")
    parser.add_argument("--server", action="store_true")
    args = parser.parse_args()
    if args.health or args.server:
        print("nova-command-registry=ok")
        print(f"commands={','.join([*COMMAND_REGISTRY.keys(), *TOOL_REGISTRY.keys()])}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""LAU terminal client — drive the hosted agent from your shell.

Reads settings from the environment and (in order) NOVA_LAU_ENV,
~/.config/nova/lau.env, ./.nova/lau.env. Nothing here is ever sent anywhere
except the backend it is configured to reach.

  lau ask "scan open ports on 127.0.0.1"
  lau stream "how do I install nuclei on kali?"
  lau chat                     # interactive session
  lau devices                  # list devices registered on the server
  lau register --name "Perez's phone" --email p@example.com --phone +2567...
  lau owner                    # run the owner-confirmation ritual
  lau status                   # health + cloud research + owner state
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

DEFAULT_BASE = (
    os.environ.get("NOVA_BACKEND_URL")
    or os.environ.get("RENDER_EXTERNAL_URL")
    or "https://novagps.onrender.com"
)
USER_AGENT = "NovaGPS-CLI/1.0 (+https://novagps.onrender.com)"
DEFAULT_TIMEOUT = 60


class CliError(RuntimeError):
    pass


def _env_paths() -> list[Path]:
    paths = []
    explicit = os.environ.get("NOVA_LAU_ENV")
    if explicit:
        paths.append(Path(explicit).expanduser())
    paths.append(Path.home() / ".config" / "nova" / "lau.env")
    paths.append(Path.cwd() / ".nova" / "lau.env")
    return paths


def load_env_file(path: Path) -> dict:
    values = {}
    if not path.is_file():
        return values
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            values[key] = value
    return values


def settings() -> dict:
    merged: dict = {}
    for path in _env_paths():
        for key, value in load_env_file(path).items():
            merged.setdefault(key, value)
    merged.update({k: v for k, v in os.environ.items() if v})
    return {
        "base_url": (merged.get("NOVA_BACKEND_URL") or DEFAULT_BASE).rstrip("/"),
        "email": merged.get("NOVA_OWNER_EMAIL") or merged.get("OWNER_EMAIL") or "",
        "password": merged.get("NOVA_OWNER_PASSWORD") or merged.get("OWNER_PASSWORD") or "",
        "phrase": merged.get("NOVA_OWNER_PHRASE") or "",
        "token": merged.get("NOVA_TOKEN") or "",
        "timeout": int(merged.get("NOVA_CLI_TIMEOUT") or DEFAULT_TIMEOUT),
        "token_file": Path(
            merged.get("NOVA_TOKEN_FILE")
            or (Path.home() / ".config" / "nova" / "token.json")
        ).expanduser(),
    }


@contextlib.contextmanager
def _ipv4_only():
    """Some resolvers only answer A records; retry the call under AF_INET."""
    original = socket.getaddrinfo

    def patched(host, port, family=0, type=0, proto=0, flags=0):  # noqa: A002
        return original(host, port, socket.AF_INET, type, proto, flags)

    socket.getaddrinfo = patched
    try:
        yield
    finally:
        socket.getaddrinfo = original


def _open(req, timeout: int):
    try:
        return urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.URLError as exc:
        reason = str(getattr(exc, "reason", exc))
        if any(marker in reason for marker in (
            "Name or service not known", "Name does not resolve",
            "Temporary failure in name resolution", "nodename nor servname",
        )):
            with _ipv4_only():
                return urllib.request.urlopen(req, timeout=timeout)
        raise
    except socket.gaierror:
        with _ipv4_only():
            return urllib.request.urlopen(req, timeout=timeout)


def _request(
    cfg: dict,
    method: str,
    path: str,
    body: Optional[dict] = None,
    token: str = "",
    timeout: Optional[int] = None,
    raw: bool = False,
):
    url = path if path.startswith("http") else f"{cfg['base_url']}{path}"
    data = None
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        resp = _open(req, int(timeout or cfg["timeout"]))
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            payload = json.loads(exc.read(4096).decode("utf-8", "replace"))
            detail = payload.get("detail") or payload.get("message") or json.dumps(payload)
        except Exception:  # noqa: BLE001
            detail = f"HTTP {exc.code}"
        raise CliError(f"{method} {path} -> {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise CliError(f"{method} {path} unreachable: {exc.reason}") from exc
    if raw:
        return resp
    payload = resp.read().decode("utf-8", "replace")
    if not payload:
        return {}
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return {"raw": payload}


def _cache_token(path: Path, token: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"token": token, "saved_at": time.time()}))
        os.chmod(path, 0o600)
    except OSError:
        pass


def _cached_token(path: Path) -> str:
    try:
        data = json.loads(path.read_text())
        token = data.get("token") or ""
        if time.time() - float(data.get("saved_at") or 0) < 6 * 3600:
            return token
    except Exception:  # noqa: BLE001
        pass
    return ""


def login(cfg: dict) -> str:
    if not cfg["email"] or not cfg["password"]:
        raise CliError(
            "No credentials. Set NOVA_OWNER_EMAIL and NOVA_OWNER_PASSWORD in "
            f"one of: {', '.join(str(p) for p in _env_paths())}"
        )
    data = _request(
        cfg, "POST", "/auth/login",
        body={"email": cfg["email"], "password": cfg["password"]},
        timeout=min(cfg["timeout"], 45),
    )
    token = data.get("access_token") or data.get("token") or ""
    if not token:
        raise CliError(f"Login returned no token: {data}")
    _cache_token(cfg["token_file"], token)
    return token


def get_token(cfg: dict) -> str:
    if cfg["token"]:
        return cfg["token"]
    cached = _cached_token(cfg["token_file"])
    if cached:
        return cached
    return login(cfg)


def _token_or_login(cfg: dict, method: str, path: str, **kwargs) -> dict:
    token = get_token(cfg)
    try:
        return _request(cfg, method, path, token=token, **kwargs)
    except CliError as exc:
        if "401" not in str(exc):
            raise
        return _request(cfg, method, path, token=login(cfg), **kwargs)


# ---------------------------------------------------------------- commands ---

def cmd_login(cfg: dict, _args) -> int:
    token = login(cfg)
    head = token[:18] + "…" if token else ""
    print(f"logged in as {cfg['email']} · token cached at {cfg['token_file']} ({head})")
    return 0


def cmd_status(cfg: dict, _args) -> int:
    started = time.time()
    health = _request(cfg, "GET", "/health", timeout=max(cfg["timeout"], 70))
    print(f"backend   : {health} ({round(time.time() - started, 1)}s)")
    with contextlib.suppress(CliError):
        cloud = _token_or_login(cfg, "GET", "/nova-core/cloud/status")
        print(f"cloud     : {json.dumps(cloud)}")
    with contextlib.suppress(CliError):
        owner = _token_or_login(cfg, "GET", "/nova-core/owner/status")
        print(f"owner     : {json.dumps(owner)}")
    return 0


def cmd_devices(cfg: dict, _args) -> int:
    devices = _token_or_login(cfg, "GET", "/devices")
    if not isinstance(devices, list):
        print(json.dumps(devices, indent=2))
        return 1
    print(f"{len(devices)} device(s)")
    for d in devices:
        where = d.get("last_latitude") and f" {d['last_latitude']},{d.get('last_longitude')}" or ""
        print(
            f"  {str(d.get('id'))[:8]}  {d.get('name', '')}  "
            f"imei={d.get('imei') or '-'}  status={d.get('status', '?')}{where}"
        )
    return 0


def cmd_register(cfg: dict, args) -> int:
    body = {
        "name": args.name,
        "email": args.email,
        "phone": args.phone,
    }
    optional = {
        "identifier": args.identifier, "serial": args.serial, "imei": args.imei,
        "model": args.model, "manufacturer": args.manufacturer,
        "os_type": args.os_type, "os_version": args.os_version,
        "device_type": args.device_type, "ip_address": args.ip_address,
        "mac_address": args.mac_address, "consent_source": args.consent_source,
        "consent_scope": args.consent_scope,
    }
    body.update({k: v for k, v in optional.items() if v})
    device = _token_or_login(cfg, "POST", "/register", body=body, timeout=max(cfg["timeout"], 70))
    print(
        f"registered · id={device.get('id')} identifier={device.get('identifier')} "
        f"name={device.get('name')}"
    )
    print("The device now appears on the server; the agent can address it by id.")
    return 0


def _print_dispatch(payload: dict, verbose: bool) -> None:
    response = payload.get("response") or ""
    print(response)
    if verbose:
        for step in payload.get("thought_process") or []:
            print(f"  · {step}", file=sys.stderr)
        for src in payload.get("sources") or []:
            print(f"  ↳ {src.get('title', '')} — {src.get('url', '')}", file=sys.stderr)
        meta = {k: payload.get(k) for k in ("intent", "engine", "tools_executed") if payload.get(k)}
        if meta:
            print(f"  {json.dumps(meta)}", file=sys.stderr)


def cmd_ask(cfg: dict, args) -> int:
    body = {"command": args.text}
    if args.device_id:
        body["device_id"] = args.device_id
    payload = _token_or_login(cfg, "POST", "/nova-core/agent/dispatch", body=body)
    if args.json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        _print_dispatch(payload, args.verbose)
    return 0


def cmd_stream(cfg: dict, args) -> int:
    token = get_token(cfg)
    body = json.dumps({"command": args.text}).encode("utf-8")
    req = urllib.request.Request(
        f"{cfg['base_url']}/nova-core/agent/stream",
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
            "User-Agent": USER_AGENT,
        },
        method="POST",
    )
    try:
        resp = _open(req, max(cfg["timeout"], 90))
    except urllib.error.HTTPError as exc:
        if exc.code != 401:
            raise CliError(f"stream -> {exc.code}") from exc
        req.add_unredirected_header("Authorization", f"Bearer {login(cfg)}")
        resp = _open(req, max(cfg["timeout"], 90))

    event, data_lines = "", []
    try:
        for raw_line in resp:
            line = raw_line.decode("utf-8", "replace").rstrip("\n")
            if line.startswith("event:"):
                event = line[6:].strip()
            elif line.startswith("data:"):
                data_lines.append(line[5:].strip())
            elif not line:
                if event and data_lines:
                    _handle_sse(event, "\n".join(data_lines), args)
                event, data_lines = "", []
    finally:
        resp.close()
    if event and data_lines:
        _handle_sse(event, "\n".join(data_lines), args)
    print()
    return 0


def _handle_sse(event: str, data: str, args) -> None:
    try:
        payload = json.loads(data)
    except json.JSONDecodeError:
        return
    if event == "thought":
        print(f"  · {payload.get('text', '')}", file=sys.stderr)
    elif event == "tool":
        print(f"  ▸ tool: {payload.get('name', '')}", file=sys.stderr)
    elif event == "sources":
        for item in payload.get("items") or []:
            print(f"  ↳ {item.get('title', '')} — {item.get('url', '')}", file=sys.stderr)
    elif event == "token":
        print(payload.get("text", ""), end="", flush=True)
    elif event == "error":
        print(f"\n[error] {payload.get('message', '')}", file=sys.stderr)
    elif event == "done" and args.verbose:
        meta = {k: payload.get(k) for k in ("intent", "engine", "tools_executed") if payload.get(k)}
        print(f"\n  {json.dumps(meta)}", file=sys.stderr)


def cmd_owner(cfg: dict, args) -> int:
    """Walk the owner ritual from the terminal."""
    claim = f"I am {args.name}"
    _print_dispatch(_token_or_login(
        cfg, "POST", "/nova-core/agent/dispatch", body={"command": claim}
    ), args.verbose)
    if not sys.stdin.isatty():
        print("(non-interactive: say the rest through 'lau ask')", file=sys.stderr)
        return 0
    while True:
        try:
            reply = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if reply.lower() in {"exit", "quit"}:
            return 0
        payload = _token_or_login(
            cfg, "POST", "/nova-core/agent/dispatch", body={"command": reply}
        )
        _print_dispatch(payload, args.verbose)
        if (payload.get("owner") or {}).get("verified"):
            return 0


def cmd_skills(cfg: dict, _args) -> int:
    data = _token_or_login(cfg, "GET", "/nova-core/skills")
    skills = data if isinstance(data, list) else data.get("skills") or []
    ready = 0
    for s in skills:
        ok = bool(s.get("ready") or s.get("available"))
        ready += ok
        mark = "YES" if ok else "no "
        print(f"  [{mark}] {s.get('name', '?')} — {s.get('category', '')}")
    print(f"{ready}/{len(skills)} skills ready")
    return 0


def cmd_chat(cfg: dict, args) -> int:
    print(f"LAU chat · {cfg['base_url']} · ctrl-c or 'exit' to leave")
    while True:
        try:
            line = input("lau> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not line:
            continue
        if line.lower() in {"exit", "quit"}:
            return 0
        try:
            payload = _token_or_login(
                cfg, "POST", "/nova-core/agent/dispatch",
                body={"command": line},
            )
        except CliError as exc:
            print(f"[error] {exc}", file=sys.stderr)
            continue
        _print_dispatch(payload, args.verbose)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lau", description="Terminal client for the hosted NOVARA agent."
    )
    parser.add_argument("--base-url", help="backend base URL (default: NOVA_BACKEND_URL)")
    parser.add_argument("--json", action="store_true", help="raw JSON output")
    parser.add_argument("-v", "--verbose", action="store_true", help="show thoughts, tools, sources")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("ask", help="send one command and print the answer")
    p.add_argument("text", help="the command")
    p.add_argument("--device-id", default="")
    p.set_defaults(func=cmd_ask)

    p = sub.add_parser("stream", help="same as ask, but tokens arrive live")
    p.add_argument("text")
    p.set_defaults(func=cmd_stream)

    p = sub.add_parser("chat", help="interactive session")
    p.set_defaults(func=cmd_chat)

    p = sub.add_parser("devices", help="list devices registered on the server")
    p.set_defaults(func=cmd_devices)

    p = sub.add_parser("register", help="register a device (writes to the server)")
    p.add_argument("--name", required=True)
    p.add_argument("--email", required=True)
    p.add_argument("--phone", required=True)
    p.add_argument("--identifier")
    p.add_argument("--serial")
    p.add_argument("--imei")
    p.add_argument("--model")
    p.add_argument("--manufacturer")
    p.add_argument("--os-type")
    p.add_argument("--os-version")
    p.add_argument("--device-type", default="other")
    p.add_argument("--ip-address")
    p.add_argument("--mac-address")
    p.add_argument("--consent-source", default="terminal")
    p.add_argument("--consent-scope", default="location,tracking")
    p.set_defaults(func=cmd_register)

    p = sub.add_parser("owner", help="run the owner-confirmation ritual")
    p.add_argument("--name", default="Perez")
    p.set_defaults(func=cmd_owner)

    p = sub.add_parser("skills", help="list agent skills and readiness")
    p.set_defaults(func=cmd_skills)

    p = sub.add_parser("status", help="backend health, cloud research, owner state")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("login", help="exchange credentials for a cached token")
    p.set_defaults(func=cmd_login)
    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg = settings()
    if args.base_url:
        cfg["base_url"] = args.base_url.rstrip("/")
    try:
        return args.func(cfg, args)
    except CliError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print()
        return 130


if __name__ == "__main__":
    sys.exit(main())

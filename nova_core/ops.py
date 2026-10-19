"""LAU recovery-ops CLI.

The terminal half of the queen interface. These commands talk to the running
NOVA backend so an operator can run the whole stolen-device lane from a shell:
register a watch, stream sightings, pull the evidence trail and hand the police
a true 15-digit IMEI.

Auth is taken from NOVA_TOKEN if present, otherwise a login is performed with
NOVA_OWNER_EMAIL / NOVA_OWNER_PASSWORD. No credentials are ever hard-coded.
"""

from __future__ import annotations

import os
import sys
import time

import httpx

from .config import get_config

GREEN = "\033[32m"
GREY = "\033[90m"
RED = "\033[31m"
CYAN = "\033[36m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _c(text: str, color: str, bold: bool = False) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{BOLD if bold else ''}{color}{text}{RESET}"


def _luhn_check_digit(digits: str) -> int:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 0:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return (10 - (total % 10)) % 10


def normalize_imei(value: str) -> tuple[str | None, str | None, bool]:
    """Return (15-digit IMEI, 16-digit IMEISV or None, check-digit valid)."""
    digits = "".join(ch for ch in (value or "") if ch.isdigit())
    if len(digits) == 16:
        imei, imeisv = digits[:15], digits
    elif len(digits) == 15:
        imei, imeisv = digits, None
    else:
        return None, None, False
    valid = _luhn_check_digit(imei[:14]) == int(imei[14])
    return imei, imeisv, valid


def _login(client: httpx.Client, cfg) -> str:
    if cfg.backend_token:
        return cfg.backend_token
    email = os.environ.get("NOVA_OWNER_EMAIL", "")
    password = os.environ.get("NOVA_OWNER_PASSWORD", "")
    if not email or not password:
        print(_c("Set NOVA_OWNER_EMAIL and NOVA_OWNER_PASSWORD (or NOVA_TOKEN) first.", RED))
        raise SystemExit(2)
    response = client.post("/auth/login", json={"email": email, "password": password})
    if response.status_code != 200:
        print(_c(f"Login failed: {response.status_code} {response.text[:200]}", RED))
        raise SystemExit(1)
    return response.json()["access_token"]


def _client(cfg) -> tuple[httpx.Client, dict]:
    client = httpx.Client(base_url=cfg.backend_url.rstrip("/"), timeout=30)
    token = _login(client, cfg)
    return client, {"Authorization": f"Bearer {token}"}


def _find_entry(entries: list[dict], needle: str) -> dict | None:
    target = needle.strip()
    digits = "".join(ch for ch in target if ch.isdigit())
    for entry in entries:
        if target and entry.get("id") == target:
            return entry
        for field in ("imei", "imeisv", "phone", "email", "label"):
            value = entry.get(field)
            if not value:
                continue
            if value == target:
                return entry
            if digits and len(digits) >= 9 and digits[-9:] == str(value)[-9:]:
                return entry
            if target.lower() in str(value).lower():
                return entry
    return None


def _playbook(entry: dict) -> list[str]:
    imei = entry.get("imei") or "(no IMEI on file)"
    phone = entry.get("phone") or "(no phone)"
    return [
        f"1. Google Find My Device  ->  https://android.com/find   (sign in as {entry.get('email') or 'the owner'})",
        "2. Samsung Find My Mobile ->  https://findmymobile.samsung.com   (if Samsung account linked)",
        f"3. Police report  ->  quote true IMEI {imei} and phone {phone}; request an MTN line/IMEI trace.",
        "4. Uganda: UCC / NITA-U can request the carrier blacklist the IMEI at the EIR once police file exists.",
        "5. Rotate any passwords the phone could unlock (email, banking, the Nova owner account).",
        "6. Do NOT confront the finder directly; hand the trail below to the investigator.",
    ]


def watch_add(argv: list[str]) -> int:
    cfg = get_config()
    if not argv:
        print("usage: lau watch add <imei|16-digit-imeisv> [--phone +256...] [--email x@y] [--label name]")
        return 2
    imei = argv[0]
    params: dict[str, str] = {"imei": imei}
    rest = argv[1:]
    index = 0
    while index < len(rest):
        flag = rest[index]
        value = rest[index + 1] if index + 1 < len(rest) else ""
        if flag in ("--phone", "-p"):
            params["phone"] = value
        elif flag in ("--email", "-e"):
            params["email"] = value
        elif flag in ("--label", "-l"):
            params["label"] = value
        elif flag in ("--notes", "-n"):
            params["notes"] = value
        index += 2
    client, headers = _client(cfg)
    response = client.post("/watchlist", params=params, headers=headers)
    if response.status_code != 201:
        print(_c(f"Watch add failed: {response.status_code} {response.text[:200]}", RED))
        return 1
    entry = response.json()
    print(_c("WATCH REGISTERED", GREEN, True))
    print(f"  id        {entry['watchlist_id']}")
    print(f"  imei      {entry['imei']}  (input {entry['imei_input']}, luhn_ok={entry['imei_luhn_valid']})")
    if entry.get("imeisv"):
        print(f"  imeisv    {entry['imeisv']}")
    print(f"  phone     {entry.get('phone') or '-'}   carrier {entry.get('carrier') or '-'}")
    print(f"  model     {entry.get('manufacturer') or '-'} {entry.get('model') or ''}")
    print(_c("  The watch fires the moment this device reports a fix.", GREY))
    return 0


def watch_list(argv: list[str]) -> int:
    cfg = get_config()
    client, headers = _client(cfg)
    entries = client.get("/watchlist", headers=headers).json()
    if not entries:
        print(_c("Watchlist is empty.", GREY))
        return 0
    print(_c(f"WATCHLIST ({len(entries)})", GREEN, True))
    for entry in entries:
        marker = {"watching": "o", "sighted": "!", "recovered": "x"}.get(entry["status"], "?")
        print(f"  [{marker}] {entry['id'][:8]}  {entry['label']:<24} {entry.get('imei') or '-':<16} "
              f"{entry.get('phone') or '-':<14} {entry['status']}")
    return 0


def watch_recover(argv: list[str]) -> int:
    cfg = get_config()
    if not argv:
        print("usage: lau watch recover <watch_id>")
        return 2
    client, headers = _client(cfg)
    response = client.post(f"/watchlist/{argv[0]}/recover", headers=headers)
    if response.status_code != 200:
        print(_c(f"Recover failed: {response.status_code} {response.text[:200]}", RED))
        return 1
    print(_c(f"Marked recovered: {argv[0]}", GREEN, True))
    return 0


def theft(argv: list[str]) -> int:
    cfg = get_config()
    if not argv:
        print("usage: lau theft <imei|phone|watch_id|label>")
        return 2
    needle = argv[0]
    client, headers = _client(cfg)
    entries = client.get("/watchlist", headers=headers).json()
    entry = _find_entry(entries, needle)
    if not entry:
        normalized, _, valid = normalize_imei(needle)
        if normalized:
            print(_c(f"No watch entry found for {needle} (true IMEI {normalized}, luhn_ok={valid}).", RED))
            print(f"Register it first:  lau watch add {needle} --phone ... --email ...")
        else:
            print(_c(f"No watch entry matched '{needle}'.", RED))
        return 1

    watch_id = entry["id"]
    print(_c("RECOVERY CASE", GREEN, True))
    print(f"  label   {entry['label']}")
    print(f"  imei    {entry.get('imei') or '-'}    phone {entry.get('phone') or '-'}")
    print(f"  status  {entry['status']}")
    trail = client.get(f"/watchlist/{watch_id}/sightings", headers=headers).json()
    sightings = trail.get("sightings", [])
    if sightings:
        print(_c(f"  sightings  ({len(sightings)} fix{'es' if len(sightings) != 1 else ''})", CYAN, True))
        for fix in sightings[:10]:
            when = fix.get("recorded_at", "")[:19].replace("T", " ")
            place = fix.get("place_name") or f"{fix['latitude']:.5f},{fix['longitude']:.5f}"
            print(f"    {when}  {place}  [{fix.get('source')}]")
    else:
        print(_c("  sightings  none yet — the reporting client has not pinged.", GREY))
    alerts = trail.get("alerts", [])
    if alerts:
        print(_c(f"  alerts ({len(alerts)})", CYAN, True))
        for alert in alerts[:5]:
            print(f"    {alert['created_at'][:19]}  {alert['message'][:90]}")
    print(_c("  next steps", GREEN, True))
    for line in _playbook(entry):
        print(f"    {line}")
    return 0


def radar(argv: list[str]) -> int:
    cfg = get_config()
    interval = int(os.environ.get("NOVA_RADAR_INTERVAL", "10"))
    client, headers = _client(cfg)
    print(_c(f"LAU RADAR — polling {cfg.backend_url} every {interval}s (Ctrl+C to stop)", GREEN, True))
    try:
        while True:
            health = client.get("/devices/health", headers=headers).json()
            watched = [d for d in health.get("devices", []) if d.get("watchlisted")]
            stale = [d for d in health.get("devices", []) if d.get("stale")]
            stamp = time.strftime("%H:%M:%S")
            line = f"[{stamp}] devices={health.get('count', 0)} watched={len(watched)} quiet={len(stale)}"
            print(_c(line, CYAN if not watched else GREEN, True))
            for device in watched:
                age = device.get("age_seconds")
                print(f"    WATCHED {device['name'][:24]:<24} last_seen={age if age is not None else 'never'}s ago")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nradar stopped.")
    return 0


def skills_list(argv: list[str]) -> int:
    try:
        from .skills import list_skills
    except Exception as exc:  # pragma: no cover - defensive
        print(_c(f"Skills registry unavailable: {exc}", RED))
        return 1
    skills = list_skills()
    if not skills:
        print(_c("No skills registered.", GREY))
        return 0
    print(_c(f"LAU SKILLS ({len(skills)})", GREEN, True))
    for skill in skills:
        state = _c("ready", GREEN) if skill.get("available") else _c("missing", GREY)
        print(f"  {skill['name']:<14} [{skill.get('priority', '-'):<2}] {state}  {skill.get('purpose', '')}")
        if not skill.get("available") and skill.get("install"):
            print(f"      install: {skill['install']}")
    return 0


def skill_run(argv: list[str]) -> int:
    try:
        from .skills import SkillRefused, get_skill, run_skill
    except Exception as exc:  # pragma: no cover - defensive
        print(_c(f"Skills registry unavailable: {exc}", RED))
        return 1
    if not argv:
        print("usage: lau skill <name> [target] [-- args...]")
        return 2
    key = argv[0]
    rest = argv[1:]
    extra: list[str] = []
    target = None
    if "--" in rest:
        split = rest.index("--")
        target = rest[0] if split > 0 else None
        extra = rest[split + 1:]
    elif rest:
        target = rest[0]
    skill = get_skill(key)
    if skill is None:
        print(_c(f"Unknown skill '{key}'. Run `lau skills` to list.", RED))
        return 1
    try:
        result = run_skill(key, target=target, args=extra)
    except SkillRefused as exc:
        print(_c(str(exc), RED))
        return 3
    status = result.get("status")
    if status == "missing":
        print(_c(f"{skill.name} is not installed.", RED))
        print(f"  install: {result.get('install')}")
        return 1
    print(_c(f"{skill.name} -> {status}", GREEN if status == "ok" else RED, True))
    print(f"  cmd: {' '.join(str(part) for part in result.get('command', []))}")
    if result.get("stdout"):
        print(result["stdout"].rstrip())
    if result.get("stderr"):
        print(_c(result["stderr"].rstrip(), GREY))
    return 0 if status == "ok" else 1


COMMANDS = {
    "watch": {
        "add": watch_add,
        "list": watch_list,
        "recover": watch_recover,
        "radar": radar,
    },
    "theft": theft,
    "radar": radar,
    "skills": skills_list,
    "skill": skill_run,
}


def run_ops(argv: list[str]) -> int:
    """Dispatch `lau <command> ...`. Returns a process exit code."""
    command = argv[0]
    handler = COMMANDS.get(command)
    if handler is None:
        return 2
    if isinstance(handler, dict):
        action = argv[1] if len(argv) > 1 else "list"
        func = handler.get(action)
        if func is None:
            print(f"usage: lau {command} {{{'|'.join(handler)}}}")
            return 2
        return func(argv[2:])
    return handler(argv[1:])

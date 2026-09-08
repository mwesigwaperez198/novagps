#!/usr/bin/env python3
"""nova_flash_android — the USB-stick flash engine for Android targets.

This is the .bat/.exe behaviour behind the scenes: it talks to a phone
over ADB (bundled under ./platform-tools on the stick) and provisions a
NOVA agent from a .nova payload.

Realistic flow (exactly what a phone-repair bench tool does — no magic):
  1. detect the connected device via `adb devices`
  2. if the bootstrap agent is not installed, `adb install` it once
  3. `adb push <device>.nova` to /sdcard/Download/
  4. `adb shell am start` the agent's ImportActivity with the file path —
     the agent re-verifies the NOVA signature + its own device key and
     attaches, then hides itself if it becomes device owner
  5. optional: `dpm set-device-owner` for the hidden/system-level attach
     (requires a fresh device without accounts)

Windows package: run flash.bat (double-click), flash.ps1, or the compiled
flash.exe. Everything else on this tool runs anywhere Python 3.9+ runs.

Exit codes: 0 ok, 1 none/shown, 2 failure.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

BOOTSTRAP_APK = "bootstrap-agent.apk"       # com.novara.agent debug/release build
AGENT_PACKAGE = "com.novara.agent"
IMPORT_ACTIVITY = "com.novara.agent/.ImportActivity"
REMOTE_FILE = "/sdcard/Download/nova-payload.nova"


class Adb:
    def __init__(self, adb_bin: str):
        self.bin = adb_bin

    def run(self, *args: str, check: bool = True) -> str:
        result = subprocess.run(
            [self.bin, *args], capture_output=True, text=True, timeout=120,
        )
        if check and result.returncode != 0:
            raise RuntimeError(f"adb {' '.join(args)} failed: {result.stderr.strip()}")
        return result.stdout


def find_adb() -> str:
    bundled = Path(__file__).resolve().parent.parent / "platform-tools" / "adb"
    if sys.platform.startswith("win"):
        bundled = bundled.with_suffix(".exe")
    return str(bundled) if Path(bundled).exists() else shutil.which("adb") or ""


def wait_for_device(adb: Adb, seconds: int = 30) -> bool:
    print("waiting for a device on USB… (enable USB debugging on the phone)")
    deadline = time.time() + seconds
    while time.time() < deadline:
        out = adb.run("devices", check=False)
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                print(f"connected: {parts[0]}")
                return True
        time.sleep(2)
    return False


def is_installed(adb: Adb) -> bool:
    out = adb.run("shell", "pm", "path", AGENT_PACKAGE, check=False)
    return "package:" in out


def push_and_import(adb: Adb, payload: Path) -> None:
    adb.run("push", str(payload), REMOTE_FILE)
    cmd = ["shell", "am", "start", "-n", IMPORT_ACTIVITY, "--es", "file", REMOTE_FILE]
    adb.run(*cmd)
    print("ImportActivity launched; it will verify signature + device key.")


def make_device_owner(adb: Adb) -> None:
    adb.run("shell", "dpm", "set-device-owner", f"{AGENT_PACKAGE}/.bootstrap.DeviceOwnerAdmin")
    print("device owner granted (icon hidden, boots with phone, cannot be uninstalled)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--payload", required=True, help="the .nova file to flash")
    parser.add_argument("--adb", default="", help="path to adb (default: bundled ./platform-tools)")
    parser.add_argument("--bootstrap", default="", help="bootstrap agent APK to install on first contact")
    parser.add_argument("--owner", action="store_true", help="grant device-owner after import (hidden attach)")
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args(argv)

    adb_bin = args.adb or find_adb()
    if not adb_bin:
        print("error: adb not found. Keep platform-tools/ next to this tool.", file=sys.stderr)
        return 2
    adb = Adb(adb_bin)

    if not Path(args.payload).is_file():
        print(f"error: payload not found: {args.payload}", file=sys.stderr)
        return 2
    if not wait_for_device(adb, args.timeout):
        print("error: no device detected. Check cable + USB debugging.", file=sys.stderr)
        return 1

    if not is_installed(adb):
        bootstrap = Path(args.bootstrap)
        if not bootstrap.is_file():
            print("error: agent is not installed and no --bootstrap APK was provided.", file=sys.stderr)
            return 2
        print("installing bootstrap agent once…")
        adb.run("install", "-r", "-t", str(bootstrap))
    else:
        print("agent already installed")

    push_and_import(adb, Path(args.payload))

    if args.owner:
        print("now provisioning device owner…")
        make_device_owner(adb)

    print("done. Verify the device appears LIVE on the NOVA dashboard.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
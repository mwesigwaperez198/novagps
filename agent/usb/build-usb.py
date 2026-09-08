#!/usr/bin/env python3
"""build-usb — assembles the NOVA flash-stick image.

Run from anywhere with Python 3.9+ and the `cryptography` package:

    python build-usb.py --device-pub deviceA.pub --apk bootstrap/app-debug.apk \
                        --nova-key nova.key --payload-out payloads/deviceA.nova

Flags:
    --keep-adb      leave platform-tools as-is (skips the SDK-download hint)
    --os/android    target (fixed to android for now)

It packs the .nova for the target device, collects adb, and prints the
final stick layout + the exact commands to run.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent / "tools"
REPO = TOOLS.parent
USB = REPO / "usb"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--device-pub", required=True, help="X25519 public key of the target phone")
    parser.add_argument("--apk", required=True, help="path to the built bootstrap agent APK")
    parser.add_argument("--nova-key", required=True, help="NOVA Ed25519 private key")
    parser.add_argument("--payload-out", default=str(USB / "payloads" / "device.nova"))
    parser.add_argument("--arch", default="arm64")
    parser.add_argument("--name", default="nova-agent.apk")
    parser.add_argument("--owner", action="store_true", help="mark the payload for device-owner attach")
    args = parser.parse_args()

    # 1) pack the encrypted payload for this exact device
    pack_args = [
        sys.executable, str(TOOLS / "nova_pack.py"), "pack",
        "-i", args.apk, "-o", args.payload_out,
        "--key", args.nova_key, "--device-pub", args.device_pub,
        "--os", "android", "--arch", args.arch, "--name", args.name,
    ]
    if args.owner:
        pack_args += ["--attach", "device_owner", "--requires-root"]
    result = subprocess.run(pack_args, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        return result.returncode
    print(result.stdout)

    # 2) assemble the stick layout
    (USB / "bootstrap").mkdir(parents=True, exist_ok=True)
    (USB / "payloads").mkdir(parents=True, exist_ok=True)
    shutil.copy2(args.apk, USB / "bootstrap" / "bootstrap-agent.apk")
    shutil.copy2(args.device_pub, USB / "payloads" / "device.pub")

    print("""
Flash-stick layout (copy USB\\ :).
    USB\\
    ├── flash.bat          <- double-click this (or flash.ps1 as admin-capable)
    ├── flash.ps1
    ├── platform-tools\\    <- adb.exe + Archlinux DLLs (google platform-tools ZIP)
    ├── bootstrap\\bootstrap-agent.apk
    └── payloads\\device.nova   <- encrypted, this phone ONLY

Push command used by the scripts:
    adb shell am start -n com.novara.agent/.ImportActivity \\
         --es file /sdcard/Download/nova-payload.nova
""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
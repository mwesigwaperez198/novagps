#!/usr/bin/env python3
"""End-to-end tests for the .nova payload toolchain.

Run:  python3 test_nova_pack.py
All exit codes must be zero; the README treats this as the gate before a
release or a format change.
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TOOL = Path(__file__).resolve().parent / "nova_pack.py"


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(TOOL), *args], capture_output=True, text=True)


def expect(name: str, ok: bool, detail: str) -> None:
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    if not ok:
        print(f"       {detail}", file=sys.stderr)
        sys.exit(1)


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="nova_test_"))
    artifact = tmp / "app-debug.apk"
    artifact.write_bytes(b"MOCK-APK" * 64)

    expect("keygen: NOVA identity", run("keygen", str(tmp / "nova.key")).returncode == 0, "keygen failed")
    expect("device-keygen: A", run("device-keygen", str(tmp / "devA.key")).returncode == 0, "devA keygen failed")
    expect("device-keygen: B", run("device-keygen", str(tmp / "devB.key")).returncode == 0, "devB keygen failed")

    packed = tmp / "devA.nova"
    pack = run(
        "pack", "-i", str(artifact), "-o", str(packed),
        "--key", str(tmp / "nova.key"), "--device-pub", str(tmp / "devA.pub"),
        "--os", "android", "--arch", "arm64", "--name", "nova-agent.apk",
        "--attach", "device_owner", "--requires-root",
    )
    expect("pack succeeds", pack.returncode == 0, pack.stderr)
    expect("payload starts with magic", packed.read_bytes()[:4] == b"NOVA", "magic missing")

    opening = tmp / "open"
    unpack = run(
        "unpack", "-p", str(packed),
        "--key", str(tmp / "devA.key"), "--verify", str(tmp / "nova.pub"),
        "-o", str(opening),
    )
    expect("devA unlocks payload", unpack.returncode == 0, unpack.stderr)
    expect("artifact byte-identical", (opening / "nova-agent.apk").read_bytes() == artifact.read_bytes(),
           "decrypted bytes differ")

    blocked = run(
        "unpack", "-p", str(packed),
        "--key", str(tmp / "devB.key"), "--verify", str(tmp / "nova.pub"), "-o", str(tmp / "openB"),
    )
    expect("devB is refused (wrong device)", blocked.returncode == 1 and "cannot open" in blocked.stderr,
           blocked.stderr)

    tampered = tmp / "tampered.nova"
    raw = bytearray(packed.read_bytes())
    raw[350] ^= 0xFF
    tampered.write_bytes(bytes(raw))
    tampered_case = run(
        "unpack", "-p", str(tampered),
        "--key", str(tmp / "devA.key"), "--verify", str(tmp / "nova.pub"), "-o", str(tmp / "openC"),
    )
    expect("tampered payload is refused", tampered_case.returncode == 1, tampered_case.stderr)

    forged = tmp / "evil.nova"
    run("keygen", str(tmp / "evil.key"))
    run(
        "pack", "-i", str(artifact), "-o", str(forged),
        "--key", str(tmp / "evil.key"), "--device-pub", str(tmp / "devA.pub"),
        "--os", "android", "--arch", "arm64", "--name", "evil.apk",
    )
    forged_case = run(
        "unpack", "-p", str(forged),
        "--key", str(tmp / "devA.key"), "--verify", str(tmp / "nova.pub"), "-o", str(tmp / "openD"),
    )
    expect("unsigned (non-NOVA) payload is refused", forged_case.returncode == 1, forged_case.stderr)

    inspect = run("inspect", "-p", str(packed), "--key", str(tmp / "nova.pub"))
    expect("inspect shows clean header metadata",
           "android" in inspect.stdout and "arm64" in inspect.stdout and "VALID (NOVA-signed)" in inspect.stdout,
           inspect.stdout)

    shutil.rmtree(tmp, ignore_errors=True)
    print("\nall nova-payload tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
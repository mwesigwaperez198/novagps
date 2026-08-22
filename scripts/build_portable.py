#!/usr/bin/env python3
"""Assemble the NOVA portable USB layout.

Produces a self-contained folder (build/nova-portable) that runs NOVA on any
x86_64/aarch64 Windows/Linux/macOS machine with zero installation:

    nova-portable/
      start_nova.bat|.sh|.command     launchers (detect OS/arch)
      doctor.bat|.sh                  self-test + tool probe
      app/backend                     backend code
      app/frontend/dist               prebuilt dashboard (offline, no Node)
      runtime/<os>-<arch>/python      bundled CPython (python-build-standalone)
      secure/README_ENCRYPTION.txt    VeraCrypt at-rest instructions
      data/                           created on first unencrypted run

The build machine needs internet ONCE (runtime + wheel downloads). The
resulting stick is fully offline afterwards.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PBS_RELEASE = os.environ.get("PBS_RELEASE", "20241016")
PBS_PYTHON = os.environ.get("PBS_PYTHON", "3.12.7")

# target -> (pbs asset filename template, pip --platform tags, abi)
TARGETS: dict[str, dict] = {
    "windows-x86_64": {
        "asset": f"cpython-{PBS_PYTHON}+{PBS_RELEASE}-x86_64-pc-windows-msvc-shared-install_only.tar.gz",
        "pip_platform": ["win_amd64"],
        "abi": "cp312",
        "so_ext": ".pyd",
    },
    "linux-x86_64": {
        "asset": f"cpython-{PBS_PYTHON}+{PBS_RELEASE}-x86_64-unknown-linux-gnu-install_only.tar.gz",
        "pip_platform": ["manylinux_2_28_x86_64", "manylinux2014_x86_64"],
        "abi": "cp312",
        "so_ext": ".so",
    },
    "linux-aarch64": {
        "asset": f"cpython-{PBS_PYTHON}+{PBS_RELEASE}-aarch64-unknown-linux-gnu-install_only.tar.gz",
        "pip_platform": ["manylinux_2_28_aarch64", "manylinux2014_aarch64"],
        "abi": "cp312",
        "so_ext": ".so",
    },
    "macos-aarch64": {
        "asset": f"cpython-{PBS_PYTHON}+{PBS_RELEASE}-aarch64-apple-darwin-install_only.tar.gz",
        "pip_platform": ["macosx_11_0_arm64"],
        "abi": "cp312",
        "so_ext": ".so",
    },
    "macos-x86_64": {
        "asset": f"cpython-{PBS_PYTHON}+{PBS_RELEASE}-x86_64-apple-darwin-install_only.tar.gz",
        "pip_platform": ["macosx_10_9_x86_64"],
        "abi": "cp312",
        "so_ext": ".so",
    },
}

HOST_OS = {"windows": "windows", "linux": "linux", "darwin": "macos"}[sys.platform]
HOST_ARCH = {"AMD64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64"}[
    os.uname().machine if hasattr(os, "uname") else os.environ.get("PROCESSOR_ARCHITEW6432", "AMD64")
]

BACKEND_EXCLUDE_DIRS = {".venv", "__pycache__", "tests", ".pytest_cache", ".ruff_cache"}
PORTABLE_FILES = [
    "start_nova.bat",
    "start_nova.sh",
    "start_nova.command",
    "stop_nova.bat",
    "stop_nova.sh",
    "doctor.bat",
    "doctor.sh",
]


def log(message: str) -> None:
    print(f"[build-portable] {message}", flush=True)


def host_target() -> str:
    return f"{HOST_OS}-{HOST_ARCH}"


def download(url: str, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and destination.stat().st_size > 0:
        log(f"cached: {destination.name}")
        return destination
    log(f"downloading {url}")
    with urllib.request.urlopen(url, timeout=120) as response, open(destination, "wb") as handle:
        shutil.copyfileobj(response, handle)
    return destination


def fetch_runtime(target: str, cache_dir: Path) -> Path:
    info = TARGETS[target]
    url = (
        "https://github.com/astral-sh/python-build-standalone/releases/download/"
        f"{PBS_RELEASE}/{info['asset']}"
    )
    return download(url, cache_dir / info["asset"])


def extract_runtime(archive: Path, runtime_dir: Path) -> None:
    runtime_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:gz") as tar:
        tar.extractall(runtime_dir)


def vendor_wheels(target: str, requirements: Path, site_packages: Path) -> None:
    info = TARGETS[target]
    wheels_dir = site_packages.parent.parent / "_wheels"
    wheels_dir.mkdir(parents=True, exist_ok=True)

    command = [
        sys.executable,
        "-m",
        "pip",
        "download",
        "-r",
        str(requirements),
        "-d",
        str(wheels_dir),
        "--only-binary=:all:",
        "--implementation",
        "cp",
        "--python-version",
        "3.12",
        "--abi",
        info["abi"],
    ]
    for platform_tag in info["pip_platform"]:
        command.extend(["--platform", platform_tag])
    log(f"vendoring wheels for {target}")
    subprocess.run(command, check=True)

    site_packages.mkdir(parents=True, exist_ok=True)
    for wheel in sorted(wheels_dir.glob("*.whl")):
        with zipfile.ZipFile(wheel) as archive:
            archive.extractall(site_packages)
    if os.name != "nt" and info["so_ext"] == ".so":
        for shared_object in site_packages.rglob("*.so"):
            shared_object.chmod(shared_object.stat().st_mode | stat.S_IRUSR | stat.S_IXUSR)
    shutil.rmtree(wheels_dir, ignore_errors=True)


def copy_backend(destination: Path) -> None:
    source = REPO_ROOT / "backend"
    for item in source.iterdir():
        if item.name in BACKEND_EXCLUDE_DIRS or item.suffix == ".pyc":
            continue
        if item.is_dir():
            shutil.copytree(item, destination / item.name, dirs_exist_ok=True)
        else:
            shutil.copy2(item, destination / item.name)
    for stale in destination.rglob("__pycache__"):
        shutil.rmtree(stale, ignore_errors=True)


def build_frontend(frontend_dir: Path) -> Path:
    dist = frontend_dir / "dist"
    npm = shutil.which("npm") or shutil.which("npm.cmd")
    if npm and not dist.is_dir():
        log("building frontend with npm (one-time)")
        for argv in ([npm, "install"], [npm, "run", "build"]):
            subprocess.run(argv, cwd=str(frontend_dir), check=True)
    elif not dist.is_dir():
        raise SystemExit(
            "frontend/dist missing and npm unavailable - build the frontend first "
            "(cd frontend && npm install && npm run build)"
        )
    return dist


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--targets",
        default="host",
        help="comma list of targets or 'host' or 'all'. "
        f"choices: {', '.join(TARGETS)}",
    )
    parser.add_argument("--out", default=str(REPO_ROOT / "build" / "nova-portable"))
    parser.add_argument("--reqs", default=str(REPO_ROOT / "portable" / "requirements-portable.txt"))
    parser.add_argument(
        "--frontend",
        choices=["auto", "skip"],
        default="auto",
        help="'auto' builds dist with npm if missing; 'skip' requires existing dist",
    )
    arguments = parser.parse_args()

    if arguments.targets == "host":
        targets = [host_target()]
    elif arguments.targets == "all":
        targets = list(TARGETS)
    else:
        targets = [item.strip() for item in arguments.targets.split(",") if item.strip()]
    unknown = [item for item in targets if item not in TARGETS]
    if unknown:
        parser.error(f"unknown targets: {', '.join(unknown)}")

    out = Path(arguments.out)
    requirements = Path(arguments.reqs)
    if out.exists():
        log(f"clearing previous layout {out}")
        shutil.rmtree(out, ignore_errors=True)
    (out / "app").mkdir(parents=True, exist_ok=True)
    cache = REPO_ROOT / "build" / "_cache"
    cache.mkdir(parents=True, exist_ok=True)

    log(f"targets={','.join(targets)} out={out}")

    copy_backend(out / "app" / "backend")
    shutil.copy2(REPO_ROOT / "portable" / "doctor_tools.py", out / "app" / "backend" / "doctor_tools.py")

    frontend_dist = build_frontend(REPO_ROOT / "frontend")
    shutil.copytree(frontend_dist, out / "app" / "frontend" / "dist", dirs_exist_ok=True)

    for filename in PORTABLE_FILES:
        source = REPO_ROOT / "portable" / filename
        shutil.copy2(source, out / filename)
        if filename.endswith(".sh") or filename.endswith(".command"):
            target_file = out / filename
            target_file.chmod(target_file.stat().st_mode | stat.S_IXUSR)

    (out / "secure").mkdir(exist_ok=True)
    shutil.copy2(REPO_ROOT / "portable" / "README_ENCRYPTION.txt", out / "secure")
    (out / "data").mkdir(exist_ok=True)

    for target in targets:
        runtime_dir = out / "runtime" / target
        archive = fetch_runtime(target, cache)
        log(f"extracting runtime for {target}")
        extract_runtime(archive, runtime_dir)
        site_packages = next(runtime_dir.rglob("site-packages"))
        vendor_wheels(target, requirements, site_packages)

    manifest = {
        "built_at": datetime.now(timezone.utc).isoformat(),
        "pbs_release": PBS_RELEASE,
        "python": PBS_PYTHON,
        "targets": targets,
        "mode": "portable",
        "entrypoints": {
            "windows": "start_nova.bat",
            "linux": "start_nova.sh",
            "macos": "start_nova.command",
        },
    }
    (out / "NOVA_MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    stick_readme = f"""NOVA PORTABLE SUITE
===================
Built {manifest['built_at']} for: {', '.join(targets)}

RUN (no installation needed on the host PC):
  Windows : double-click start_nova.bat
  Linux   : bash start_nova.sh
  macOS   : double-click start_nova.command

The dashboard opens at http://127.0.0.1:8000 (pass a port number to override).
Stop with Ctrl+C, or stop_nova.

SECURITY:
  Put your data inside an encrypted container - see secure/README_ENCRYPTION.txt.
  Doctor/self-test: doctor.bat (Windows) or bash doctor.sh.
"""
    (out / "README.txt").write_text(stick_readme, encoding="utf-8")

    log("done. Copy the CONTENTS of this folder to a FAT32/exFAT USB stick:")
    log(f"  {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

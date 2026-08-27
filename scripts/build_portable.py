#!/usr/bin/env python3
"""Build NOVA GPS portable bundle — embeds Python runtime + all deps.

Produces a self-contained directory (nova-portable/) that runs on any
machine without installing Python or pip.

Usage:
    python3 scripts/build_portable.py [--output DIR] [--platform PLATFORM]

Platforms: linux-x86_64, linux-aarch64, macos-x86_64, macos-aarch64, windows-x86_64
"""
import argparse
import os
import platform
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"
DEFAULT_OUTPUT = ROOT / "build" / "nova-portable"


def run(cmd, **kw):
    print(f"  $ {' '.join(str(c) for c in cmd)}")
    subprocess.check_call(cmd, **kw)


def detect_platform():
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "linux":
        return f"linux-{machine}"
    elif system == "darwin":
        return f"macos-{machine}"
    elif system == "win32":
        return "windows-x86_64"
    return f"{system}-{machine}"


def download_python_embed(portable_dir, target_platform):
    """Download embeddable Python for the target platform."""
    print("[portable] Downloading Python embeddable package...")
    pyver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    if "windows" in target_platform:
        url = f"https://www.python.org/ftp/python/{pyver}/python-{pyver}-embed-amd64.zip"
        dest = portable_dir / "runtime" / target_platform / "python"
        dest.mkdir(parents=True, exist_ok=True)
        zip_path = dest / "python.zip"
        run(["wget", "-q", "-O", str(zip_path), url])
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(dest)
        zip_path.unlink()
        # Enable pip in embeddable Python
        pth_files = list(dest.glob("python*._pth"))
        for pth in pth_files:
            content = pth.read_text()
            content = content.replace("#import site", "import site")
            pth.write_text(content)
    else:
        # For Linux/Mac, we use a standalone build via PyInstaller or system Python
        dest = portable_dir / "runtime" / target_platform / "python"
        dest.mkdir(parents=True, exist_ok=True)
        # Copy system Python as fallback
        py_bin = Path(sys.executable)
        py_lib = Path(sys.prefix)
        shutil.copy2(py_bin, dest / "bin" / "python3")
        (dest / "bin").mkdir(parents=True, exist_ok=True)
        shutil.copy2(py_bin, dest / "bin" / "python3")


def install_deps(portable_dir, target_platform):
    """Install Python deps into the portable bundle."""
    print("[portable] Installing Python dependencies...")
    runtime_python = portable_dir / "runtime" / target_platform / "python"
    if "windows" in target_platform:
        py = runtime_python / "python.exe"
        pip = runtime_python / "Scripts" / "pip.exe"
    else:
        py = runtime_python / "bin" / "python3"
        pip = runtime_python / "bin" / "pip3"

    if py.exists():
        run([str(py), "-m", "ensurepip"])
        run([str(pip), "install", "-r", str(BACKEND / "requirements.txt")])
    else:
        # Fallback: install into a venv
        venv_dir = portable_dir / "runtime" / target_platform / "venv"
        run([sys.executable, "-m", "venv", str(venv_dir)])
        venv_py = venv_dir / ("Scripts/python.exe" if "windows" in target_platform else "bin/python")
        run([str(venv_py), "-m", "pip", "install", "-r", str(BACKEND / "requirements.txt")])


def copy_app(portable_dir):
    """Copy backend source and frontend build."""
    print("[portable] Copying application files...")
    app_dir = portable_dir / "app"
    app_backend = app_dir / "backend"
    app_backend.mkdir(parents=True, exist_ok=True)

    # Copy backend source
    for item in BACKEND.iterdir():
        if item.is_file() and item.suffix == ".py":
            shutil.copy2(item, app_backend / item.name)
        elif item.is_dir() and item.name not in ("__pycache__", ".pytest_cache"):
            shutil.copytree(item, app_backend / item.name, dirs_exist_ok=True)

    # Copy frontend dist
    frontend_dist = FRONTEND / "dist"
    if frontend_dist.exists():
        app_frontend = app_dir / "frontend" / "dist"
        shutil.copytree(frontend_dist, app_frontend)

    # Copy portable scripts
    portable_scripts = ROOT / "portable"
    for item in portable_scripts.iterdir():
        if item.is_file() and item.suffix in (".sh", ".bat", ".command", ".py", ".txt", ".md"):
            shutil.copy2(item, portable_dir / item.name)


def create_portable(args):
    portable_dir = Path(args.output)
    if portable_dir.exists():
        shutil.rmtree(portable_dir)
    portable_dir.mkdir(parents=True)

    target_platform = args.platform or detect_platform()
    print(f"[portable] Building portable bundle for: {target_platform}")
    print(f"[portable] Output: {portable_dir}")

    # Create directory structure
    (portable_dir / "data").mkdir()
    (portable_dir / "secure").mkdir()
    secure_readme = portable_dir / "secure" / "README_ENCRYPTION.txt"
    secure_readme.write_text(
        "Mount a VeraCrypt or LUKS container here for at-rest data protection.\n"
        "Create a container, mount it, then create a 'data' directory inside.\n"
        "The portable launcher will auto-detect secure/data/ and use it.\n"
    )

    # Build steps
    download_python_embed(portable_dir, target_platform)
    install_deps(portable_dir, target_platform)
    copy_app(portable_dir)

    # Bootstrap script
    bootstrap = portable_dir / "app" / "backend" / "bootstrap_portable.py"
    if not bootstrap.exists():
        bootstrap.write_text(
            '#!/usr/bin/env python3\n"""Bootstrap portable database."""\n'
            "import os, sys\n"
            "sys.path.insert(0, os.path.dirname(__file__))\n"
            "from db import init_db\n"
            "init_db()\n"
            'print("[NOVA] Database ready.")\n'
        )

    # Create zip archive
    zip_path = portable_dir.with_suffix(".zip")
    print(f"[portable] Creating archive: {zip_path}")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(portable_dir):
            for f in files:
                fp = os.path.join(root, f)
                arcname = os.path.relpath(fp, portable_dir.parent)
                zf.write(fp, arcname)

    size_mb = zip_path.stat().st_size / (1024 * 1024)
    print(f"[portable] Done! {zip_path} ({size_mb:.1f} MB)")
    return zip_path


def main():
    parser = argparse.ArgumentParser(description="Build NOVA GPS portable bundle")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--platform", default=None,
                        help="Target: linux-x86_64, linux-aarch64, macos-x86_64, macos-aarch64, windows-x86_64")
    args = parser.parse_args()
    create_portable(args)


if __name__ == "__main__":
    main()

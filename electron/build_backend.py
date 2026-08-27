#!/usr/bin/env python3
"""Build NOVA GPS backend into a standalone binary using PyInstaller.

Produces a single-file executable that embeds Python + all deps.
Run from the project root:
    python3 electron/build_backend.py [--platform linux|mac|win] [--output DIR]
"""
import argparse
import os
import platform
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "backend")
ELECTRON = os.path.join(ROOT, "electron")


def run(cmd, **kwargs):
    print(f"  $ {' '.join(cmd)}")
    subprocess.check_call(cmd, **kwargs)


def build_binary(target_platform, output_dir):
    os.makedirs(output_dir, host=True)

    print("[build] Installing PyInstaller...")
    run([sys.executable, "-m", "pip", "install", "--quiet", "pyinstaller>=6.0"])

    spec_file = os.path.join(ELECTRON, "nova-backend.spec")
    dist_dir = os.path.join(ELECTRON, "dist")
    build_dir = os.path.join(ELECTRON, "build")

    print(f"[build] Building backend binary for {target_platform}...")
    run([
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name", "nova-backend" + (".exe" if target_platform == "win" else ""),
        "--distpath", dist_dir,
        "--workpath", build_dir,
        "--specpath", ELECTRON,
        "--paths", BACKEND,
        "--hidden-import", "uvicorn.logging",
        "--hidden-import", "uvicorn.loops",
        "--hidden-import", "uvicorn.loops.auto",
        "--hidden-import", "uvicorn.protocols",
        "--hidden-import", "uvicorn.protocols.http",
        "--hidden-import", "uvicorn.protocols.http.auto",
        "--hidden-import", "uvicorn.protocols.websockets",
        "--hidden-import", "uvicorn.protocols.websockets.auto",
        "--hidden-import", "uvicorn.lifespan",
        "--hidden-import", "uvicorn.lifespan.on",
        "--hidden-import", "fastapi",
        "--hidden-import", "sqlalchemy.dialects.sqlite",
        "--hidden-import", "jose",
        "--hidden-import", "cryptography",
        "--hidden-import", "multipart",
        "--collect-all", "fastapi",
        "--collect-all", "starlette",
        "--collect-all", "sqlalchemy",
        os.path.join(BACKEND, "main.py"),
    ])

    binary_name = "nova-backend" + (".exe" if target_platform == "win" else "")
    src = os.path.join(dist_dir, binary_name)
    dst = os.path.join(output_dir, binary_name)
    shutil.copy2(src, dst)
    os.chmod(dst, 0o755)
    size_mb = os.path.getsize(dst) / (1024 * 1024)
    print(f"[build] Backend binary: {dst} ({size_mb:.1f} MB)")
    return dst


def install_frontend_deps():
    frontend = os.path.join(ROOT, "frontend")
    node_modules = os.path.join(frontend, "node_modules")
    if not os.path.isdir(node_modules):
        print("[build] Installing frontend dependencies...")
        run(["npm", "install"], cwd=frontend)


def build_frontend():
    frontend = os.path.join(ROOT, "frontend")
    dist = os.path.join(frontend, "dist")
    if os.path.isdir(dist):
        shutil.rmtree(dist)
    print("[build] Building frontend...")
    run(["npm", "run", "build"], cwd=frontend)
    print(f"[build] Frontend built: {dist}")
    return dist


def package_electron(frontend_dist, backend_binary, target_platform):
    print("[build] Installing Electron dependencies...")
    run(["npm", "install"], cwd=ELECTRON)

    # Copy frontend dist into electron/src
    electron_src = os.path.join(ELECTRON, "src")
    if os.path.isdir(electron_src):
        shutil.rmtree(electron_src)
    shutil.copytree(frontend_dist, electron_src)

    # Copy backend binary
    electron_backend = os.path.join(ELECTRON, "backend-bin")
    os.makedirs(electron_backend, exist_ok=True)
    shutil.copy2(backend_binary, electron_backend)

    print(f"[build] Packaging Electron app for {target_platform}...")

    extra_args = []
    if target_platform == "linux":
        extra_args = ["--linux", "AppImage"]
    elif target_platform == "mac":
        extra_args = ["--mac", "dmg"]
    elif target_platform == "win":
        extra_args = ["--win", "nsis"]
    elif target_platform == "all":
        sysname = platform.system().lower()
        if sysname == "linux":
            extra_args = ["--linux", "AppImage"]
        elif sysname == "darwin":
            extra_args = ["--mac", "dmg"]
        elif sysname == "win32":
            extra_args = ["--win", "nsis"]

    run([
        "npx", "electron-builder",
        "--config", "package.json",
        *extra_args,
    ], cwd=ELECTRON)

    release_dir = os.path.join(ELECTRON, "release")
    print(f"[build] Release artifacts: {release_dir}")
    if os.path.isdir(release_dir):
        for f in os.listdir(release_dir):
            fp = os.path.join(release_dir, f)
            size_mb = os.path.getsize(fp) / (1024 * 1024)
            print(f"  {f} ({size_mb:.1f} MB)")


def main():
    parser = argparse.ArgumentParser(description="Build NOVA GPS desktop app")
    parser.add_argument("--platform", choices=["linux", "mac", "win", "all"], default="all")
    parser.add_argument("--output", default=os.path.join(ELECTRON, "backend-bin"))
    parser.add_argument("--skip-backend", action="store_true")
    parser.add_argument("--skip-frontend", action="store_true")
    parser.add_argument("--skip-electron", action="store_true")
    args = parser.parse_args()

    target = args.platform
    if target == "all":
        sysname = platform.system().lower()
        if sysname == "linux":
            target = "linux"
        elif sysname == "darwin":
            target = "mac"
        elif sysname == "win32":
            target = "win"

    print(f"[build] Target platform: {target}")
    print(f"[build] Project root: {ROOT}")

    backend_binary = None
    if not args.skip_backend:
        backend_binary = build_binary(target, args.output)

    frontend_dist = None
    if not args.skip_frontend:
        install_frontend_deps()
        frontend_dist = build_frontend()

    if not args.skip_electron:
        if not frontend_dist:
            frontend_dist = os.path.join(ROOT, "frontend", "dist")
        if not backend_binary:
            backend_binary = os.path.join(args.output, "nova-backend" + (".exe" if target == "win" else ""))
        package_electron(frontend_dist, backend_binary, target)

    print("\n[build] DONE! Check electron/release/ for artifacts.")


if __name__ == "__main__":
    main()

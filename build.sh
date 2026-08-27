#!/usr/bin/env bash
# NOVA GPS Desktop App — Unified Build Script
# Usage: ./build.sh [linux|mac|win|all|portable|iso]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ELECTRON="$ROOT/electron"
SCRIPTS="$ROOT/scripts"
TARGET="${1:-all}"

log() { echo -e "\033[32m[NOVA]\033[0m $*"; }
err() { echo -e "\033[31m[ERROR]\033[0m $*" >&2; exit 1; }

check_deps() {
    command -v node >/dev/null || err "Node.js not found. Install from https://nodejs.org"
    command -v npm >/dev/null || err "npm not found."
    command -v python3 >/dev/null || err "Python 3 not found."
    log "Deps OK: node $(node -v), npm $(npm -v), python $(python3 --version)"
}

build_frontend() {
    log "Building frontend..."
    cd "$ROOT/frontend"
    npm install --silent
    npm run build
    log "Frontend built: frontend/dist/"
}

build_backend_binary() {
    log "Building backend binary (PyInstaller)..."
    cd "$ROOT"
    python3 "$ELECTRON/build_backend.py" --platform "${TARGET}" --skip-frontend --skip-electron
}

build_electron() {
    log "Building Electron app..."
    cd "$ELECTRON"
    npm install --silent
    local sysname
    sysname="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$TARGET" in
        linux)  npx electron-builder --linux AppImage ;;
        mac)    npx electron-builder --mac dmg ;;
        win)    npx electron-builder --win nsis ;;
        all)
            case "$sysname" in
                linux)  npx electron-builder --linux AppImage ;;
                darwin) npx electron-builder --mac dmg ;;
                mingw*|msys*|cygwin*) npx electron-builder --win nsis ;;
            esac
            ;;
    esac
    log "Electron artifacts: $ELECTRON/release/"
}

build_portable() {
    log "Building portable bundle..."
    cd "$ROOT"
    python3 "$SCRIPTS/build_portable.py"
}

build_iso() {
    log "Building bootable ISO..."
    cd "$ROOT"
    if [[ $EUID -ne 0 ]]; then
        err "ISO build requires root. Run: sudo ./build.sh iso"
    fi
    python3 "$SCRIPTS/build_portable.py" --output "$ROOT/build/nova-portable"
    bash "$ROOT/livebuild/build.sh" "$ROOT/build/nova-portable"
}

show_usage() {
    echo "NOVA GPS Build System"
    echo ""
    echo "Usage: ./build.sh <target>"
    echo ""
    echo "Targets:"
    echo "  linux     Build Electron AppImage for Linux x86_64"
    echo "  mac       Build Electron DMG for macOS (x64 + arm64)"
    echo "  win       Build Electron NSIS installer for Windows x64"
    echo "  all       Build for current platform"
    echo "  portable  Build portable bundle (zip, no install needed)"
    echo "  iso       Build bootable USB ISO (requires root + Debian host)"
    echo ""
    echo "Examples:"
    echo "  ./build.sh linux        # Linux AppImage"
    echo "  ./build.sh portable     # Portable zip bundle"
    echo "  sudo ./build.sh iso     # Bootable USB ISO"
}

case "$TARGET" in
    linux|mac|win|all)
        check_deps
        build_frontend
        build_backend_binary
        build_electron
        ;;
    portable)
        check_deps
        build_portable
        ;;
    iso)
        check_deps
        build_iso
        ;;
    -h|--help|help)
        show_usage
        ;;
    *)
        err "Unknown target: $TARGET. Run: ./build.sh help"
        ;;
esac

log "Build complete! Check release/ or build/ directories."

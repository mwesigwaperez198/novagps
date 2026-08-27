#!/usr/bin/env bash
# Build all NOVA GPS release artifacts.
# Requires: node, npm, python3, and platform-specific tools.
#
# Usage:
#   ./release.sh              # Build for current platform
#   ./release.sh --all        # Build portable for all platforms
#   ./release.sh --iso        # Also build bootable ISO (needs root)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="1.0.0"
RELEASE_DIR="$ROOT/build/releases/v$VERSION"
FLAG="${1:-}"

log() { echo -e "\033[32m[RELEASE]\033[0m $*"; }

mkdir -p "$RELEASE_DIR"

log "NOVA GPS v$VERSION Release Builder"
log "=================================="

# 1. Build frontend
log "[1/4] Building frontend..."
cd "$ROOT/frontend"
npm install --silent
npm run build
log "Frontend: OK"

# 2. Build Electron desktop app
log "[2/4] Building Electron desktop app..."
cd "$ROOT/electron"
npm install --silent
# Copy frontend dist
rm -rf src
cp -r "$ROOT/frontend/dist" src
# Build backend binary
cd "$ROOT"
python3 "$ROOT/electron/build_backend.py" --skip-frontend --skip-electron 2>/dev/null || true
# Package Electron
cd "$ROOT/electron"
SYSNAME="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$SYSNAME" in
    linux)  npx electron-builder --linux AppImage 2>/dev/null ;;
    darwin) npx electron-builder --mac dmg 2>/dev/null ;;
    mingw*|msys*|cygwin*) npx electron-builder --win nsis 2>/dev/null ;;
esac
log "Electron: OK"

# 3. Build portable bundle
log "[3/4] Building portable bundle..."
cd "$ROOT"
python3 "$ROOT/scripts/build_portable.py" --output "$ROOT/build/nova-portable-v$VERSION"
# Create release zip
cd "$ROOT/build"
zip -r "$RELEASE_DIR/nova-gps-portable-v$VERSION.zip" "nova-portable-v$VERSION/" -q
log "Portable: OK"

# 4. Copy Electron artifacts
log "[4/4] Collecting release artifacts..."
if [[ -d "$ROOT/electron/release" ]]; then
    cp "$ROOT/electron/release/"* "$RELEASE_DIR/" 2>/dev/null || true
fi

# 5. ISO build (optional)
if [[ "$FLAG" == "--iso" ]]; then
    log "Building bootable ISO (requires root)..."
    cd "$ROOT"
    sudo bash "$ROOT/livebuild/build.sh" "$ROOT/build/nova-portable-v$VERSION"
    if [[ -f "$ROOT/livebuild/nova-gps-live-amd64.hybrid.iso" ]]; then
        cp "$ROOT/livebuild/nova-gps-live-amd64.hybrid.iso" "$RELEASE_DIR/"
    fi
fi

# Summary
log ""
log "Release v$VERSION ready!"
log "Artifacts in: $RELEASE_DIR/"
ls -lh "$RELEASE_DIR/" 2>/dev/null
log ""
log "Upload to GitHub Releases:"
log "  gh release create v$VERSION $RELEASE_DIR/* --title 'NOVA GPS v$VERSION' --notes 'See RELEASE.md'"

#!/usr/bin/env bash
# Build the NOVA Live-USB ISO (Debian live + NOVA portable bundle).
# Run from a Debian 12/Ubuntu host with root privileges:
#   sudo ./build.sh [path-to-nova-portable-bundle]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE="${1:-$HERE/../build/nova-portable}"

if [[ ! -d "$BUNDLE" ]]; then
    echo "ERROR: portable bundle not found at $BUNDLE"
    echo "Build it first:  python scripts/build_portable.py"
    exit 1
fi

echo "[live] installing live-build toolchain..."
apt-get update -qq
apt-get install -y -qq live-build debootstrap rsync squashfs-tools >/dev/null

echo "[live] embedding NOVA portable bundle into image..."
mkdir -p "$HERE/config/includes.chroot/opt/nova" "$HERE/config/includes.chroot/etc/systemd/system"
rsync -a --delete "$BUNDLE/" "$HERE/config/includes.chroot/opt/nova/"
chmod +x "$HERE/config/includes.chroot/opt/nova"/start_nova.* "$HERE/config/includes.chroot/opt/nova"/doctor.*

echo "[live] configuring image..."
cd "$HERE"
lb clean >/dev/null 2>&1 || true
lb config noauto \
    --distribution bookworm \
    --archive-areas "main contrib non-free non-free-firmware" \
    --architecture amd64 \
    --binary-images iso-hybrid \
    --bootappend-live "boot=live components persistence quiet splash hostname=nova" \
    --debian-installer none \
    --username nova \
    --packages-lists "standard-x11" \
    --packages "$(cat config/package-lists/nova.list.chroot | tr '\n' ' ')" \
    ${LB_ARGS:-} >/dev/null

echo "[live] building ISO (this can take 20-60 minutes on first run)..."
lb build
echo "[live] done: $HERE/live-image-amd64.hybrid.iso"
echo "[live] Write it to USB:  dd if=live-image-amd64.hybrid.iso of=/dev/sdX bs=4M status=progress conv=fsync"
echo "[live] Or use Rufus/Ventoy on Windows."

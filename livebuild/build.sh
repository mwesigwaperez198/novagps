#!/usr/bin/env bash
# Build the NOVA GPS Live-USB ISO (Debian 12 live + NOVA portable bundle).
#
# Run from a Debian 12/Ubuntu host with root privileges:
#   sudo ./build.sh [path-to-nova-portable-bundle]
#
# What this produces:
#   A hybrid ISO image (~3-4 GB) that boots any x86-64 PC from USB.
#   - NOVA pre-installed and auto-starting
#   - Full security tool suite pre-installed
#   - Optional encrypted persistence partition
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE="${1:-$HERE/../build/nova-portable}"
ISO_NAME="nova-gps-live-amd64"

log()  { echo -e "\033[32m[NOVA]\033[0m $*"; }
warn() { echo -e "\033[33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[31m[ERROR]\033[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || err "This script must be run as root (sudo ./build.sh)"

if [[ ! -d "$BUNDLE" ]]; then
    warn "Portable bundle not found at $BUNDLE"
    log "Building portable bundle first..."
    cd "$HERE/.."
    python3 scripts/build_portable.py --output "$BUNDLE"
fi

# Install live-build toolchain
log "Installing live-build toolchain..."
apt-get update -qq
apt-get install -y -qq live-build debootstrap rsync squashfs-tools xorriso isolinux syslinux-efi grub-efi-amd64-bin >/dev/null

# Prepare config
log "Preparing live-build configuration..."
cd "$HERE"
lb clean 2>/dev/null || true

# Embed NOVA bundle
mkdir -p config/includes.chroot/opt/nova
mkdir -p config/includes.chroot/etc/systemd/system
mkdir -p config/includes.chroot/etc/skel/Desktop
rsync -a --delete "$BUNDLE/" config/includes.chroot/opt/nova/
chmod +x config/includes.chroot/opt/nova"/start_nova"* config/includes.chroot/opt/nova"/doctor"* 2>/dev/null || true

# Create desktop shortcut
cat > config/includes.chroot/etc/skel/Desktop/nova-gps.desktop << 'DESKTOP'
[Desktop Entry]
Type=Application
Name=NOVA GPS
Comment=GPS Tracking & Security Workbench
Exec=/opt/nova/start_nova.sh
Icon=utilities-terminal
Terminal=false
Categories=Security;Utility;
DESKTOP
chmod +x config/includes.chroot/etc/skel/Desktop/nova-gps.desktop

# Configure live-build
log "Configuring Debian live image..."
lb config noauto \
    --distribution bookworm \
    --archive-areas "main contrib non-free non-free-firmware" \
    --architecture amd64 \
    --binary-images iso-hybrid \
    --bootappend-live "boot=live components persistence quiet splash hostname=nova" \
    --debian-installer none \
    --username nova \
    --hostname nova-gps \
    --bootloaders "grub-efi,isolinux" \
    --packages-lists "standard-x11" \
    --memtest memtest86+ \
    ${LB_ARGS:-} 2>/dev/null

# Copy package list
if [[ -f config/package-lists/nova.list.chroot ]]; then
    log "Using existing package list"
else
    log "Creating default package list..."
    mkdir -p config/package-lists
    cat > config/package-lists/nova.list.chroot << 'PKGS'
# NOVA GPS live image packages
nmap
tshark
tcpdump
yara
sleuthkit
autopsy
aircrack-ng
macchanger
sqlmap
nikto
john
hashcat
whois
dnsutils
netcat-openbsd
suricata
kismet
reaver
bully
mosquitto
firefox-esr
xfce4
xfce4-terminal
lightdm
network-manager
gvfs
thunar
pkexec
curl
wget
git
htop
tree
vim-tiny
nano
openssh-client
p7zip-full
p7zip-rar
PKGS
fi

# Build ISO
log "Building ISO image (this takes 20-60 minutes on first run)..."
log "Output: $HERE/${ISO_NAME}.hybrid.iso"
lb build 2>&1 | tail -20

ISO="$HERE/${ISO_NAME}.hybrid.iso"
if [[ -f "$ISO" ]]; then
    SIZE=$(du -h "$ISO" | cut -f1)
    log "Build complete!"
    log "ISO: $ISO ($SIZE)"
    log ""
    log "Write to USB (Linux):  sudo dd if=$ISO of=/dev/sdX bs=4M status=progress conv=fsync"
    log "Write to USB (Mac):    sudo dd if=$ISO of=/dev/rdiskX bs=4m"
    log "Write to USB (Windows): Use Rufus (DD mode) or Ventoy"
    log ""
    log "The image boots both UEFI and Legacy BIOS."
else
    err "ISO build failed. Check lb build output above."
fi

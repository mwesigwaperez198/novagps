# NOVA Live-USB (bootable security workbench)

A bootable Debian 12 live image with the NOVA portable bundle and the
authorized-testing toolset installed. Boots any x86-64 PC from USB - no host
installation, no trace on the host disk, optional encrypted persistence.

## What's inside

- Debian 12 live desktop (Xfce standard set) with autologin user `nova`
- NOVA portable stack auto-started as a systemd service (`nova.service`),
  dashboard at http://127.0.0.1:8000
- Security tools: nmap, tshark/wireshark-common, tcpdump, yara, sleuthkit,
  autopsy, volatility3, kismet, aircrack-ng, macchanger, sqlmap, nikto,
  john, hashcat, whois, dnsutils, netcat-openbsd, suricata
- firefox-esr for the dashboard UI

## Build (once, on a Debian/Ubuntu machine)

```bash
# 1. build the portable bundle first
python scripts/build_portable.py

# 2. build the ISO (needs root)
sudo ./livebuild/build.sh
```

Result: `livebuild/live-image-amd64.hybrid.iso` (~3-4 GB).

## Write to USB

Any of:
- Linux: `sudo dd if=live-image-amd64.hybrid.iso of=/dev/sdX bs=4M status=progress conv=fsync`
- Windows: Rufus (DD mode) or Ventoy (drop the ISO onto the stick)

The hybrid image boots UEFI and Legacy BIOS.

## Encrypted persistence (recommended)

Without persistence the live system resets on reboot; data lives only in RAM.
To keep case/evidence data across reboots:

1. After imaging, create a second partition on the stick (ext4),
   label it exactly `persistence`.
2. Inside it create a file `persistence.conf` containing one line:
   ```
   /opt/nova
   ```
3. Optional LUKS: `cryptsetup luksFormat /dev/sdX2 && cryptsetup open ...`
   then `mkfs.ext4` on the mapper and label via `e2label`. The boot menu
   entry can add `encryption` to kernel args when prompted for the passphrase.

Everything under `/opt/nova` (including the SQLite database and evidence
files) now persists. For at-rest protection prefer the LUKS variant or keep
using VeraCrypt containers inside `/opt/nova/secure/`.

## Booting on a remote PC

1. Insert stick, boot to the boot menu (F12/F8/Esc depending on vendor).
2. Pick the USB entry; if Secure Boot complains, disable it once in firmware.
3. At the live boot menu choose "Live persistence" (if configured) or plain Live.
4. Desktop autologins as `nova`; NOVA is already running at
   http://127.0.0.1:8000 (service `nova.service`). Tools are on PATH -
   verify with `/opt/nova/doctor.sh`.

## Legal reminder

Wireless exploitation, scanning, and tracking features are gated by NOVA's
consent/audit layer. Only assess systems you are authorized to test.

# NOVA Live-USB (Bootable Workbench)

For machines you are **authorized to reboot**, the live-USB boots an entire
Debian 12 desktop with NOVA pre-started and the security toolset installed.
Nothing touches the host disk; optional encrypted persistence keeps case data
on the stick.

Build instructions and usage: see [`livebuild/README.md`](../livebuild/README.md).

## Quick flow

```bash
# 1. build the portable bundle (embedded into the ISO)
python scripts/build_portable.py

# 2. build the bootable image (Debian/Ubuntu host, root)
sudo ./livebuild/build.sh

# 3. write to USB
sudo dd if=livebuild/live-image-amd64.hybrid.iso of=/dev/sdX bs=4M status=progress conv=fsync
```

Boot the target machine from USB (UEFI + Legacy BIOS supported). The desktop
autologins as `nova`, the `nova.service` systemd unit starts the platform on
`http://127.0.0.1:8000`, and tools (`nmap`, `tshark`, `yara`, `volatility3`,
`autopsy`, `kismet`, `aircrack-ng`, `sqlmap`, `nikto`, `john`, `hashcat`,
`suricata`, ...) are already on PATH.

## Portable vs Live-USB - when to use which

| Situation | Use |
|---|---|
| Cannot reboot / no admin rights on host | Portable mode |
| Host has Python or antivirus blocking executables | Live-USB |
| Wireless assessments needing kernel tools + monitor mode | Live-USB |
| Quick case review on a client's Windows PC | Portable mode |
| Forensically clean environment required | Live-USB |

## Persistence & encryption

Without persistence, all writes stay in RAM and vanish at shutdown - useful
for sensitive one-shot work. For ongoing cases create a second ext4 partition
labelled `persistence` containing `persistence.conf` with `/opt/nova`, or use
LUKS under it for encryption-at-rest. Details in
[`livebuild/README.md`](../livebuild/README.md).

The same VeraCrypt container workflow from portable mode also works inside
the live system (`/opt/nova/secure/`).

# NOVA GPS Desktop App — Release Notes

## v1.0.0 (2026-08-26)

### Desktop App (Electron)
- Cross-platform: Linux, macOS, Windows
- System tray with quick access
- Auto-starts backend server
- Splash screen while loading
- Window management (minimize to tray)

### Bootable USB (Debian Live)
- Boot any x86-64 PC from USB
- NOVA pre-installed and auto-starting
- Full security tool suite (nmap, aircrack, john, etc.)
- Optional encrypted persistence (LUKS/VeraCrypt)
- No trace on host disk

### Portable Bundle
- Run anywhere without installation
- Embedded Python runtime
- Linux (x86_64, aarch64), macOS (x64, arm64), Windows (x64)
- Encrypted data directory support

## Build Targets

| Target | Format | Size | Platform |
|--------|--------|------|----------|
| `./build.sh linux` | AppImage | ~300 MB | Linux x86_64 |
| `./build.sh mac` | DMG | ~350 MB | macOS x64 + arm64 |
| `./build.sh win` | NSIS installer | ~280 MB | Windows x64 |
| `./build.sh portable` | ZIP | ~150 MB | All platforms |
| `sudo ./build.sh iso` | ISO | ~3-4 GB | Any x86-64 PC |

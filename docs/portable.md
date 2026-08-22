# NOVA Portable Mode

Run NOVA from a USB stick directly on any Windows / Linux / macOS machine
(x86_64 or arm64) **without installing anything** - no Docker, no Postgres,
no Node, no admin rights, no reboot. Designed for field use where you plug
the stick into a machine you are authorized to work from.

## What changes in portable mode

| Concern | Full mode (docker-compose) | Portable mode |
|---|---|---|
| Database | PostgreSQL + PostGIS | SQLite file on the stick |
| Event pipeline | Kafka + Zookeeper | In-process asyncio event bus |
| MQTT | Mosquitto broker | Disabled (or remote broker via `MQTT_BROKER`) |
| WebSocket bridge | Separate process (`kafka_to_ws.py`) | `/ws` endpoint inside the API process |
| Frontend | Vite dev server / CDN | Prebuilt static files served by FastAPI |
| Security tools | Docker sandbox executors | Host CLIs detected on PATH (`nmap`, `tshark`, ...) |

Everything else is identical: consent gating, RBAC, audit logs, GDPR delete,
retention, Prometheus metrics.

## Building a portable stick

On any machine with Python 3.11+ and internet access:

```bash
# 1. build the frontend once (needs npm)
cd frontend && npm install && npm run build && cd ..

# 2. assemble the USB layout for THIS machine's OS/arch
python scripts/build_portable.py

# or bundle every platform at once (bigger stick)
python scripts/build_portable.py --targets all

# or pick targets
python scripts/build_portable.py --targets windows-x86_64,linux-aarch64
```

Result: `build/nova-portable/`. Copy its **contents** onto a FAT32/exFAT
stick (8 GB minimum for one target; 64 GB recommended with evidence space).

```
nova-portable/
├── start_nova.bat / .sh / .command   # launchers per host OS
├── stop_nova.bat / .sh
├── doctor.bat / .sh                  # self-test + tool probe
├── app/backend/                      # API code
├── app/frontend/dist/                # dashboard (offline-capable 3D view)
├── runtime/<os>-<arch>/python/       # bundled CPython + vendored deps
├── secure/README_ENCRYPTION.txt      # VeraCrypt at-rest instructions
└── data/                             # created at first unencrypted run
```

## Using it

Plug into the target PC, then:

- Windows: double-click `start_nova.bat`
- Linux: `bash start_nova.sh`
- macOS: double-click `start_nova.command`

The dashboard opens automatically at `http://127.0.0.1:8000`
(pass a port as first argument to override). Stop with Ctrl+C or
`stop_nova.*`.

The server binds to `127.0.0.1` only - nothing is exposed to the network
unless you explicitly change it.

First run on a new machine? Use `doctor.*` to verify the runtime and see
which security tools exist on that host.

## Encrypted data at rest

All case data lives in one SQLite file inside the data directory. Put that
directory inside an encrypted VeraCrypt container mounted at
`secure/data` - launchers detect and prefer it, and warn loudly when falling
back to plain storage. Full instructions ship on the stick:
`secure/README_ENCRYPTION.txt`.

## Offline behaviour

The 3D mission view is rendered locally (Three.js) and requires no map
tiles or external CDNs; the whole stack runs air-gapped. Only features that
inherently need a target system (DNS lookups, HTTP header fetches, port
scans) touch the network of the environment you are working in.

## Audited security tools

Portable mode extends the immutable command registry (`backend/tool_registry.py`)
with host-tool diagnostics. Rules unchanged from the safety model:

- only fixed `command_id`s - never raw shell input,
- role gates per command (`viewer < auditor < operator < admin`),
- strict argument pattern validation plus per-argument validators
  (http/https-only URLs, paths confined to `DATA_DIR`),
- timeouts, output truncation, SHA-256 hashing of args/output into audit rows.

Probe what exists on the current host: `GET /diagnose/tools`.
Built-ins like `system.info` need no binaries; `net.scan.topports` needs
`nmap`; `net.capture.interfaces` needs `tshark`/`dumpcap`; etc. Missing
tools return exit code 127 with an explicit marker instead of failing silently.

Scanning or probing anything without authorization is prohibited by policy;
the consent/case layer and full audit trail exist so engagements stay lawful.

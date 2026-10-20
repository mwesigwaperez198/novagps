# NOVA GPS — Complete Capability Reference

## System Overview

Nova GPS is a full-stack mobile GPS tracking platform with 100+ capabilities spanning:
- Real-time location tracking with 3D map
- Device fingerprinting (OS/TCP stack + MAC vendor)
- Network discovery (SNMP, ARP, USB, SSDP)
- OSINT and penetration testing tools
- WiFi security auditing
- Firmware vulnerability analysis
- Vehicle theft recovery
- Remote device commands (lock, wipe, lost mode)
- VPN/IDS management
- Blockchain-anchored audit trail
- Scheduled tasks and webhooks
- Role-based access control (viewer, operator, admin, auditor, superadmin)
- Multi-protocol ingestion (HTTP, MQTT, LoRaWAN, LTE-M, NB-IoT, Traccar)
- Geofencing with breach alerts
- WebSocket broadcasting
- Analytics and reporting

---

## Authentication & Authorization

| Endpoint | Method | Description |
|---|---|---|
| `/auth/login` | POST | Email/password login, returns JWT |
| `/register` | POST | Register new device |

### Roles
- **viewer** — Read-only access to devices and locations
- **operator** — Can run scans, remote commands, discovery
- **admin** — Full access including user management, webhooks, tasks
- **auditor** — Read + diagnostic commands
- **superadmin** — Full admin + superadmin-only features (dev mode bypasses auth)

---

## Device Management

| Endpoint | Method | Description |
|---|---|---|
| `/devices` | GET | List all registered devices |
| `/search?q=` | GET | Search devices by name/email/phone |
| `/register` | POST | Register a new device |

### Device Types
`vehicle`, `motorcycle`, `phone`, `tablet`, `laptop`, `tracker`, `other`

---

## Location Tracking

| Endpoint | Method | Description |
|---|---|---|
| `/update-location` | POST | Ingest location update (202 Accepted) |
| `/device/locate` | POST | Device self-locate (query params) |
| `/devices/{id}/locations` | GET | Location history (limit 1-1000) |

### Location Fields
`latitude`, `longitude`, `altitude`, `speed`, `heading`, `accuracy`, `source`, `place_name`, `recorded_at`

### Sources
`http`, `mobile`, `traccar`, `iot`, `mqtt`, `lorawan`, `lte-m`, `nb-iot`

### Protocols
- **HTTP** — REST API push
- **MQTT** — Message queue telemetry (mosquitto broker)
- **LoRaWAN** — Long-range low-power via ChirpStack
- **LTE-M / NB-IoT** — Cellular IoT via Pycom or Quectel
- **Traccar** — Compatible with Traccar protocol

---

## Consent Management

| Endpoint | Method | Description |
|---|---|---|
| `/consent` | POST | Grant consent with blockchain hash |
| `/consent/revoke` | POST | Revoke consent |

Consent records are anchored to a simulated blockchain (SHA-256 hash chain).

---

## Geofencing

| Endpoint | Method | Description |
|---|---|---|
| `/geofences` | GET | List all configured geofences |
| `/geofences/{id}` | GET | Get geofence details + WKT polygon + coordinates |

### Built-in Geofences
- Golden Gate Park (San Francisco)
- Financial District (San Francisco)
- LAX Airport (Los Angeles)

---

## Device Fingerprinting

| Endpoint | Method | Description |
|---|---|---|
| `/fingerprint/ip/{ip}` | POST | OS fingerprint via TCP/IP stack analysis |
| `/device/{id}/oui` | GET | MAC vendor lookup (OUI database) |

### Fingerprint Data
- TTL analysis (initial TTL guess, OS mapping)
- TCP window size
- Don't Fragment bit
- OS guess with confidence score

---

## Network Discovery

| Endpoint | Method | Description |
|---|---|---|
| `/discovery/scan-network` | POST | SNMP/ping sweep on subnet |
| `/discovery/usb` | GET | List USB devices and serial ports |
| `/discovery/arp` | GET | ARP table with OUI vendor lookup |

---

## WiFi Security

| Endpoint | Method | Description |
|---|---|---|
| `/wifi/scan` | POST | Scan WiFi networks (airodump-ng) |
| `/wifi/capture-handshake` | POST | Capture WPA handshake |
| `/wifi/crack-wpa` | POST | Dictionary attack on captured handshake |
| `/wifi/wps-attack` | POST | WPS PIN brute force (reaver/bully) |
| `/wifi/deauth` | POST | Deauthentication attack (aireplay-ng) |

---

## Firmware Analysis

| Endpoint | Method | Description |
|---|---|---|
| `/firmware/cve` | GET | CVE database lookup by keyword |
| `/firmware/diagnose/{ip}` | GET | Full firmware diagnosis (manufacturer, model, version) |
| `/firmware/health/{ip}` | GET | Device health check |

---

## OSINT Tools

| Endpoint | Method | Description |
|---|---|---|
| `/osint/whois` | GET | WHOIS domain lookup |
| `/osint/dns-brute` | GET | DNS brute-force subdomain enumeration |
| `/osint/reverse-dns` | GET | Reverse DNS lookup |
| `/osint/http-headers` | GET | HTTP security headers analysis |
| `/osint/nikto` | GET | Web server vulnerability scanner |
| `/osint/sqlmap` | GET | SQL injection detection |
| `/osint/theharvester` | GET | Email/subdomain/IP harvesting |
| `/osint/whatweb` | GET | Web technology fingerprinting |
| `/osint/wpscan` | GET | WordPress vulnerability scanner |
| `/osint/dirb` | GET | Directory/file brute-force |
| `/osint/sublist3r` | GET | Subdomain enumeration |
| `/osint/phone-lookup` | GET | Phone number OSINT |
| `/osint/email-lookup` | GET | Email address OSINT |

---

## LAU Cloud Research (read-only)

LAU can consult public sources when the local toolset cannot answer a question
(vendor docs, CVEs, install steps, current versions, general how-to). This is a
read-only capability and it is deliberately narrow.

| Endpoint / Tool | Method | Description |
|---|---|---|
| `POST /nova-core/agent/dispatch` | POST | Any question; LAU may run `cloud_research` and cite sources |
| `GET /nova-core/cloud/status` | GET | Provider readiness (provider, key configured?) |
| `cloud_research` tool | — | Search + fetch the top pages, return titles, URLs, excerpts |
| `web_search` tool | — | Search only; return titles, URLs, snippets |
| `fetch_url` tool | — | Fetch one public page as plain text |

Constraints, enforced in code (`nova_core/cloud.py`):

- **GET only.** The single POST exception is a search-provider API call, which
  carries the query and nothing else. No cookies, no credentials, no referer,
  no device data, no telemetry ever leave the host.
- **SSRF guard.** Scheme (http/https), port (80/443), host shape, and every
  resolved address are checked before the request, on each redirect, and at the
  socket — loopback, RFC1918, link-local, and the cloud metadata address
  `169.254.169.254` are refused. URLs with embedded credentials are refused.
- **robots.txt** is fetched and honoured for page reads.
- Bodies are content-type restricted and size-capped; `<script>`/`<style>` and
  other active markup are stripped before the text reaches the model.
- **Fetched content is untrusted data, never instructions.** LAU quotes it and
  cites the URL; it never executes commands, scripts, or "ignore instructions"
  text found on a page. Cloud-derived commands are never auto-run.
- Provider chain, degrading safely: Brave/Tavily/Serper (on `NOVA_SEARCH_API_KEY`)
  → self-hosted SearXNG (on `NOVA_SEARCH_BASE_URL`) → keyless DuckDuckGo Instant
  Answer + Wikipedia. A failed provider falls through to the next.

Config (all optional; sensible defaults): `NOVA_CLOUD_RESEARCH=1`,
`NOVA_CLOUD_MAX_SOURCES=3`, `NOVA_CLOUD_TIMEOUT=20`, `NOVA_CLOUD_MAX_BYTES`,
`NOVA_SEARCH_PROVIDER`, `NOVA_SEARCH_API_KEY`, `NOVA_SEARCH_BASE_URL`.

### What "outside the sandbox" actually means

The Render container is not what blocks the internet — outbound HTTPS already
works (the hosted model, package downloads, and cloud research all use it). What
the platform will not grant a public web service is **raw-socket privilege**
(`CAP_NET_RAW`) and an **unrestricted shell**. Giving the internet-facing API a
generic shell would be a remote-code-execution backdoor, so that is refused by
design.

The safe way to reach host/raw-socket capabilities is a **probe companion**: a
small agent the operator runs on a machine they control (a home server, a lab
box, a phone), which connects *outbound* to NOVA and executes an explicit,
allow-listed set of probes. The public API only ever sends it named tasks
(`masscan`, a raw SYN scan, an ARP sweep) and reads back structured results —
never a shell string. Until that companion is running, LAU on Render uses the
unprivileged equivalents (`nmap -sT`, connect scans) and says plainly when a
capability needs the companion.

---

## Penetration Testing

| Endpoint | Method | Description |
|---|---|---|
| `/pentest/vuln-scan` | GET | Vulnerability scan (nmap scripts) |
| `/pentest/auth-scan` | GET | Authentication testing |

---

## Terminal / Diagnostic Commands

| Endpoint | Method | Description |
|---|---|---|
| `/diagnose/tools` | GET | List registered commands |
| `/diagnose` | POST | Execute registered command (`command_id` + `args`) |

### Available Commands
`system_info`, `network_scan`, `process_list`, `port_scan`, `service_scan`, `ip_scan`, `masscan`, `crypto_audit`, `firewall_check`, `disk_usage`, `cpu_monitor`, `memory_check`, `log_reader`, `whois_lookup`, `dns_lookup`, `ssl_check`, `packet_capture`, `wifi_scan`, `interface_list`, `routing_table`, `arp_table`, `connection_list`, `bandwidth_test`, `traceroute`, `mtu_test`

---

## VPN Management

| Endpoint | Method | Description |
|---|---|---|
| `/vpn/status` | GET | VPN connection status |
| `/vpn/connect` | POST | Connect VPN (WireGuard/OpenVPN) |
| `/vpn/disconnect` | POST | Disconnect VPN |

---

## IDS/IPS

| Endpoint | Method | Description |
|---|---|---|
| `/ids/status` | GET | Suricata status |
| `/ids/alerts` | GET | Recent IDS alerts |
| `/ids/update-rules` | POST | Update IDS rulesets |

---

## Camera

| Endpoint | Method | Description |
|---|---|---|
| `/camera/discover` | GET | Discover IP cameras on subnet |
| `/camera/screenshot` | GET | Capture RTSP screenshot |
| `/camera/record` | POST | Record video clip |

---

## Remote Device Commands

| Endpoint | Method | Description |
|---|---|---|
| `/remote/sms` | POST | Send SMS with tracking link |
| `/remote/lock-guide` | POST | Get lock instructions |
| `/remote/icloud-instructions` | GET | iCloud remote lock guide |
| `/remote/android-instructions` | GET | Android Device Manager guide |
| `/device/{id}/remote-lock` | POST | Remote lock command |
| `/device/{id}/remote-wipe` | POST | Remote wipe command (admin only) |
| `/device/{id}/lost-mode` | POST | Enable lost mode with message |
| `/device/{id}/send-message` | POST | Push message to device |
| `/device/{id}/trigger-locate` | POST | Force immediate location report |

---

## Vehicle Theft Recovery

| Endpoint | Method | Description |
|---|---|---|
| `/vehicle/stolen-report` | POST | Report vehicle stolen (creates alert + recovery mode) |
| `/vehicle/recovery/{id}` | GET | Get recovery status |
| `/vehicle/recovery/{id}/end` | POST | End recovery mode |
| `/vehicle/recovery/{id}/link-camera` | POST | Link IP camera to recovery |
| `/vehicle/active-recoveries` | GET | List all active recoveries |

---

## Alerts

| Endpoint | Method | Description |
|---|---|---|
| `/alerts` | GET | List alerts (filter by severity, acknowledged) |
| `/alerts/{id}/acknowledge` | POST | Acknowledge alert |

### Alert Types
`geofence_breach`, `theft`, `firmware`, `ids`, `device_offline`

### Severity Levels
`info`, `medium`, `high`, `critical`

---

## Scheduled Tasks

| Endpoint | Method | Description |
|---|---|---|
| `/tasks/schedule` | POST | Create cron-scheduled task |
| `/tasks` | GET | List all tasks |
| `/tasks/{id}/toggle` | PUT | Enable/disable task |
| `/tasks/{id}` | DELETE | Delete task |

---

## Webhooks

| Endpoint | Method | Description |
|---|---|---|
| `/webhooks` | POST | Register webhook endpoint |
| `/webhooks` | GET | List all webhook endpoints |
| `/webhooks/{id}` | DELETE | Delete webhook |
| `/webhooks/{id}/deliveries` | GET | Delivery history |

### Supported Events
`location.updated`, `geofence.breach`, `vehicle.stolen`, `device.offline`, `alert.created`

---

## Analytics

| Endpoint | Method | Description |
|---|---|---|
| `/analytics/dashboard` | GET | Dashboard summary |
| `/analytics/device/{id}` | GET | Device analytics |
| `/analytics/device/{id}/fraud` | GET | Fraud detection analysis |
| `/analytics/device/{id}/heartbeat` | GET | Heartbeat/uptime analysis |
| `/analytics/device/{id}/location-stats` | GET | Location statistics |
| `/analytics/device/{id}/export` | GET | Export data (CSV/JSON) |

---

## Blockchain Audit Trail

All consent grants, device registrations, location updates, and security events are recorded with SHA-256 hash chain integrity. The `audit-logs` endpoint provides the full audit trail.

---

## WebSocket

| Endpoint | Method | Description |
|---|---|---|
| `/ws?channel={ch}` | WS | Real-time event stream |
| `/broadcast` | POST | Create broadcast session |

### Channels
`map`, `terminal`, `alerts`

---

## Frontend Panels (18 tabs)

| Tab | Component | Description |
|---|---|---|
| DIAG | TerminalPanel | xterm.js diagnostic terminal |
| SCAN | ScanPanel | Port scanner (TCP/UDP/masscan) |
| OSINT | OSINTPanel | 13 OSINT + 12 pentest tools |
| WEB | WebScanPanel | Security headers, Nikto, SQLi |
| CAM | CameraPanel | IP camera discovery + screenshots |
| VPN | VPNPanel | WireGuard/OpenVPN controls |
| IDS | IDSPanel | Suricata status + alerts |
| FORE | ForensicsPanel | Hash, YARA, John, TLS |
| REM | RemotePanel | SMS, lock, recovery |
| FP | FingerprintPanel | OS fingerprint + MAC vendor |
| DISC | DiscoveryPanel | Network, USB, ARP discovery |
| WIFI | WifiPanel | WiFi scan, handshake, WPS, deauth |
| FW | FirmwarePanel | CVE lookup, diagnosis, health |
| VHC | VehicleRecoveryPanel | Stolen report, recovery tracking |
| GEO | GeofencePanel | Geofence zones + coordinates |
| ALRT | AlertsPanel | System alerts + acknowledgment |
| TASK | SchedulerPanel | Cron task management |
| HOOK | WebhookPanel | Webhook endpoints + deliveries |

---

## Tech Stack

### Backend
- **Python 3.14** + **FastAPI**
- **SQLAlchemy** (SQLite for dev, PostgreSQL for prod)
- **Prometheus** metrics (via prometheus-fastapi-instrumentator)
- **JWT** authentication (python-jose)
- **Kafka** event streaming (optional)
- **WebSocket** real-time updates

### Frontend
- **React 18** + **Vite**
- **Three.js** 3D map
- **xterm.js** terminal
- **TanStack Query** data fetching
- **lucide-react** icons

### Hardware Integration
- **BLE relay firmware** (ESP32 + nRF52) — see `ble_relay_firmware/`
- **ChirpStack** LoRaWAN integration
- **Traccar** protocol compatibility
- **Mosquitto** MQTT broker

<!-- lau: owner session persistence verified 2026-10-20T06:28:22Z -->

# NOVARA Master Plan — Phases 0–6

## The "why"
- **Client's stolen phone** (Samsung Galaxy A06, IMEI 355758535145530, MTN Uganda +256776335383). Honest recovery: watchlist + Find My + police→UCC/MTN IMEI blacklist. No fabricated coordinates, no SS7/IMEI interception.
- **`prompt.txt`** — consent-first tracking, terminal aesthetic, sandboxed commands, RBAC/audit.
- **`desccription.txt`** — authorized-only security intelligence (OSINT/recon, network/web testing under explicit scope, chain-of-custody evidence). LAU is the queen: coordinates tracking + defensive security, refuses the illegal lane.

## Phase 0 — Unblock live (user-side + verify)
1. Render env: `OWNER_PASSWORD=perez123!`, `DEV_OWNER_EMAIL=mwesigwagershom7@gmail.com`
2. Fresh GitHub PAT → push `c21064f` (watchlist + stolen_track) → clean remote URLs
3. Verify `POST /auth/login` 200 → `POST /watchlist` register stolen phone
4. Deliver evidence packet + client playbook (android.com/find, Samsung Find My, police→UCC)

## Phase 1 — Android agent v2 ("our own Traccar")
1. QR pairing: server URL + identifier + consent token (configured once)
2. Every ping sends identifier, phone, IMEI (privileged path only), cell-ID, SIM state
3. Offline retry queue (currently failed pings are dropped)
4. SIM-change + uninstall/tamper alerts (Device Owner API)
5. Battery-optimization prompt on first run; FCM wake later
6. CI APK via `agent-build.yml` (working) — keep shipping via Actions

## Phase 2 — Server glue
1. `GET /watchlist/{id}/sightings` — last-seen timeline
2. Device last-seen health / stale-device alert (>2× interval no ping)
3. Pairing-token endpoint for QR flow
4. Watchlist hook into `/device/locate` (currently only `/update-location` + `/traccar`)

## Phase 3 — iOS (limited or defer)
- Significant-change + region monitoring, or Find My instructions in playbook
- Continuous background GPS is not deliverable on iOS — never promise it

## Phase 4 — Windows / fleet
1. Desktop agent (Electron shell exists) — Wi-Fi geolocation + IP
2. Fleet MDM: Device Owner QR provisioning

## Phase 5 — LAU queen interface (CLI + web)

### CLI (`lau.sh`)
1. `lau watch add/list/recover <imei>` → `/watchlist`
2. `lau theft <imei>` → guided recovery: sightings → evidence packet → MTN/UCC/police
3. `lau watch` → live ping radar stream
4. `lau skills` → skill registry with readiness

### Web HUD (`LAUAgentPanel.jsx`)
1. **Theft** sub-tab: watchlist cards, register form, sightings timeline, evidence packet; locate highlights globe
2. **Skills** sub-tab: skill browser, run buttons (same dispatch backend → CLI/web parity)
3. **Live** sub-tab: WS alert feed; `watchlist_sighting` critical, LAU speaks first
4. Black/green terminal aesthetic (per `prompt.txt`)

## Phase 6 — Skills cloned from git (enforcer-gated, authorized-only)

| Priority | Skill | Repo | License |
|---|---|---|---|
| P0 | PhoneInfoga | sundowndev/phoneinfoga | GPL-3.0 |
| P0 | Nuclei + templates | projectdiscovery/nuclei | MIT |
| P0 | httpx | projectdiscovery/httpx | MIT |
| P1 | theHarvester | laramies/theHarvester | GPL-2.0 |
| P1 | Sherlock | sherlock-project/sherlock | GPL-3.0 |
| P1 | sqlmap | sqlmapproject/sqlmap | GPL-2.0 |
| P1 | ffuf | ffuf/ffuf | MIT |
| P1 | Nmap | nmap/nmap | NPSL |
| P2 | maigret | soxoj/maigret | AGPL-3.0 |
| P2 | WhatWeb | urbanadventurer/WhatWeb | GPL-3.0 |
| P2 | mitmproxy | mitmproxy/mitmproxy | MIT |
| P2 | YARA + rules | VirusTotal/yara | Apache-2.0 |
| P2 | TruffleHog | trufflesecurity/trufflehog | AGPL-3.0 |
| P3 | Zeek / Suricata | zeek/zeek / Suricata/suricata | BSD-3 / GPL-2 |
| P3 | bettercap | bettercap/bettercap | GPL-3.0 |
| P3 | kismet / aircrack-ng | kismetwireless/kismet / aircrack-ng | GPL-2.0 |

Each skill = clone into `nova_core/skills/<name>/` + `SKILL.md` + thin tool adapter → registered in brain → every invocation passes scope allowlist + audit log (`desccription.txt` §2A).

## Execution order
Phase 0 → Phase 5 theft workflow → Phase 1 → Phase 6 (PhoneInfoga + Nuclei first) → Phase 2 → 3 → 4

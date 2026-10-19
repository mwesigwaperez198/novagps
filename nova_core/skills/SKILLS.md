# LAU Skills

External security / OSINT tools the queen agent can drive. Nothing is vendored
into this repo — each skill is an open-source project installed separately and
invoked through a guarded adapter (`nova_core/skills/adapters.py`). Run
`lau skills` to see what is present on this host.

| Skill | Pri | Category | Source |
| --- | --- | --- | --- |
| phoneinfoga | P0 | osint | https://github.com/sundowndev/phoneinfoga |
| nuclei | P0 | vuln | https://github.com/projectdiscovery/nuclei |
| httpx | P0 | recon | https://github.com/projectdiscovery/httpx |
| theharvester | P1 | osint | https://github.com/laramies/theHarvester |
| sherlock | P1 | osint | https://github.com/sherlock-project/sherlock |
| sqlmap | P1 | vuln | https://github.com/sqlmapproject/sqlmap |
| ffuf | P1 | fuzz | https://github.com/ffuf/ffuf |
| nmap | P1 | recon | https://github.com/nmap/nmap |
| maigret | P2 | osint | https://github.com/soxoj/maigret |
| whatweb | P2 | recon | https://github.com/urbanadventurer/WhatWeb |
| mitmproxy | P2 | proxy | https://github.com/mitmproxy/mitmproxy |
| yara | P2 | malware | https://github.com/VirusTotal/yara |
| trufflehog | P2 | secrets | https://github.com/trufflesecurity/trufflehog |
| zeek | P3 | network | https://github.com/zeek/zeek |
| suricata | P3 | network | https://github.com/OISF/suricata |
| bettercap | P3 | network | https://github.com/bettercap/bettercap |
| kismet | P3 | wireless | https://github.com/kismetwireless/kismet |
| aircrack-ng | P3 | wireless | https://github.com/aircrack-ng/aircrack-ng |

## Usage

```
lau skills                                  # what is installed + install hints
lau skill phoneinfoga +256776335383         # run a skill against a target
lau skill nmap 10.0.0.5 -- -p 1-1000        # pass extra arguments after --
```

## Safety scope

- **P0–P2** run normally against targets the operator is authorised to test.
- **P3 (zeek / suricata / bettercap / kismet / aircrack-ng)** are **lab-only**:
  they refuse unless `NOVA_LAB_MODE=1` is set, and every run is written to LAU
  memory with the exact command line, target and outcome.
- The adapter never downloads or installs anything; missing tools return the
  install hint from the registry.

## Per-skill notes

- **phoneinfoga** — `lau skill phoneinfoga +256776335383`. Carriers, line type
  and short-number matching for a subscriber number.
- **nuclei** — `lau skill nuclei https://target`. Curated CVE/exposure templates.
- **httpx** — `lau skill httpx https://target`. Liveness, status, title, tech.
- **theharvester** — `lau skill theharvester example.com`. Passive email/subdomain harvest.
- **sherlock** — `lau skill sherlock <username>`. Social-network profile hunt.
- **sqlmap** — `lau skill sqlmap 'https://target/item?id=1'`. Batch injection test.
- **ffuf** — `lau skill ffuf 'https://target/FUZZ'`. Path/endpoint fuzzing.
- **nmap** — `lau skill nmap 10.0.0.5`. Service/version scan.
- **maigret** — `lau skill maigret <username>`. Username report across 2000+ sites.
- **whatweb** — `lau skill whatweb https://target`. CMS/framework fingerprint.
- **mitmproxy** — `lau skill mitmproxy`. HTTPS interception console (owned traffic).
- **yara** — `lau skill yara rules.yar /path/to/scan`. Signature hits.
- **trufflehog** — `lau skill trufflehog /path/to/repo`. Leaked secrets.
- **zeek** — `lau skill zeek -i eth0`. Passive traffic analysis (lab).
- **suricata** — `lau skill suricata -i eth0`. IDS/IPS run (lab).
- **bettercap** — `lau skill bettercap`. Lab-segment console.
- **kismet** — `lau skill kismet`. Wireless survey console (authorised).
- **aircrack-ng** — `lau skill aircrack-ng`. Wi-Fi audit suite binaries (own networks).

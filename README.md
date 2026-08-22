# NOVA GPS Tracking System

NOVA is a consent-first GPS tracking platform for vehicles, motorcycles, smartphones, laptops, and other registered devices. This scaffold gives you a runnable local development stack, backend services, a terminal-style React dashboard, Kubernetes and Helm templates, Terraform examples, CI/CD, monitoring, backup guidance, and security/compliance runbooks.

It ships in three run modes:

1. **Server mode** - the full docker-compose / k8s stack (Postgres, Kafka, MQTT).
2. **Portable mode** - runs from a USB stick on any Windows/Linux/macOS PC with zero installation (SQLite + in-process event bus + bundled Python runtime). See [docs/portable.md](docs/portable.md).
3. **Live-USB mode** - a bootable Debian workbench with NOVA auto-started and the security toolset preinstalled. See [docs/live-usb.md](docs/live-usb.md).

## Local Development

1. Copy environment defaults:

   ```bash
   cp .env.example .env
   ```

2. Start the platform:

   ```bash
   docker compose up --build
   ```

3. Open the services:

   - API: http://localhost:8000/docs
   - Frontend: http://localhost:5173
   - WebSocket bridge: ws://localhost:8765
   - Prometheus: http://localhost:9090
   - Grafana: http://localhost:3000

You can also run a single-process stack without Docker:

```bash
pip install -r backend/requirements.txt
cd backend && NOVA_MODE=portable uvicorn main:app --port 8000
```

This uses SQLite (`./data/nova.sqlite3`) and skips Kafka/MQTT automatically.

## Core Safety Model

- Location updates are rejected unless the device has an active consent record.
- Manual registration supports Android IDs or generated UUIDs. IMEI must only be used when you have lawful access, carrier permission, or a managed-device agreement.
- `/diagnose` accepts only immutable command IDs from `backend/command_registry.py` + `backend/tool_registry.py`; it never accepts raw shell commands. Host-tool commands are role-gated, argument-validated, timed out, and hash-audited.
- Production deployments should use TLS at ingress, mTLS internally, managed secrets, encrypted database volumes, RBAC, audit logs, and retention policies.

## Quick API Smoke Test

```bash
bash scripts/curl_examples.sh
```

In development, the API allows missing bearer tokens and treats the caller as an admin. In production, set `ENVIRONMENT=production` and provide OAuth/JWT verification through your identity provider.

## Project Map

- `backend/` FastAPI API, Kafka workers, MQTT consumer, WebSocket bridge (standalone + in-process), Alembic migrations, tests.
- `frontend/` React + Three.js + xterm.js terminal dashboard.
- `portable/` launchers, doctor, encryption guide, portable requirements.
- `scripts/build_portable.py` assembles the zero-install USB layout; `scripts/portable_smoke.*` end-to-end checks.
- `livebuild/` Debian live-USB image build with security toolset.
- `k8s/` Kubernetes base manifests and Helm chart skeleton.
- `iac/terraform/` cloud infrastructure example for VPC, managed Kubernetes, managed Postgres, and object storage.
- `.github/workflows/ci.yml` test, build, scan, plan, and deploy pipeline.
- `docs/` security, compliance, deployment, runbook, backup, ASCII UI, portable mode, and live-USB artifacts.
- `monitoring/` Prometheus and Grafana examples.

Start with `docs/architecture.md`, then `docs/security-compliance.md`, then `docs/deployment-operations.md` for the production path.

## Troubleshooting

- DB connection fails: confirm `postgres` is healthy with `docker compose ps` and that `DATABASE_URL` points to `postgres:5432` inside Compose.
- PostGIS missing: run `docker compose exec backend-api alembic upgrade head`; the initial migration enables `postgis`.
- Kafka unavailable: wait for `kafka-init` to complete, then check `docker compose logs kafka kafka-init`.
- Frontend live map is quiet: send a consent record and then a location update using `scripts/curl_examples.sh`.

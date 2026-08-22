# Security And Compliance

## Consent

NOVA must only track users and devices that have explicitly opted in. Store consent with:

- device ID
- user email
- timestamp
- source
- scope
- proof hash
- revocation timestamp when consent is withdrawn

Suggested consent text:

> I consent to NOVA collecting and processing my live and historical location for the selected device for operational tracking, alerts, and diagnostics. I can revoke this consent and request deletion of my data.

## RBAC

Roles:

- Admin: deployment, imports, deletion, retention, broadcast, diagnostics.
- Operator: registration, consent capture, live operations, safe diagnostics.
- Viewer: read-only map and device views.
- Auditor: audit and diagnostic trace review.

Use JWTs with `sub` and `role` claims. Integrate OAuth2/OIDC in production and set `ENVIRONMENT=production` so unauthenticated development fallback is disabled.

## TLS And mTLS

- Use cert-manager and Let's Encrypt for public HTTPS ingress.
- Use a service mesh such as Istio, Linkerd, or Consul for internal mTLS.
- Rotate certificates automatically and alert on expiration within 14 days.
- Disable plaintext Kafka and Postgres outside private networks; prefer managed services with TLS.

## Encryption At Rest

- Use managed Postgres storage encryption or LUKS on self-managed disks.
- Use object-store encryption for backups.
- Use Vault, AWS Secrets Manager, GCP Secret Manager, or Azure Key Vault for secrets.
- Never commit `.env` files, DB credentials, Vault tokens, or service account JSON.

Self-managed LUKS sketch:

```bash
cryptsetup luksFormat /dev/nvme1n1
cryptsetup open /dev/nvme1n1 nova_pg_data
mkfs.ext4 /dev/mapper/nova_pg_data
mount /dev/mapper/nova_pg_data /var/lib/postgresql
```

## Immutable Command Registry

`/diagnose` accepts `command_id` only. Commands are defined in `backend/command_registry.py`, validated by role and argument schema, and executed in mock mode locally. Production can set `SANDBOX_EXECUTOR_MODE=docker` on a hardened host. The executor uses:

- no shell from user input
- no network
- CPU and memory limits
- read-only filesystem
- dropped Linux capabilities
- timeout enforcement
- SHA-256 hashes for arguments and output
- audit log for every execution

## GDPR Checklist

- Capture consent before accepting location pings.
- Provide `/delete-data` for deletion requests.
- Run `/admin/retention/run` on a schedule.
- Minimize data fields; do not collect IMEI unless lawful and necessary.
- Keep audit logs for security accountability.
- Document data processors and subprocessors.
- Export or delete user data within your required legal window.

## IMEI Legal Note

Modern Android and iOS restrict IMEI access. Use Android ID, app-generated UUID, MDM-managed identifiers, or Traccar device identifiers by default. IMEI collection may require carrier agreements, enterprise MDM enrollment, explicit legal basis, and regional compliance review.

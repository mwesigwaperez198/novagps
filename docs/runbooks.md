# Incident Runbooks

## Location Ingestion Outage

1. Check `/health` and Prometheus `up{job="nova-api"}`.
2. Confirm Postgres accepts connections.
3. Confirm Kafka topic `nova.locations` exists.
4. Check recent API logs for consent rejection, validation errors, or DB errors.
5. Scale API replicas if CPU or latency is saturated.

## Kafka Lag

1. Check consumer group lag.
2. Scale `nova-worker`.
3. Verify workers can reach Postgres.
4. Increase topic partitions if lag persists under normal worker health.

## Data Deletion Request

1. Verify requester identity through your support workflow.
2. Call `/delete-data` with `device_id` or `email`.
3. Confirm records are removed from `devices`, `locations`, `consents`, and `imported_users`.
4. Keep the audit log entry for accountability.

## Suspicious Diagnostics

1. Query `audit_logs` for `diagnose.execute`.
2. Review `command_id`, actor, role, output hash, and timing.
3. Disable broadcast sessions if tokens may be exposed.
4. Rotate JWT signing key if authorization is suspected compromised.

# Monitoring And Alerting

## Metrics

FastAPI exposes `/metrics` through `prometheus-fastapi-instrumentator`.

Core dashboards:

- request rate
- p95 latency
- 4xx and 5xx rates
- Kafka lag
- location updates per minute
- active WebSocket sessions
- Postgres CPU, disk, locks, and slow queries

## Logs

Use Loki or ELK. Required labels:

- `service`
- `environment`
- `pod`
- `trace_id`
- `device_type`
- `source`

Never log raw credentials, full JWTs, service account JSON, or sensitive diagnosis output.

## Alerts

- API down for 2 minutes.
- 5xx rate above 5 percent for 5 minutes.
- Kafka consumer lag above one partition-hour.
- Postgres free storage below 20 percent.
- Backup older than 24 hours.
- Certificate expiration inside 14 days.
- Consent rejection spike above baseline.

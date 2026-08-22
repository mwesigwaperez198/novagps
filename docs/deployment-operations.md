# Deployment And Operations

## Local

```bash
cp .env.example .env
docker compose up --build
```

Run migrations manually when needed:

```bash
docker compose exec backend-api alembic upgrade head
```

## Production Cluster

Baseline sizing:

- API: 3 replicas, 1 CPU, 1 GiB each.
- Worker: 2 replicas minimum, scale by Kafka lag.
- WebSocket bridge: 2 replicas minimum, sticky sessions if your ingress needs them.
- Postgres: managed, encrypted, multi-AZ, 100 GB minimum with autoscaling.
- Kafka: managed Kafka preferred, 3 brokers minimum, replication factor 3.

## Kafka Topics

Topic: `nova.locations`

Suggested production config:

- partitions: 12 to 48 depending on device volume
- replication.factor: 3
- min.insync.replicas: 2
- retention.ms: 604800000 for 7 days
- compression.type: lz4

## Postgres/PostGIS Tuning

- Enable PostGIS extension through Alembic.
- Keep GiST index on `locations.geom`.
- Partition `locations` monthly or daily for very high volume.
- Move hot telemetry to TimescaleDB hypertables when ingest exceeds normal Postgres write comfort.
- Set `shared_buffers` near 25 percent of RAM on self-managed hosts.

## Blue/Green And Canary

Use Helm value overrides for canary images:

```bash
helm upgrade --install nova-gps k8s/helm/nova-gps \
  --namespace nova-gps --create-namespace \
  --set image.api.tag=$GIT_SHA \
  --set image.frontend.tag=$GIT_SHA \
  --wait
```

For stricter canary, split deployments by label and route 5 percent of traffic through ingress or service mesh weights.

## Troubleshooting

- API 500 on `/health`: check `DATABASE_URL` and PostGIS migration.
- Locations rejected: confirm an active `Consent` exists for the device.
- Kafka bridge quiet: check topic name and broker address.
- MQTT messages ignored: payload must include `device_id` or `identifier`, `latitude`, and `longitude`.

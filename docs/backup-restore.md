# Backup And Restore

## Postgres

Daily logical backup:

```bash
pg_dump "$DATABASE_URL" --format=custom --file=nova_gps_$(date -u +%Y%m%dT%H%M%SZ).dump
aws s3 cp nova_gps_*.dump s3://nova-gps-prod-backups/postgres/
```

Point-in-time recovery:

- Enable managed Postgres automated backups.
- Retain WAL for your recovery window.
- Test restore monthly into a non-production account.

Restore:

```bash
createdb nova_gps_restore
pg_restore --dbname=nova_gps_restore nova_gps_YYYYMMDD.dump
```

## Kafka

- Prefer managed Kafka snapshots where available.
- Keep topic retention long enough for downstream recovery.
- Mirror topics to a second region with MirrorMaker 2 for disaster recovery.

## Disaster Recovery

Targets:

- RPO: 15 minutes for database, 1 hour for Kafka unless using managed replication.
- RTO: 4 hours for regional restore.

Runbook:

1. Freeze writes if data corruption is suspected.
2. Restore Postgres into a new instance.
3. Repoint `DATABASE_URL` secret.
4. Replay Kafka from retained offsets if needed.
5. Run audit checks and consent consistency queries.

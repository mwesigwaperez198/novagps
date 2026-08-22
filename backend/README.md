# NOVA Backend

FastAPI services for consent-first device registration, GPS ingestion, Kafka streaming, WebSocket broadcasting, MQTT forwarding, geofence workers, and sandboxed diagnostics.

## Commands

```bash
alembic upgrade head
uvicorn main:app --reload
python kafka_consumer.py
python kafka_to_ws.py
python mqtt_consumer.py
```

## Security Notes

- `ENVIRONMENT=development` allows unauthenticated local API calls as `dev-admin@nova.local`.
- `ENVIRONMENT=production` requires bearer JWTs containing `sub` and `role` claims.
- `/diagnose` never accepts shell text. It accepts immutable command IDs from `command_registry.py`.
- Set `SANDBOX_EXECUTOR_MODE=docker` only on a hardened executor host that can run isolated containers safely.

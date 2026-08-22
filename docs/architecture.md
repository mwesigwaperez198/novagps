# Architecture

## Components

- Frontend: React terminal dashboard with DeviceList, MapPanel, Diagnostics, BroadcastController, and AlertsLog.
- API: FastAPI service for registration, consent, location ingestion, search, diagnostics, broadcasts, imports, retention, and deletion.
- Postgres/PostGIS: canonical device, consent, audit, imported user, broadcast, and telemetry store.
- Kafka: live telemetry stream on `nova.locations`.
- Worker: Kafka consumer for geofence checks, analytics, alerting, and device-type pipelines.
- Kafka to WebSocket bridge: streams authorized map and terminal data to viewers.
- MQTT consumer: forwards IoT payloads from `nova/locations/#` into the API.
- Command registry: immutable diagnostics registry with sandboxed execution.

## Data Flow

```text
mobile/traccar/iot -> API /update-location -> PostGIS
                                      |
                                      v
                                Kafka nova.locations
                                      |
                         +------------+-------------+
                         v                          v
                    geofence worker           websocket bridge
                         |                          |
                         v                          v
                    alerts/logs              terminal dashboard
```

## Consent Gate

Location ingestion resolves a device by `device_id` or `identifier`, checks for an active `Consent`, writes `Location`, records `AuditLog`, then publishes Kafka. Without consent, the API returns `403`.

## Device Types

Supported values:

- `vehicle`
- `motorcycle`
- `phone`
- `laptop`
- `other`

Workers branch telemetry handling by type so vehicle and motorcycle pipelines can focus on motion and route analytics while phone and laptop pipelines can focus on portable-device state and source validation.

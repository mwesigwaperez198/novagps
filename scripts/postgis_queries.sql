-- Devices currently inside a geofence polygon.
SELECT d.id, d.name, d.device_type, l.recorded_at
FROM devices d
JOIN LATERAL (
  SELECT *
  FROM locations
  WHERE locations.device_id = d.id
  ORDER BY recorded_at DESC
  LIMIT 1
) l ON true
WHERE ST_Contains(
  ST_GeomFromText('POLYGON((-122.42 37.77,-122.40 37.77,-122.40 37.79,-122.42 37.79,-122.42 37.77))', 4326),
  l.geom
);

-- Last 24 hours for one device with spatial order intact.
SELECT latitude, longitude, speed, heading, recorded_at
FROM locations
WHERE device_id = :device_id
  AND recorded_at >= now() - interval '24 hours'
ORDER BY recorded_at ASC;

-- Retention preview before deletion.
SELECT count(*) AS expired_locations
FROM locations
WHERE recorded_at < now() - interval '365 days';

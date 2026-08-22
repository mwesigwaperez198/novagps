const DEFAULT_ORIGIN = { latitude: 37.7749, longitude: -122.4194 };
const METERS_PER_DEGREE_LATITUDE = 111_320;
const SCENE_UNIT_METERS = 14;

export function asNumber(value) {
  const next = Number(value);
  return Number.isFinite(next) ? next : null;
}

export function normalizeLocation(location) {
  if (!location) return null;
  const latitude = asNumber(location.latitude);
  const longitude = asNumber(location.longitude);
  if (latitude === null || longitude === null) return null;
  return {
    ...location,
    latitude,
    longitude,
    altitude: asNumber(location.altitude),
    speed: asNumber(location.speed),
    heading: asNumber(location.heading),
    accuracy: asNumber(location.accuracy),
  };
}

export function samePoint(left, right) {
  return (
    left &&
    right &&
    Math.abs(left.latitude - right.latitude) < 0.000001 &&
    Math.abs(left.longitude - right.longitude) < 0.000001 &&
    left.recorded_at === right.recorded_at
  );
}

export function chooseOrigin(points) {
  const latest = points[points.length - 1];
  return latest ? { latitude: latest.latitude, longitude: latest.longitude } : DEFAULT_ORIGIN;
}

export function projectLocation(location, origin) {
  const latitudeScale = METERS_PER_DEGREE_LATITUDE;
  const longitudeScale = METERS_PER_DEGREE_LATITUDE * Math.cos((origin.latitude * Math.PI) / 180);
  const x = ((location.longitude - origin.longitude) * longitudeScale) / SCENE_UNIT_METERS;
  const z = -((location.latitude - origin.latitude) * latitudeScale) / SCENE_UNIT_METERS;
  const altitude = location.altitude ?? 0;
  const speedLift = location.speed ? Math.min(location.speed / 8, 5) : 0;
  const y = 4 + Math.max(0, altitude) / 18 + speedLift;
  return { ...location, x, y, z };
}

export function getMapBounds(points) {
  if (!points.length) {
    return { minX: -1, maxX: 1, minY: -1, maxY: 1 };
  }

  let minX = points[0].x;
  let maxX = points[0].x;
  let minY = points[0].z;
  let maxY = points[0].z;

  points.forEach((point) => {
    minX = Math.min(minX, point.x);
    maxX = Math.max(maxX, point.x);
    minY = Math.min(minY, point.z);
    maxY = Math.max(maxY, point.z);
  });

  const spanX = Math.max(1, maxX - minX);
  const spanY = Math.max(1, maxY - minY);
  return { minX, maxX, minY, maxY, spanX, spanY };
}

export function toDisplayCoordinates(points, padding = 12) {
  if (!points.length) return [];

  const { minX, maxX, minY, maxY, spanX, spanY } = getMapBounds(points);
  const safePadding = padding / 100;
  const widthSpan = Math.max(spanX, 1) + safePadding * 2;
  const heightSpan = Math.max(spanY, 1) + safePadding * 2;

  return points.map((point) => {
    const x = ((point.x - minX) / widthSpan) * 100;
    const y = ((maxY - point.z) / heightSpan) * 100;
    return { ...point, displayX: x, displayY: y };
  });
}

export const KAMPALA = { latitude: 0.3476, longitude: 32.5825 };

export function relativeTime(isoDate) {
  if (!isoDate) return null;
  const then = new Date(isoDate).getTime();
  if (Number.isNaN(then)) return null;
  const seconds = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (seconds < 10) return "now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hr ago`;
  return `${Math.floor(hours / 24)} days ago`;
}

export function clockTime(isoDate) {
  if (!isoDate) return null;
  const date = new Date(isoDate);
  if (Number.isNaN(date.getTime())) return null;
  return date.toLocaleTimeString();
}

export function isLive(location) {
  if (!location?.recorded_at) return false;
  const then = new Date(location.recorded_at).getTime();
  return Number.isFinite(then) && Date.now() - then < 60_000;
}

// Fetch the viewer's actual position (used when a device has no real fix yet).
// Returns the precise GPS point with the browser's real accuracy estimate.
export function getViewerLocation() {
  if (typeof navigator === "undefined" || !navigator.geolocation) return Promise.resolve(null);
  return new Promise((resolve) => {
    navigator.geolocation.getCurrentPosition(
      (position) =>
        resolve({
          latitude: position.coords.latitude,
          longitude: position.coords.longitude,
          accuracy: position.coords.accuracy,
          altitude: position.coords.altitude,
          speed: position.coords.speed,
          heading: position.coords.heading,
        }),
      () => resolve(null),
      { enableHighAccuracy: true, timeout: 8000 },
    );
  });
}

// Records ONE real, exact point for a device that has no live telemetry yet,
// using the person's actual GPS position. No synthetic movement, no fake
// speeds, no mock routes - just a single precise fix through the real ingest
// pipeline (active consent required, same as a hardware tracker).
export async function reportViewerLocation(device, api, anchor = null) {
  if (!device?.identifier) throw new Error("Device has no identifier");
  const point = anchor || (await getViewerLocation());
  if (!point?.latitude || !point?.longitude) {
    throw new Error("No GPS fix available. Grant location access on this device first.");
  }
  await api.updateLocation({
    identifier: device.identifier,
    latitude: Number(point.latitude.toFixed(7)),
    longitude: Number(point.longitude.toFixed(7)),
    accuracy: Number(point.accuracy ?? 8),
    altitude: point.altitude,
    source: "mobile",
    raw_payload: { viewer_reported: true, precision_m: point.accuracy ?? null },
  });
}

export function speedColor(speed) {
  if (speed === null || speed === undefined) return "#40d7ff";
  if (speed < 20) return "#29e06b";
  if (speed < 50) return "#f2d96b";
  if (speed < 80) return "#f2896b";
  return "#e04040";
}
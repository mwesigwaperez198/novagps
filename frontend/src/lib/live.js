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

// Streams a short synthetic trip for a device with no real signal so the
// map, telemetry and analytics go live during demos. Uses the real
// /update-location endpoint (active consent required on the device).
export async function simulateMotion(device, api) {
  if (!device?.identifier) throw new Error("Device has no identifier");
  const anchor = device.latest_location
    ? {
        latitude: Number(device.latest_location.latitude),
        longitude: Number(device.latest_location.longitude),
      }
    : KAMPALA;
  const speeds = [12, 24, 38, 52, 61, 47, 33, 19];
  let currentLat = anchor.latitude;
  let currentLon = anchor.longitude;
  for (const [index, speed] of speeds.entries()) {
    currentLat += 0.0009 + Math.sin(index * 1.7) * 0.0004;
    currentLon += 0.0026 + Math.cos(index * 1.3) * 0.0005;
    await api.updateLocation({
      identifier: device.identifier,
      latitude: Number(currentLat.toFixed(6)),
      longitude: Number(currentLon.toFixed(6)),
      altitude: 1180,
      speed,
      heading: 122,
      accuracy: 6,
      source: "mobile",
      raw_payload: { simulated: true, seq: index + 1 },
    });
  }
}

export function speedColor(speed) {
  if (speed === null || speed === undefined) return "#40d7ff";
  if (speed < 20) return "#29e06b";
  if (speed < 50) return "#f2d96b";
  if (speed < 80) return "#f2896b";
  return "#e04040";
}
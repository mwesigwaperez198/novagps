import { describe, it, expect } from "vitest";

describe("mapView helpers", () => {
  it("normalizes and projects a location to scene coordinates", async () => {
    const { chooseOrigin, normalizeLocation, projectLocation } = await import("./mapView.js");
    const input = { latitude: 37.7749, longitude: -122.4194, altitude: 120, speed: 32, heading: 45, accuracy: 10 };
    const normalized = normalizeLocation(input);
    const origin = chooseOrigin([normalized]);
    const projected = projectLocation(normalized, origin);
    expect(normalized).toMatchObject({ latitude: 37.7749, longitude: -122.4194, altitude: 120, speed: 32, heading: 45, accuracy: 10 });
    expect(projected.x).toBeCloseTo(0, 6);
    expect(projected.z).toBeCloseTo(0, 6);
    expect(projected.y).toBeGreaterThan(4);
  });

  it("detects identical points", async () => {
    const { samePoint } = await import("./mapView.js");
    const pointA = { latitude: 1, longitude: 2, altitude: 0, speed: 0, heading: 0, accuracy: 5, recorded_at: "a" };
    const pointB = { latitude: 1, longitude: 2, altitude: 0, speed: 0, heading: 0, accuracy: 5, recorded_at: "a" };
    expect(samePoint(pointA, pointB)).toBe(true);
  });

  it("detects different points", async () => {
    const { samePoint } = await import("./mapView.js");
    const pointA = { latitude: 1, longitude: 2, altitude: 0, speed: 0, heading: 0, accuracy: 5, recorded_at: "a" };
    const pointB = { latitude: 1, longitude: 3, altitude: 0, speed: 0, heading: 0, accuracy: 5, recorded_at: "a" };
    expect(samePoint(pointA, pointB)).toBe(false);
  });

  it("toDisplayCoordinates returns correct length", async () => {
    const { toDisplayCoordinates } = await import("./mapView.js");
    const points = [
      { x: 0, z: 0 },
      { x: 10, z: 20 },
      { x: 20, z: 10 },
    ];
    expect(toDisplayCoordinates(points)).toHaveLength(3);
  });

  it("toDisplayCoordinates handles empty array", async () => {
    const { toDisplayCoordinates } = await import("./mapView.js");
    expect(toDisplayCoordinates([])).toHaveLength(0);
  });

  it("chooseOrigin returns last point when multiple", async () => {
    const { chooseOrigin, normalizeLocation } = await import("./mapView.js");
    const locs = [
      normalizeLocation({ latitude: 10.0, longitude: 20.0 }),
      normalizeLocation({ latitude: 30.0, longitude: 40.0 }),
    ];
    const origin = chooseOrigin(locs);
    expect(origin.latitude).toBeCloseTo(30.0);
    expect(origin.longitude).toBeCloseTo(40.0);
  });

  it("chooseOrigin returns default when empty", async () => {
    const { chooseOrigin } = await import("./mapView.js");
    const origin = chooseOrigin([]);
    expect(origin.latitude).toBeDefined();
    expect(origin.longitude).toBeDefined();
  });

  it("normalizeLocation returns null for invalid input", async () => {
    const { normalizeLocation } = await import("./mapView.js");
    expect(normalizeLocation(null)).toBeNull();
    expect(normalizeLocation({})).toBeNull();
    expect(normalizeLocation({ latitude: "bad", longitude: 1 })).toBeNull();
  });

  it("projectLocation scales correctly", async () => {
    const { normalizeLocation, projectLocation } = await import("./mapView.js");
    const origin = { latitude: 0, longitude: 0 };
    const loc = normalizeLocation({ latitude: 1, longitude: 1 });
    const projected = projectLocation(loc, origin);
    expect(projected.x).toBeGreaterThan(0);
    expect(projected.z).toBeLessThan(0);
  });
});

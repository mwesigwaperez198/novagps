import { describe, it, expect } from "vitest";
import { chooseOrigin, normalizeLocation, projectLocation, samePoint, toDisplayCoordinates } from "./mapView.js";

describe("mapView helpers", () => {
  it("normalizes and projects a location to scene coordinates", () => {
    const input = { latitude: 37.7749, longitude: -122.4194, altitude: 120, speed: 32, heading: 45, accuracy: 10 };
    const normalized = normalizeLocation(input);
    const origin = chooseOrigin([normalized]);
    const projected = projectLocation(normalized, origin);

    expect(normalized).toMatchObject({ latitude: 37.7749, longitude: -122.4194, altitude: 120, speed: 32, heading: 45, accuracy: 10 });
    expect(projected.x).toBeCloseTo(0, 6);
    expect(projected.z).toBeCloseTo(0, 6);
    expect(projected.y).toBeGreaterThan(4);
  });

  it("detects identical points and converts to display coordinates", () => {
    const pointA = { latitude: 1, longitude: 2, altitude: 0, speed: 0, heading: 0, accuracy: 5, recorded_at: "a" };
    const pointB = { latitude: 1, longitude: 2, altitude: 0, speed: 0, heading: 0, accuracy: 5, recorded_at: "a" };
    const projected = [
      { x: 0, z: 0 },
      { x: 10, z: 20 },
      { x: 20, z: 10 },
    ];

    expect(samePoint(pointA, pointB)).toBe(true);
    expect(toDisplayCoordinates(projected)).toHaveLength(3);
  });
});

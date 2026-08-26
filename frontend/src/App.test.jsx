import { describe, it, expect } from "vitest";

function hashLine(value) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  let hash = 0;
  for (let index = 0; index < text.length; index += 1) {
    hash = (hash << 5) - hash + text.charCodeAt(index);
    hash |= 0;
  }
  return `#${Math.abs(hash).toString(16).padStart(8, "0")}`;
}

describe("hashLine utility", () => {
  it("produces consistent hex output", () => {
    const h1 = hashLine("BOOT");
    const h2 = hashLine("BOOT");
    expect(h1).toBe(h2);
    expect(h1).toMatch(/^#[0-9a-f]{8}$/);
  });

  it("produces different hashes for different inputs", () => {
    const h1 = hashLine("ONLINE");
    const h2 = hashLine("DEGRADED");
    expect(h1).not.toBe(h2);
  });

  it("handles non-string input", () => {
    const h = hashLine({ event: "test" });
    expect(h).toMatch(/^#[0-9a-f]{8}$/);
  });

  it("handles empty string", () => {
    const h = hashLine("");
    expect(h).toMatch(/^#[0-9a-f]{8}$/);
  });

  it("handles numbers", () => {
    const h = hashLine(42);
    expect(h).toMatch(/^#[0-9a-f]{8}$/);
  });
});

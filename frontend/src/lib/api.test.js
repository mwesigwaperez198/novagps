import { describe, it, expect, vi, beforeEach } from "vitest";

const mockFetch = vi.fn();
global.fetch = mockFetch;

beforeEach(() => {
  mockFetch.mockReset();
});

describe("api.js", () => {
  it("health endpoint calls GET /health", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ status: "ok" }),
    });
    const { api } = await import("./api.js");
    const result = await api.health();
    expect(result.status).toBe("ok");
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining("/health"),
      expect.objectContaining({ headers: expect.anything() }),
    );
  });

  it("login sends POST with credentials", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ access_token: "tok123", token_type: "bearer" }),
    });
    const { api } = await import("./api.js");
    const result = await api.login({ username: "admin", password: "pass" });
    expect(result.access_token).toBe("tok123");
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining("/auth/login"),
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("devices endpoint calls GET /devices", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => [{ id: "d1", name: "Tracker" }],
    });
    const { api } = await import("./api.js");
    const result = await api.devices();
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe("d1");
  });

  it("search encodes query parameter", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => [],
    });
    const { api } = await import("./api.js");
    await api.search("test query");
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining("q=test%20query"),
      expect.anything(),
    );
  });

  it("register sends POST with device payload", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ id: "new-1", name: "New Device" }),
    });
    const { api } = await import("./api.js");
    const result = await api.register({ name: "New Device", email: "a@b.com", phone: "+123" });
    expect(result.id).toBe("new-1");
  });

  it("consent sends POST", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ status: "accepted" }),
    });
    const { api } = await import("./api.js");
    const result = await api.consent({ device_id: "d1", source: "manual", scope: "gps" });
    expect(result.status).toBe("accepted");
  });

  it("diagnose sends POST with command_id", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ exit_code: 0, output: "ok" }),
    });
    const { api } = await import("./api.js");
    const result = await api.diagnose({ command_id: "system.health" });
    expect(result.exit_code).toBe(0);
  });

  it("broadcast sends POST", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ token: "abc" }),
    });
    const { api } = await import("./api.js");
    const result = await api.broadcast({ channel: "map", scope: "viewer" });
    expect(result.token).toBe("abc");
  });

  it("auditLogs calls GET with limit", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => [],
    });
    const { api } = await import("./api.js");
    await api.auditLogs(25);
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining("limit=25"),
      expect.anything(),
    );
  });

  it("geofences calls GET /geofences", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => [{ geofence_id: "f1" }],
    });
    const { api } = await import("./api.js");
    const result = await api.geofences();
    expect(result).toHaveLength(1);
  });

  it("throws on non-ok response", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      statusText: "Internal Server Error",
      json: async () => ({ detail: "something broke" }),
    });
    const { api } = await import("./api.js");
    await expect(api.health()).rejects.toThrow("something broke");
  });

  it("throws on network error with fallback message", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      statusText: "Bad Request",
      json: async () => ({}),
    });
    const { api } = await import("./api.js");
    await expect(api.health()).rejects.toThrow("Bad Request");
  });

  it("setAuthToken stores and getAuthToken retrieves", async () => {
    const { setAuthToken, getAuthToken } = await import("./api.js");
    setAuthToken("my-token");
    expect(getAuthToken()).toBe("my-token");
    expect(localStorage.getItem("nova_token")).toBe("my-token");
  });

  it("setAuthToken(null) clears token", async () => {
    const { setAuthToken, getAuthToken } = await import("./api.js");
    setAuthToken("temp");
    setAuthToken(null);
    expect(getAuthToken()).toBeNull();
    expect(localStorage.getItem("nova_token")).toBeNull();
  });

  it("Authorization header is set when token exists", async () => {
    const { setAuthToken, api } = await import("./api.js");
    setAuthToken("test-bearer");
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ status: "ok" }),
    });
    await api.health();
    const callHeaders = mockFetch.mock.calls[0][1].headers;
    expect(callHeaders["Authorization"]).toBe("Bearer test-bearer");
  });
});

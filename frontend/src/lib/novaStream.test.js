import { describe, it, expect, vi, beforeEach } from "vitest";

const mockFetch = vi.fn();
global.fetch = mockFetch;

beforeEach(() => {
  mockFetch.mockReset();
});

function readerFrom(rawFrames) {
  const encoder = new TextEncoder();
  const chunks = rawFrames.map((f) => encoder.encode(f));
  let index = 0;
  return {
    getReader: () => ({
      read: async () =>
        index < chunks.length
          ? { value: chunks[index++], done: false }
          : { value: undefined, done: true },
    }),
  };
}

describe("novaAgentStream", () => {
  it("posts to the stream endpoint and emits parsed frames in order", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      body: readerFrom([
        'event: status\ndata: {"state":"thinking"}\n\n',
        'event: thought\ndata: {"index":0,"text":"parse the request"}\n\n',
        'event: tool\ndata: {"name":"port_scan"}\n\n',
        'event: token\ndata: {"text":"Hel"}\n\n',
        'event: token\ndata: {"text":"lo"}\n\n',
        'event: done\ndata: {"engine":"deterministic_shield","tools_executed":["port_scan"]}\n\n',
      ]),
    });

    const { novaAgentStream } = await import("./api.js");
    const events = [];
    await novaAgentStream("scan ports", "dev-1", { onEvent: (e) => events.push(e) });

    expect(events.map((e) => e.event)).toEqual([
      "status", "thought", "tool", "token", "token", "done",
    ]);
    expect(events[3].data.text).toBe("Hel");
    const [url, options] = mockFetch.mock.calls[0];
    expect(url).toContain("/nova-core/agent/stream");
    expect(options.method).toBe("POST");
    expect(JSON.parse(options.body)).toEqual({ command: "scan ports", device_id: "dev-1" });
  });

  it("reassembles a frame split across two network chunks", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      body: readerFrom(['event: token\ndata: {"text":"ab', 'c"}\n\n']),
    });

    const { novaAgentStream } = await import("./api.js");
    const events = [];
    await novaAgentStream("hi", "", { onEvent: (e) => events.push(e) });

    expect(events).toHaveLength(1);
    expect(events[0].data.text).toBe("abc");
  });

  it("throws when the server responds with an error status", async () => {
    mockFetch.mockResolvedValueOnce({ ok: false, status: 500, statusText: "Server Error" });
    const { novaAgentStream } = await import("./api.js");
    await expect(novaAgentStream("x", "")).rejects.toThrow("Server Error");
  });
});

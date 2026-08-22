const isDev = Boolean(import.meta.env.DEV);
const API_URL = import.meta.env.VITE_API_URL || (isDev ? "http://localhost:8000" : "");
const wsProtocol = typeof location !== "undefined" && location.protocol === "https:" ? "wss" : "ws";
export const WS_URL =
  import.meta.env.VITE_WS_URL ||
  (isDev ? "ws://localhost:8765" : `${wsProtocol}://${typeof location !== "undefined" ? location.host : "127.0.0.1:8000"}/ws`);

async function request(path, options = {}) {
  const response = await fetch(`${API_URL}${path}`, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || response.statusText);
  }
  return data;
}

export const api = {
  health: () => request("/health"),
  devices: () => request("/devices"),
  locations: (deviceId, limit = 160) => request(`/devices/${encodeURIComponent(deviceId)}/locations?limit=${limit}`),
  register: (payload) => request("/register", { method: "POST", body: JSON.stringify(payload) }),
  diagnose: (payload) => request("/diagnose", { method: "POST", body: JSON.stringify(payload) }),
  tools: () => request("/diagnose/tools"),
  broadcast: (payload) => request("/broadcast", { method: "POST", body: JSON.stringify(payload) }),
};

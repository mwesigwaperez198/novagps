const isDev = Boolean(import.meta.env.DEV);
const API_URL = import.meta.env.VITE_API_URL || (isDev ? "http://localhost:8000" : "");
const wsProtocol = typeof location !== "undefined" && location.protocol === "https:" ? "wss" : "ws";
export const WS_URL =
  import.meta.env.VITE_WS_URL ||
  (isDev ? "ws://localhost:8765" : `${wsProtocol}://${typeof location !== "undefined" ? location.host : "127.0.0.1:8000"}/ws`);

let authToken = localStorage.getItem("nova_token") || null;

export function setAuthToken(token) {
  authToken = token;
  if (token) {
    localStorage.setItem("nova_token", token);
  } else {
    localStorage.removeItem("nova_token");
  }
}

export function getAuthToken() {
  return authToken;
}

async function request(path, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };
  if (authToken) {
    headers["Authorization"] = `Bearer ${authToken}`;
  }
  const response = await fetch(`${API_URL}${path}`, {
    ...options,
    headers,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || response.statusText);
  }
  return data;
}

export const api = {
  health: () => request("/health"),
  login: (payload) => request("/auth/login", { method: "POST", body: JSON.stringify(payload) }),
  devices: () => request("/devices"),
  search: (q) => request(`/search?q=${encodeURIComponent(q)}`),
  locations: (deviceId, limit = 160) => request(`/devices/${encodeURIComponent(deviceId)}/locations?limit=${limit}`),
  register: (payload) => request("/register", { method: "POST", body: JSON.stringify(payload) }),
  consent: (payload) => request("/consent", { method: "POST", body: JSON.stringify(payload) }),
  consentRevoke: (payload) => request("/consent/revoke", { method: "POST", body: JSON.stringify(payload) }),
  diagnose: (payload) => request("/diagnose", { method: "POST", body: JSON.stringify(payload) }),
  tools: () => request("/diagnose/tools"),
  broadcast: (payload) => request("/broadcast", { method: "POST", body: JSON.stringify(payload) }),
  auditLogs: (limit = 100) => request(`/audit-logs?limit=${limit}`),
  cameraDiscover: (subnet) => request(`/camera/discover?subnet=${encodeURIComponent(subnet)}`),
  cameraScreenshot: (rtspUrl) => request(`/camera/screenshot?rtsp_url=${encodeURIComponent(rtspUrl)}`),
  cameraRecord: (rtspUrl, duration = 30) => request(`/camera/record?rtsp_url=${encodeURIComponent(rtspUrl)}&duration=${duration}`, { method: "POST" }),
  vpnStatus: () => request("/vpn/status"),
  vpnConnect: (configPath, vpnType = "wireguard") => request(`/vpn/connect?config_path=${encodeURIComponent(configPath)}&vpn_type=${vpnType}`, { method: "POST" }),
  vpnDisconnect: (iface, vpnType = "wireguard") => request(`/vpn/disconnect?interface=${encodeURIComponent(iface)}&vpn_type=${vpnType}`, { method: "POST" }),
  idsStatus: () => request("/ids/status"),
  idsAlerts: (limit = 50) => request(`/ids/alerts?limit=${limit}`),
  idsUpdateRules: () => request("/ids/update-rules", { method: "POST" }),
  osintWhois: (domain) => request(`/osint/whois?domain=${encodeURIComponent(domain)}`),
  osintDnsBrute: (domain) => request(`/osint/dns-brute?domain=${encodeURIComponent(domain)}`),
  osintReverseDns: (ip) => request(`/osint/reverse-dns?ip=${encodeURIComponent(ip)}`),
  osintHttpHeaders: (url) => request(`/osint/http-headers?url=${encodeURIComponent(url)}`),
  osintNikto: (target) => request(`/osint/nikto?target=${encodeURIComponent(target)}`),
  osintSqlmap: (url) => request(`/osint/sqlmap?url=${encodeURIComponent(url)}`),
  osintTheharvester: (domain) => request(`/osint/theharvester?domain=${encodeURIComponent(domain)}`),
  osintWhatweb: (url) => request(`/osint/whatweb?url=${encodeURIComponent(url)}`),
  osintWpscan: (url) => request(`/osint/wpscan?url=${encodeURIComponent(url)}`),
  osintDirb: (url) => request(`/osint/dirb?url=${encodeURIComponent(url)}`),
  osintSublist3r: (domain) => request(`/osint/sublist3r?domain=${encodeURIComponent(domain)}`),
  pentestVulnScan: (target) => request(`/pentest/vuln-scan?target=${encodeURIComponent(target)}`),
  pentestAuthScan: (target) => request(`/pentest/auth-scan?target=${encodeURIComponent(target)}`),
  osintPhoneLookup: (phone, countryCode = "") => request(`/osint/phone-lookup?phone=${encodeURIComponent(phone)}&country_code=${encodeURIComponent(countryCode)}`),
  osintEmailLookup: (email) => request(`/osint/email-lookup?email=${encodeURIComponent(email)}`),
  toolRun: (commandId, params = {}) => {
    const qs = new URLSearchParams({ command_id: commandId, ...params });
    return request(`/tool/run?${qs}`, { method: "POST" });
  },
  geofences: () => request("/geofences"),
};

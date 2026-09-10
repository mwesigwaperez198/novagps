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
  getDevice: (deviceId) => request(`/devices/${encodeURIComponent(deviceId)}`),
  search: (q) => request(`/search?q=${encodeURIComponent(q)}`),
  locations: (deviceId, limit = 160) => request(`/devices/${encodeURIComponent(deviceId)}/locations?limit=${limit}`),
  updateLocation: (payload) => request("/update-location", { method: "POST", body: JSON.stringify(payload) }),
  register: (payload) => request("/register", { method: "POST", body: JSON.stringify(payload) }),
  consent: (payload) => request("/consent", { method: "POST", body: JSON.stringify(payload) }),
  consentRevoke: (payload) => request("/consent/revoke", { method: "POST", body: JSON.stringify(payload) }),
  consentHistory: (deviceId, limit = 50) => request(`/consent/history?device_id=${encodeURIComponent(deviceId)}&limit=${limit}`),
  consentVerifyChain: (limit = 1000) => request(`/consent/verify-chain?limit=${limit}`),
  diagnose: (payload) => request("/diagnose", { method: "POST", body: JSON.stringify(payload) }),
  tools: () => request("/diagnose/tools"),
  broadcast: (payload) => request("/broadcast", { method: "POST", body: JSON.stringify(payload) }),
  auditLogs: (limit = 100) => request(`/audit-logs?limit=${limit}`),
  logs: (kind = null, severity = null, limit = 100) => {
    const params = new URLSearchParams({ limit });
    if (kind) params.set("kind", kind);
    if (severity) params.set("severity", severity);
    return request(`/logs?${params}`);
  },
  observatory: () => request("/observatory/summary"),
  novaEngineStatus: () => request("/nova-core/engine/status"),
  novaEngineInit: (force = false) => request("/nova-core/engine/init", { method: "POST", body: JSON.stringify({ force }) }),
  novaTelemetryVerify: (packet) => request("/nova-core/telemetry/verify", { method: "POST", body: JSON.stringify({ packet }) }),
  novaQuery: (query) => request("/nova-core/query", { method: "POST", body: JSON.stringify({ query }) }),
  novaShieldValidate: () => request("/nova-core/shield/validate", { method: "POST" }),
  novaShieldEmit: (prompt) => request("/nova-core/shield/emit", { method: "POST", body: JSON.stringify({ prompt }) }),
  novaAgentDispatch: (command, deviceId = "") => request("/nova-core/agent/dispatch", { method: "POST", body: JSON.stringify({ command, device_id: deviceId }) }),
  cameraDiscover: (subnet) => request(`/camera/discover?subnet=${encodeURIComponent(subnet)}`),
  cameraScreenshot: (rtspUrl) => request(`/camera/screenshot?rtsp_url=${encodeURIComponent(rtspUrl)}`, { method: "POST" }),
  cameraRecord: (rtspUrl, duration = 30) => request(`/camera/record?rtsp_url=${encodeURIComponent(rtspUrl)}&duration=${duration}`, { method: "POST" }),
  vpnStatus: () => request("/vpn/status"),
  vpnConfig: () => request("/vpn/config"),
  vpnConnect: (configPath, vpnType = "wireguard") => request(`/vpn/connect?config_path=${encodeURIComponent(configPath || "")}&vpn_type=${vpnType}`, { method: "POST" }),
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
  remoteSms: (deviceId, message) => request(`/remote/sms?device_id=${encodeURIComponent(deviceId)}&message=${encodeURIComponent(message)}`, { method: "POST" }),
  remoteLockGuide: (deviceId) => request(`/remote/lock-guide?device_id=${encodeURIComponent(deviceId)}`, { method: "POST" }),
  remoteIcloud: () => request("/remote/icloud-instructions"),
  remoteAndroid: () => request("/remote/android-instructions"),
  toolRun: (commandId, params = {}) => {
    const qs = new URLSearchParams({ command_id: commandId, ...params });
    return request(`/tool/run?${qs}`, { method: "POST" });
  },
  geofences: () => request("/geofences"),
  getGeofence: (id) => request(`/geofences/${encodeURIComponent(id)}`),

  // Fingerprinting
  deviceFingerprint: (deviceId) => request(`/device/${encodeURIComponent(deviceId)}/fingerprint`),
  fingerprintIp: (ip) => request(`/fingerprint/ip/${encodeURIComponent(ip)}`, { method: "POST" }),
  deviceOui: (deviceId) => request(`/device/${encodeURIComponent(deviceId)}/oui`),

  // Discovery
  discoveryScanNetwork: (subnet = "192.168.1.0/24") => request(`/discovery/scan-network?subnet=${encodeURIComponent(subnet)}`, { method: "POST" }),
  discoveryUsb: () => request("/discovery/usb"),
  discoveryArp: () => request("/discovery/arp"),

  // Device commands
  deviceCommands: (deviceId, limit = 20) => request(`/device/${encodeURIComponent(deviceId)}/commands?limit=${limit}`),
  devicePendingCommands: (deviceId) => request(`/device/${encodeURIComponent(deviceId)}/commands/pending`),
  deviceTriggerLocate: (deviceId) => request(`/device/${encodeURIComponent(deviceId)}/trigger-locate`, { method: "POST" }),

  // Remote commands
  remoteLock: (deviceId, message = "This device has been remotely locked.", contact = "") =>
    request(`/device/${encodeURIComponent(deviceId)}/remote-lock?message=${encodeURIComponent(message)}&contact=${encodeURIComponent(contact)}`, { method: "POST" }),
  remoteWipe: (deviceId, confirmCode = "") =>
    request(`/device/${encodeURIComponent(deviceId)}/remote-wipe?confirm_code=${encodeURIComponent(confirmCode)}`, { method: "POST" }),
  remoteLostMode: (deviceId, message = "This device is lost. Please call the owner.", contact = "", locationInterval = 30) =>
    request(`/device/${encodeURIComponent(deviceId)}/lost-mode?message=${encodeURIComponent(message)}&contact=${encodeURIComponent(contact)}&location_interval=${locationInterval}`, { method: "POST" }),
  remoteSendMessage: (deviceId, message) =>
    request(`/device/${encodeURIComponent(deviceId)}/send-message?message=${encodeURIComponent(message)}`, { method: "POST" }),

  // WiFi security
  wifiScan: (iface = "wlan0") => request(`/wifi/scan?interface=${encodeURIComponent(iface)}`),
  wifiCaptureHandshake: (iface, bssid, duration = 30) =>
    request(`/wifi/capture-handshake?interface=${encodeURIComponent(iface)}&bssid=${encodeURIComponent(bssid)}&duration=${duration}`, { method: "POST" }),
  wifiCrackWpa: (captureFile, wordlist = "/usr/share/wordlists/rockyou.txt") =>
    request(`/wifi/crack-wpa?capture_file=${encodeURIComponent(captureFile)}&wordlist=${encodeURIComponent(wordlist)}`, { method: "POST" }),
  wifiWpsAttack: (iface, bssid) =>
    request(`/wifi/wps-attack?interface=${encodeURIComponent(iface)}&bssid=${encodeURIComponent(bssid)}`, { method: "POST" }),
  wifiDeauth: (iface, bssid, count = 5) =>
    request(`/wifi/deauth?interface=${encodeURIComponent(iface)}&bssid=${encodeURIComponent(bssid)}&count=${count}`, { method: "POST" }),

  // Firmware
  firmwareCve: (keyword, limit = 10) => request(`/firmware/cve?keyword=${encodeURIComponent(keyword)}&limit=${limit}`),
  firmwareDiagnose: (ip, manufacturer = "", model = "", firmwareVersion = "") =>
    request(`/firmware/diagnose/${encodeURIComponent(ip)}?manufacturer=${encodeURIComponent(manufacturer)}&model=${encodeURIComponent(model)}&firmware_version=${encodeURIComponent(firmwareVersion)}`),
  firmwareHealth: (ip) => request(`/firmware/health/${encodeURIComponent(ip)}`),

  // Vehicle recovery
  vehicleReportStolen: (deviceId) => request(`/vehicle/stolen-report?device_id=${encodeURIComponent(deviceId)}`, { method: "POST" }),
  vehicleRecoveryStatus: (recoveryId) => request(`/vehicle/recovery/${encodeURIComponent(recoveryId)}`),
  vehicleRecoveryAssets: (recoveryId) => request(`/vehicle/recovery/${encodeURIComponent(recoveryId)}/assets`),
  vehicleEndRecovery: (recoveryId) => request(`/vehicle/recovery/${encodeURIComponent(recoveryId)}/end`, { method: "POST" }),
  vehicleLinkCamera: (recoveryId, deviceId, cameraIp, cameraPort = 554, streamUrl = "") =>
    request(`/vehicle/recovery/${encodeURIComponent(recoveryId)}/link-camera?device_id=${encodeURIComponent(deviceId)}&camera_ip=${encodeURIComponent(cameraIp)}&camera_port=${cameraPort}&stream_url=${encodeURIComponent(streamUrl)}`, { method: "POST" }),
  vehicleActiveRecoveries: () => request("/vehicle/active-recoveries"),

  // Alerts
  alertsList: (limit = 50, severity = null, acknowledged = null) => {
    const params = new URLSearchParams({ limit });
    if (severity) params.set("severity", severity);
    if (acknowledged !== null) params.set("acknowledged", acknowledged);
    return request(`/alerts?${params}`);
  },
  alertAcknowledge: (alertId) => request(`/alerts/${encodeURIComponent(alertId)}/acknowledge`, { method: "POST" }),

  // Scheduled tasks
  taskSchedule: (name, cronExpr, commandId = "") =>
    request(`/tasks/schedule?name=${encodeURIComponent(name)}&cron_expr=${encodeURIComponent(cronExpr)}&command_id=${encodeURIComponent(commandId)}`, { method: "POST" }),
  tasksList: () => request("/tasks"),
  taskToggle: (taskId, enabled) =>
    request(`/tasks/${encodeURIComponent(taskId)}/toggle?enabled=${enabled}`, { method: "PUT" }),
  taskDelete: (taskId) => request(`/tasks/${encodeURIComponent(taskId)}`, { method: "DELETE" }),

  // Webhooks
  webhookRegister: (url, events = "location.updated,geofence.breach,vehicle.stolen") =>
    request(`/webhooks?url=${encodeURIComponent(url)}&events=${encodeURIComponent(events)}`, { method: "POST" }),
  webhooksList: () => request("/webhooks"),
  webhookDelete: (endpointId) => request(`/webhooks/${encodeURIComponent(endpointId)}`, { method: "DELETE" }),
  webhookDeliveries: (endpointId, limit = 50) =>
    request(`/webhooks/${encodeURIComponent(endpointId)}/deliveries?limit=${limit}`),

  // Analytics
  analyticsDashboard: () => request("/analytics/dashboard"),
  analyticsDevice: (deviceId) => request(`/analytics/device/${encodeURIComponent(deviceId)}`),
  analyticsFraud: (deviceId) => request(`/analytics/device/${encodeURIComponent(deviceId)}/fraud`),
  analyticsHeartbeat: (deviceId) => request(`/analytics/device/${encodeURIComponent(deviceId)}/heartbeat`),
  analyticsLocationStats: (deviceId) => request(`/analytics/device/${encodeURIComponent(deviceId)}/location-stats`),
  analyticsExport: (deviceId, format = "csv") => request(`/analytics/device/${encodeURIComponent(deviceId)}/export?format=${format}`),
};

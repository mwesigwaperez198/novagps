import { useEffect, useState } from "react";
import { Camera, Loader2, Network, Plug, Radio, RefreshCw, Satellite, Wifi } from "lucide-react";
import { api } from "../lib/api.js";

const TABS = [
  { id: "devices", label: "Devices", icon: Satellite },
  { id: "wifi", label: "WiFi", icon: Wifi },
  { id: "cameras", label: "Cameras", icon: Camera },
  { id: "ips", label: "IPs & Subnets", icon: Network },
];

function liveBadge(online) {
  return online ? <span className="status-ok">LIVE</span> : <span className="status-dim">OFFLINE</span>;
}

export default function ObservatoryPanel() {
  const [data, setData] = useState(null);
  const [tab, setTab] = useState("devices");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      setData(await api.observatory());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  const devices = data?.devices?.rows || [];
  const wifi = data?.wifi_networks || [];
  const cameras = data?.cameras_seen || [];
  const counts = data?.counts || {};

  return (
    <div className="panel-inner observatory-panel">
      <h3><Radio size={14} /> System Observatory</h3>
      <p className="muted">
        Everything the platform sees — not just your selected device: every reported device,
        WiFi network, camera and IP the system has tracked on its own.
      </p>

      {data && (
        <div className="obs-counts">
          {[
            { label: "Devices", value: data.devices.total },
            { label: "Online", value: data.devices.online },
            { label: "WiFi nets", value: counts.wifi },
            { label: "Cameras", value: counts.cameras },
            { label: "Public IPs", value: counts.public_ips },
            { label: "Local IPs", value: counts.local_ips },
            { label: "Subnets", value: counts.subnets },
          ].map((c) => (
            <div className="obs-count" key={c.label}>
              <strong>{c.value}</strong>
              <span>{c.label}</span>
            </div>
          ))}
        </div>
      )}

      <div className="tab-row" style={{ marginTop: 8 }}>
        {TABS.map((t) => (
          <button
            key={t.id}
            className={`tab-btn ${tab === t.id ? "active" : ""}`}
            onClick={() => setTab(t.id)}
            type="button"
          >
            <t.icon size={12} /> {t.label}
          </button>
        ))}
        <button onClick={load} disabled={loading} className="btn-secondary" type="button">
          {loading ? <Loader2 size={12} className="spin" /> : <RefreshCw size={12} />}
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}

      {tab === "devices" && (
        <div className="result-box" style={{ padding: 0 }}>
          <table className="data-table">
            <thead>
              <tr><th>Device</th><th>Type</th><th>Source</th><th>Status</th><th>Public IP</th><th>Local IP</th><th>Carrier</th><th>Recovery</th></tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.id}>
                  <td><code>{d.identifier}</code>{d.name !== `Auto-${d.identifier}` ? <div className="muted">{d.name}</div> : null}</td>
                  <td>{d.device_type}</td>
                  <td>{d.source === "traccar" ? "Traccar" : "Manual"}</td>
                  <td>{liveBadge(d.online)}</td>
                  <td className="muted">{d.ip_address || "—"}</td>
                  <td className="muted">{d.local_ip || "—"}</td>
                  <td className="muted">{d.carrier || "—"}</td>
                  <td><code>{d.recovery_id || "—"}</code></td>
                </tr>
              ))}
              {devices.length === 0 && <tr><td colSpan="8" className="empty">No devices yet.</td></tr>}
            </tbody>
          </table>
        </div>
      )}

      {tab === "wifi" && (
        <div className="result-box" style={{ padding: 0 }}>
          {wifi.length === 0 && <div className="empty-row">No WiFi networks reported by agents yet.</div>}
          <table className="data-table">
            <thead><tr><th>SSID</th><th>BSSID</th><th>Channel</th><th>Encryption</th><th>Strength</th></tr></thead>
            <tbody>
              {wifi.map((net, i) => (
                <tr key={`${net.ssid}-${i}`}>
                  <td><strong>{net.ssid}</strong></td>
                  <td className="muted">{net.bssid}</td>
                  <td>{net.channel || "—"}</td>
                  <td>{net.encryption}</td>
                  <td className="muted">{net.strength != null ? `${net.strength} dBm` : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === "cameras" && (
        <div className="result-box" style={{ padding: 0 }}>
          {cameras.length === 0 && <div className="empty-row">No cameras seen yet.</div>}
          <table className="data-table">
            <thead><tr><th>IP</th><th>Port</th><th>Protocol</th><th>Kind</th></tr></thead>
            <tbody>
              {cameras.map((cam) => (
                <tr key={`${cam.ip}-${cam.port}`}>
                  <td><code>{cam.ip}</code></td>
                  <td>{cam.port || "—"}</td>
                  <td>{cam.protocol}</td>
                  <td>{cam.kind || "camera"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === "ips" && (
        <div className="obs-ip-grid">
          <div className="result-box">
            <div className="scan-meta-row"><span><strong>Public IPs</strong> seen</span><span>{counts.public_ips}</span></div>
            <div className="obs-ip-list">
              {(data?.public_ips || []).map((ip) => <code key={ip}>{ip}</code>)}
            </div>
          </div>
          <div className="result-box">
            <div className="scan-meta-row"><span><strong>Local IPs</strong> reported</span><span>{counts.local_ips}</span></div>
            <div className="obs-ip-list">
              {(data?.local_ips || []).map((ip) => <code key={ip}>{ip}</code>)}
            </div>
          </div>
          <div className="result-box">
            <div className="scan-meta-row"><span><strong>Subnets</strong> in reach</span><span>{counts.subnets}</span></div>
            <div className="obs-ip-list">
              {(data?.subnets || []).map((sub) => <code key={sub}><Plug size={10} /> {sub}</code>)}
            </div>
          </div>
          <div className="result-box">
            <div className="scan-meta-row"><span><strong>Carriers</strong></span><span>{(data?.carriers || []).length}</span></div>
            <div className="obs-ip-list">
              {(data?.carriers || []).map((carrier) => <code key={carrier}>{carrier}</code>)}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
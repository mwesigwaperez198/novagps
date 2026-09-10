import { useEffect, useState } from "react";
import { Braces, Camera, Cpu, Loader2, Network, Plug, Radio, RefreshCw, Satellite, Send, Shield, Wifi } from "lucide-react";
import { api } from "../lib/api.js";

const TABS = [
  { id: "devices", label: "Devices", icon: Satellite },
  { id: "wifi", label: "WiFi", icon: Wifi },
  { id: "cameras", label: "Cameras", icon: Camera },
  { id: "ips", label: "IPs & Subnets", icon: Network },
  { id: "brain", label: "LAU Brain", icon: Braces },
];

const PRESETS = {
  good: { label: "Good fix", packet: { packet_payload: "telemetry frame ok", device_id: "dev-fleet-07", lat: 37.7749, lon: -122.4194, speed: 45.6, battery: 88 } },
  spoof: { label: "(0,0) spoof", packet: { packet_payload: "telemetry frame", device_id: "dev-fleet-07", lat: 0, lon: 0, speed: 0 } },
  range: { label: "lat=120 out of range", packet: { packet_payload: "telemetry frame", device_id: "dev-fleet-07", lat: 120.0, lon: 300.5, speed: 9.2 } },
  inject: { label: "SQL injection", packet: { packet_payload: "UNION SELECT username, password FROM users; ' --", device_id: "dev-fleet-07", lat: 37.7, lon: -122.5 } },
};

function liveBadge(online) {
  return online ? <span className="status-ok">LIVE</span> : <span className="status-dim">OFFLINE</span>;
}

export default function ObservatoryPanel() {
  const [data, setData] = useState(null);
  const [tab, setTab] = useState("devices");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [engine, setEngine] = useState(null);
  const [verify, setVerify] = useState(null);
  const [checking, setChecking] = useState(false);
  const [verifyError, setVerifyError] = useState("");
  const [packet, setPacket] = useState({ packet_payload: "telemetry frame ok", device_id: "dev-fleet-07", lat: 37.7749, lon: -122.4194, speed: 45.6 });

  async function loadEngine() {
    setEngine(null);
    try {
      setEngine(await api.novaEngineStatus());
    } catch (err) {
      setVerifyError(err.message);
    }
  }

  useEffect(() => {
    loadEngine();
  }, []);

  async function runVerify() {
    setChecking(true);
    setVerifyError("");
    setVerify(null);
    try {
      setVerify(await api.novaTelemetryVerify(packet));
    } catch (err) {
      setVerifyError(err.message);
    } finally {
      setChecking(false);
    }
  }

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

      {tab === "brain" && (
        <div className="obs-ip-grid">
          <div className="result-box">
            <div className="scan-meta-row"><span><strong>LAU engine status</strong></span>
              <button onClick={loadEngine} disabled={!engine && checking} className="btn-secondary" type="button">
                <RefreshCw size={12} /> Status
              </button>
            </div>
            <div style={{ padding: "8px 0" }}>
              {engine ? (
                <table className="data-table" style={{ minWidth: 420 }}>
                  <tbody>
                    <tr><td>agent / engine</td><td><code>{engine.agent}</code> · {engine.engine_used}</td></tr>
                    <tr><td>state</td><td>{engine.state === "ready"
                      ? <span className="status-ok">READY</span>
                      : engine.state === "shield_only"
                        ? <span className="status-ok">SHIELD ONLY</span>
                        : <span className="status-dim">{engine.state}</span>}</td></tr>
                    <tr><td>model</td><td className="muted">{engine.model || "none (deterministic fallback)"}</td></tr>
                    <tr><td>latency</td><td>{engine.latency_ms} ms</td></tr>
                    <tr><td>RAM available</td><td>{engine.available_ram_mb} MB</td></tr>
                    {engine.init_error && <tr><td>init_error</td><td className="muted">{engine.init_error}</td></tr>}
                  </tbody>
                </table>
              ) : (
                <div className="empty-row"><Loader2 size={12} className="spin" /> querying engine…</div>
              )}
            </div>
          </div>

          <div className="result-box">
            <div className="scan-meta-row"><span><strong>Telemetry verify probe</strong></span><Shield size={13} /></div>
            <div className="preset-row" style={{ display: "flex", gap: 6, flexWrap: "wrap", padding: "8px 0" }}>
              {Object.entries(PRESETS).map(([key, pre]) => (
                <button key={key} className="btn-ghost" type="button" onClick={() => setPacket(pre.packet)}>{pre.label}</button>
              ))}
            </div>
            <label className="field-label">lat</label>
            <input className="text-input" value={packet.lat} onChange={(e) => setPacket({ ...packet, lat: Number(e.target.value) })} />
            <label className="field-label">lon</label>
            <input className="text-input" value={packet.lon} onChange={(e) => setPacket({ ...packet, lon: Number(e.target.value) })} />
            <label className="field-label">packet_payload</label>
            <input className="text-input" value={packet.packet_payload} onChange={(e) => setPacket({ ...packet, packet_payload: e.target.value })} />
            <button onClick={runVerify} disabled={checking} className="btn-primary" type="button" style={{ marginTop: 8 }}>
              {checking ? <Loader2 size={12} className="spin" /> : <Send size={12} />} Verify payload
            </button>
            {verifyError && <div className="error-box">{verifyError}</div>}

            {verify && (
              <div className="verify-result" style={{ marginTop: 10 }}>
                <div className="scan-meta-row"><span>Verdict</span>
                  <span className="status-ok">{verify.output_payload.verdict}</span></div>
                <div className="scan-meta-row"><span>Action enforced</span><code>{verify.output_payload.action_enforced}</code></div>
                <div className="scan-meta-row"><span>Engine</span><code>{verify.engine}</code> · <span className="muted">latency {verify.latency_ms} ms</span></div>
                {verify.thought_process && (
                  <div className="think-steps" style={{ marginTop: 8 }}>
                    {Object.entries(verify.thought_process).map(([k, v]) => (
                      <div key={k} className="think-step"><span>{k}</span><code>{v}</code></div>
                    ))}
                  </div>
                )}
                {verify.simulated_monologue && (
                  <div className="monologue muted" style={{ marginTop: 8 }}>
                    <Cpu size={11} /> {verify.simulated_monologue}
                  </div>
                )}
                <div className="directives" style={{ marginTop: 8, display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {(verify.output_payload.directives || []).map((d) => <code key={d}>{d}</code>)}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
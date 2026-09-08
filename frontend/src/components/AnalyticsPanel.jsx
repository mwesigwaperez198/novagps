import { useState, useEffect } from "react";
import { BarChart3, Download, RefreshCw, Loader2 } from "lucide-react";
import { api } from "../lib/api.js";

export default function AnalyticsPanel({ device }) {
  const [active, setActive] = useState("dashboard");
  const [dashboard, setDashboard] = useState(null);
  const [deviceStats, setDeviceStats] = useState(null);
  const [fraud, setFraud] = useState(null);
  const [heartbeat, setHeartbeat] = useState(null);
  const [location, setLocation] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function loadDashboard() {
    setLoading(true); setError(null);
    try { setDashboard(await api.analyticsDashboard()); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function loadDevice() {
    if (!device?.id) return;
    setLoading(true); setError(null);
    try { setDeviceStats(await api.analyticsDevice(device.id)); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function loadFraud() {
    if (!device?.id) return;
    setLoading(true); setError(null);
    try { setFraud(await api.analyticsFraud(device.id)); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function loadHeartbeat() {
    if (!device?.id) return;
    setLoading(true); setError(null);
    try { setHeartbeat(await api.analyticsHeartbeat(device.id)); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function loadLocation() {
    if (!device?.id) return;
    setLoading(true); setError(null);
    try { setLocation(await api.analyticsLocationStats(device.id)); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  useEffect(() => { loadDashboard(); }, []);

  async function runExport() {
    if (!device?.id) return;
    setLoading(true); setError(null);
    try {
      const res = await api.analyticsExport(device.id, "csv");
      setError(null);
      const blob = new Blob([res.content], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `device-${device.id}-track.csv`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) { setError(e.message); }
    setLoading(false);
  }

  function renderSummary() {
    if (!dashboard) return <div className="muted">No dashboard data</div>;
    const s = dashboard.summary || {};
    const cards = [
      { label: "Devices", value: s.total_devices },
      { label: "Active", value: s.active_devices },
      { label: "Lost Mode", value: s.lost_mode_devices },
      { label: "Updates (24h)", value: s.locations_24h },
      { label: "Active (24h)", value: s.active_devices_24h },
      { label: "Open Alerts", value: s.open_alerts },
      { label: "Critical", value: s.critical_alerts },
      { label: "Avg Speed", value: `${s.avg_speed_kph} km/h` },
    ];
    return (
      <div className="analytics-grid">
        {cards.map((card) => (
          <div key={card.label} className="stat-card">
            <div className="stat-value">{card.value}</div>
            <div className="stat-label">{card.label}</div>
          </div>
        ))}
        {dashboard.activity?.length > 0 && (
          <div className="result-box" style={{ gridColumn: "1 / -1" }}>
            <strong>Updates per day</strong>
            {dashboard.activity.map((row, i) => (
              <div key={i} className="activity-row">
                <span>{row.date}</span>
                <div className="activity-bar-track">
                  <div className="activity-bar" style={{ width: `${Math.min(100, (row.updates / Math.max(...dashboard.activity.map((r) => r.updates))) * 100)}%` }} />
                </div>
                <span className="muted">{row.updates}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  }

  function renderDevice() {
    if (!device) return <div className="muted">Select a device first</div>;
    if (!deviceStats) return <div className="muted">Load device analytics</div>;
    const m = deviceStats.metrics || {};
    const rows = [
      ["Samples", m.samples],
      ["Max Speed", `${m.max_speed_kph} km/h`],
      ["Avg Speed", `${m.avg_speed_kph} km/h`],
      ["OS", `${m.os || "N/A"} ${m.os_version || ""}`],
      ["IMEI", m.imei || "N/A"],
      ["Active", m.active ? "Yes" : "No"],
      ["Lost Mode", m.lost_mode ? "Yes" : "No"],
    ];
    return (
      <div>
        {rows.map(([k, v]) => (
          <div key={k} className="list-item" style={{ display: "flex", justifyContent: "space-between" }}>
            <span className="muted">{k}</span><span>{v}</span>
          </div>
        ))}
      </div>
    );
  }

  function renderFraud() {
    if (!device) return <div className="muted">Select a device first</div>;
    if (!fraud) return <div className="muted">Load fraud analysis</div>;
    return (
      <div>
        <div className={`verdict verdict-${fraud.verdict}`}>{fraud.verdict.toUpperCase()}</div>
        <div className="muted">Samples: {fraud.samples} · Anomalies: {fraud.anomaly_count}</div>
        {fraud.anomalies?.length === 0 && <div className="muted">No implausible-speed events detected</div>}
        {fraud.anomalies?.map((a, i) => (
          <div key={i} className="list-item">
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span className="status-err">{a.speed_kph} km/h</span>
              <span className="muted">{a.time?.substring(0, 19)}</span>
            </div>
            <div className="muted">{a.reason} @ {a.lat.toFixed(5)},{a.lon.toFixed(5)}</div>
          </div>
        ))}
      </div>
    );
  }

  function renderHeartbeat() {
    if (!device) return <div className="muted">Select a device first</div>;
    if (!heartbeat) return <div className="muted">Load heartbeat</div>;
    const state = heartbeat.status;
    return (
      <div>
        <div className={`verdict verdict-${state}`}>{state.toUpperCase()}</div>
        <div className="list-item" style={{ display: "flex", justifyContent: "space-between" }}>
          <span className="muted">Updates</span><span>{heartbeat.count}</span>
        </div>
        <div className="list-item" style={{ display: "flex", justifyContent: "space-between" }}>
          <span className="muted">Cadence</span><span>{heartbeat.cadence_seconds ? `${Math.round(heartbeat.cadence_seconds)}s` : "N/A"}</span>
        </div>
        <div className="list-item" style={{ display: "flex", justifyContent: "space-between" }}>
          <span className="muted">Last update</span><span>{heartbeat.last_update?.substring(0, 19)}</span>
        </div>
      </div>
    );
  }

  function renderLocation() {
    if (!device) return <div className="muted">Select a device first</div>;
    if (!location) return <div className="muted">Load location stats</div>;
    return (
      <div>
        <div className="list-item" style={{ display: "flex", justifyContent: "space-between" }}>
          <span className="muted">Samples</span><span>{location.samples}</span>
        </div>
        <div className="list-item" style={{ display: "flex", justifyContent: "space-between" }}>
          <span className="muted">Distance tracked</span><span>{location.distance_tracked_km} km</span>
        </div>
        <div className="list-item" style={{ display: "flex", justifyContent: "space-between" }}>
          <span className="muted">Peak speed</span><span>{location.peak_speed_kph} km/h</span>
        </div>
        <div className="section-title">Top sources</div>
        {location.top_sources?.map(([src, count]) => (
          <div key={src} className="list-item" style={{ display: "flex", justifyContent: "space-between" }}>
            <span>{src}</span><span className="muted">{count}</span>
          </div>
        ))}
        {location.top_places?.length > 0 && (
          <>
            <div className="section-title">Top places</div>
            {location.top_places.map(([place, count]) => (
              <div key={place} className="list-item" style={{ display: "flex", justifyContent: "space-between" }}>
                <span>{place}</span><span className="muted">{count}</span>
              </div>
            ))}
          </>
        )}
      </div>
    );
  }

  const actions = {
    dashboard: () => loadDashboard(),
    device: () => loadDevice(),
    fraud: () => loadFraud(),
    heartbeat: () => loadHeartbeat(),
    location: () => loadLocation(),
  };

  return (
    <div className="panel-inner">
      <h3><BarChart3 size={14} /> Analytics</h3>
      <p className="muted">Fleet and device intelligence</p>

      <div className="input-row" style={{ flexWrap: "wrap" }}>
        <button className={`btn-sm ${active === "dashboard" ? "btn-primary" : ""}`} onClick={() => { setActive("dashboard"); loadDashboard(); }}>Dashboard</button>
        <button className={`btn-sm ${active === "device" ? "btn-primary" : ""}`} onClick={() => { setActive("device"); loadDevice(); }}>Device</button>
        <button className={`btn-sm ${active === "fraud" ? "btn-primary" : ""}`} onClick={() => { setActive("fraud"); loadFraud(); }}>Fraud</button>
        <button className={`btn-sm ${active === "heartbeat" ? "btn-primary" : ""}`} onClick={() => { setActive("heartbeat"); loadHeartbeat(); }}>Heartbeat</button>
        <button className={`btn-sm ${active === "location" ? "btn-primary" : ""}`} onClick={() => { setActive("location"); loadLocation(); }}>Locations</button>
        <button className="btn-sm btn-primary" onClick={runExport} disabled={loading || !device?.id} title="Export CSV">
          <Download size={10} /> CSV
        </button>
        <button className="btn-sm" onClick={actions[active]} disabled={loading} title="Reload">
          <RefreshCw size={10} />
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}
      {loading && <div className="muted"><Loader2 size={12} className="spin" /> Loading...</div>}

      <div className="analytics-content">
        {active === "dashboard" && renderSummary()}
        {active === "device" && renderDevice()}
        {active === "fraud" && renderFraud()}
        {active === "heartbeat" && renderHeartbeat()}
        {active === "location" && renderLocation()}
      </div>
    </div>
  );
}

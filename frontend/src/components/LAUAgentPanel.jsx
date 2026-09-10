import { useEffect, useState } from "react";
import { Braces, Cpu, Loader2, Radio, RefreshCw, Send, Shield } from "lucide-react";
import { api } from "../lib/api.js";
import LAUShieldPanel from "./LAUShieldPanel.jsx";

const TABS = [
  { id: "engine", label: "Engine", icon: Radio },
  { id: "probe", label: "Probe", icon: Send },
  { id: "shield", label: "Shield", icon: Shield },
];

const PRESETS = {
  good: { label: "Good fix", packet: { packet_payload: "telemetry frame ok", device_id: "dev-fleet-07", lat: 37.7749, lon: -122.4194, speed: 45.6, battery: 88 } },
  spoof: { label: "(0,0) spoof", packet: { packet_payload: "telemetry frame", device_id: "dev-fleet-07", lat: 0, lon: 0, speed: 0 } },
  range: { label: "lat=120 out of range", packet: { packet_payload: "telemetry frame", device_id: "dev-fleet-07", lat: 120.0, lon: 300.5, speed: 9.2 } },
  inject: { label: "SQL injection", packet: { packet_payload: "UNION SELECT username, password FROM users; ' --", device_id: "dev-fleet-07", lat: 37.7, lon: -122.5 } },
};

function stateChip(state) {
  if (!state) return null;
  if (state === "ready") return <span className="status-ok">READY</span>;
  if (state === "shield_only") return <span className="status-ok">SHIELD ONLY</span>;
  return <span className="status-dim">{state}</span>;
}

function EngineView() {
  const [engine, setEngine] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      setEngine(await api.novaEngineStatus());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="result-box">
      <div className="scan-meta-row">
        <span><strong>LAU engine status</strong></span>
        <button onClick={load} disabled={loading} className="btn-secondary" type="button">
          {loading ? <Loader2 size={12} className="spin" /> : <RefreshCw size={12} />} Refresh
        </button>
      </div>
      {error && <div className="error-box">{error}</div>}
      {!engine && !error && <div className="empty-row"><Loader2 size={12} className="spin" /> querying engine…</div>}
      {engine && (
        <table className="data-table" style={{ minWidth: 420 }}>
          <tbody>
            <tr><td>agent / engine</td><td><code>{engine.agent}</code> · {engine.engine_used}</td></tr>
            <tr><td>state</td><td>{stateChip(engine.state)}</td></tr>
            <tr><td>model</td><td className="muted">{engine.model || "none (deterministic fallback)"}</td></tr>
            <tr><td>latency</td><td>{engine.latency_ms} ms</td></tr>
            <tr><td>RAM available</td><td>{engine.available_ram_mb} MB</td></tr>
            {engine.init_error && <tr><td>init_error</td><td className="muted">{engine.init_error}</td></tr>}
          </tbody>
        </table>
      )}
    </div>
  );
}

function ProbeView() {
  const [verify, setVerify] = useState(null);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState("");
  const [packet, setPacket] = useState({ packet_payload: "telemetry frame ok", device_id: "dev-fleet-07", lat: 37.7749, lon: -122.4194, speed: 45.6 });

  async function run() {
    setChecking(true);
    setError("");
    setVerify(null);
    try {
      setVerify(await api.novaTelemetryVerify(packet));
    } catch (err) {
      setError(err.message);
    } finally {
      setChecking(false);
    }
  }

  return (
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
      <label className="field-label">speed</label>
      <input className="text-input" value={packet.speed} onChange={(e) => setPacket({ ...packet, speed: Number(e.target.value) })} />
      <label className="field-label">packet_payload</label>
      <input className="text-input" value={packet.packet_payload} onChange={(e) => setPacket({ ...packet, packet_payload: e.target.value })} />
      <button onClick={run} disabled={checking} className="btn-primary" type="button" style={{ marginTop: 8 }}>
        {checking ? <Loader2 size={12} className="spin" /> : <Send size={12} />} Verify payload
      </button>
      {error && <div className="error-box">{error}</div>}

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
  );
}

export default function LAUAgentPanel() {
  const [tab, setTab] = useState("shield");

  return (
    <div className="panel-inner observatory-panel">
      <h3><Braces size={14} /> LAU Agent</h3>
      <p className="muted">
        The LAU operating home: engine status, telemetry probe, and the deterministic
        shield with its module validators. The agent works from here.
      </p>

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
      </div>

      {tab === "engine" && <EngineView />}
      {tab === "probe" && <ProbeView />}
      {tab === "shield" && <LAUShieldPanel />}
    </div>
  );
}
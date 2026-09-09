import { useEffect, useState } from "react";
import { FileSearch, Loader2, RefreshCw } from "lucide-react";
import { api } from "../lib/api.js";

const KINDS = [
  { id: "", label: "All" },
  { id: "alert", label: "Alerts" },
  { id: "audit", label: "Audit" },
  { id: "consent", label: "Consent" },
  { id: "vehicle", label: "Recovery" },
];

const SEVERITIES = ["", "critical", "warn", "info", "active"];

function severityClass(severity) {
  if (severity === "critical") return "status-err";
  if (severity === "warn") return "status-warn";
  if (severity === "active") return "status-ok";
  return "status-dim";
}

function when(ts) {
  if (String(ts).endsWith("Z")) return new Date(ts).toLocaleString();
  return String(ts).replace("T", " ").slice(0, 19);
}

export default function LogsPanel() {
  const [data, setData] = useState(null);
  const [kind, setKind] = useState("");
  const [severity, setSeverity] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function load(nextKind = kind, nextSeverity = severity) {
    setLoading(true);
    setError("");
    try {
      setData(await api.logs(nextKind, nextSeverity, 150));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load("");
  }, []);

  const entries = data?.entries || [];
  const stats = data?.stats || {};

  return (
    <div className="panel-inner logs-panel">
      <h3><FileSearch size={14} /> System Logs & Analysis</h3>
      <p className="muted">All alerts, audits, consents and recoveries in a single analysis feed.</p>

      <div className="log-stats">
        {Object.entries(stats.by_kind || {}).map(([key, count]) => (
          <div className="log-stat-chip" key={key}>
            <strong>{count}</strong> {key}
          </div>
        ))}
        {stats.last_24h && (
          <div className="log-stat-chip">
            <strong>{(stats.last_24h.alerts || 0) + (stats.last_24h.audit || 0)}</strong> last 24h
          </div>
        )}
      </div>

      <div className="input-row" style={{ marginTop: 8 }}>
        <select value={kind} onChange={(e) => { setKind(e.target.value); load(e.target.value, severity); }}>
          {KINDS.map((k) => <option key={k.id} value={k.id}>{k.label}</option>)}
        </select>
        <select value={severity} onChange={(e) => { setSeverity(e.target.value); load(kind, e.target.value); }}>
          {SEVERITIES.map((s) => <option key={s || "any"} value={s}>{s ? s.toUpperCase() : "ANY SEVERITY"}</option>)}
        </select>
        <button onClick={() => load()} disabled={loading} className="btn-secondary">
          {loading ? <Loader2 size={12} className="spin" /> : <RefreshCw size={12} />} Refresh
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}

      <div className="result-box" style={{ padding: 0 }}>
        {entries.length === 0 && !loading && (
          <div className="empty-row">No log entries.</div>
        )}
        <table className="data-table">
          <thead>
            <tr>
              <th>Time</th><th>Kind</th><th>Severity</th><th>Event</th><th>Actor / Device</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry) => (
              <tr key={`${entry.kind}-${entry.id}`}>
                <td className="muted">{when(entry.ts)}</td>
                <td><code>{entry.kind}</code></td>
                <td><span className={severityClass(entry.severity)}>{entry.severity}</span></td>
                <td>
                  {entry.title}
                  {entry.message && <div className="muted">{entry.message}</div>}
                </td>
                <td className="muted">
                  {entry.actor || entry.device_id || "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
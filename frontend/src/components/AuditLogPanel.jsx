import { useState, useEffect } from "react";
import { ScrollText, RefreshCw, User, Loader2 } from "lucide-react";
import { api } from "../lib/api.js";

export default function AuditLogPanel() {
  const [logs, setLogs] = useState([]);
  const [actionFilter, setActionFilter] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function loadLogs() {
    setLoading(true); setError(null);
    try {
      const res = await api.auditLogs(100);
      setLogs(Array.isArray(res) ? res : []);
    } catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function applyFilter() {
    setLoading(true); setError(null);
    try {
      const res = await api.auditLogs(100);
      const filtered = actionFilter ? res.filter((l) => l.action === actionFilter) : res;
      setLogs(filtered);
    } catch (e) { setError(e.message); }
    setLoading(false);
  }

  useEffect(() => { loadLogs(); }, []);

  return (
    <div className="panel-inner">
      <h3><ScrollText size={14} /> Audit Logs</h3>
      <p className="muted">Immutable activity trail</p>

      <div className="input-row">
        <input className="text-input" value={actionFilter} onChange={(e) => setActionFilter(e.target.value)} placeholder="Filter by action" />
        <button className="btn-primary" onClick={applyFilter} disabled={loading}>
          {loading ? <Loader2 size={12} className="spin" /> : <RefreshCw size={12} />}
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}

      {logs.length === 0 && !loading && <div className="muted">No audit logs</div>}

      {logs.map((log) => (
        <div key={log.id} className="list-item">
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <span className="badge">{log.action}</span>
            <span className="muted">{log.created_at?.substring(0, 19)}</span>
          </div>
          <div className="muted" style={{ display: "flex", alignItems: "center", gap: 4 }}>
            <User size={10} /> {log.actor} · {log.role}
          </div>
          {log.command_id && <div className="muted">Command: {log.command_id}</div>}
          {log.exit_code !== null && log.exit_code !== undefined && (
            <div className="muted">Exit: {log.exit_code}</div>
          )}
        </div>
      ))}
    </div>
  );
}

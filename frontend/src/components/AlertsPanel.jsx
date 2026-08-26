import { useState, useEffect } from "react";
import { Bell, Check, Loader2, Filter } from "lucide-react";
import { api } from "../lib/api.js";

export default function AlertsPanel() {
  const [alerts, setAlerts] = useState([]);
  const [severityFilter, setSeverityFilter] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function loadAlerts() {
    setLoading(true); setError(null);
    try {
      const res = await api.alertsList(50, severityFilter || null);
      setAlerts(res.alerts || []);
    } catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function acknowledgeAlert(alertId) {
    try {
      await api.alertAcknowledge(alertId);
      setAlerts((prev) => prev.map((a) => a.id === alertId ? { ...a, acknowledged: true } : a));
    } catch (e) { setError(e.message); }
  }

  useEffect(() => { loadAlerts(); }, []);

  return (
    <div className="panel-inner">
      <h3><Bell size={14} /> Alerts</h3>
      <p className="muted">System alerts and notifications</p>

      <div className="input-row">
        <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
          <option value="">All Severity</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="info">Info</option>
        </select>
        <button onClick={loadAlerts} disabled={loading} className="btn-primary">
          {loading ? <Loader2 size={12} className="spin" /> : <Filter size={12} />}
          Filter
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}

      {alerts.length === 0 && !loading && <div className="muted">No alerts</div>}

      {alerts.map((alert) => (
        <div key={alert.id} className={`list-item alert-${alert.severity} ${alert.acknowledged ? "acknowledged" : ""}`}>
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <span><strong>{alert.title}</strong></span>
            <span className={`severity-badge severity-${alert.severity}`}>{alert.severity}</span>
          </div>
          <div className="muted">{alert.message}</div>
          <div style={{ display: "flex", justifyContent: "space-between", marginTop: 4 }}>
            <span className="muted">{alert.created_at}</span>
            {!alert.acknowledged && (
              <button className="btn-sm" onClick={() => acknowledgeAlert(alert.id)} title="Acknowledge">
                <Check size={10} /> ACK
              </button>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

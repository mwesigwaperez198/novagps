import { useState, useEffect } from "react";
import { ShieldAlert } from "lucide-react";
import { api } from "../lib/api.js";

export default function IDSPanel() {
  const [status, setStatus] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    refresh();
  }, []);

  async function refresh() {
    setLoading(true);
    try {
      const [s, a] = await Promise.all([api.idsStatus(), api.idsAlerts(30)]);
      setStatus(s);
      setAlerts(a.alerts || []);
    } catch (err) {
      setStatus({ error: err.message });
    } finally {
      setLoading(false);
    }
  }

  async function updateRules() {
    setLoading(true);
    try {
      await api.idsUpdateRules();
      await refresh();
    } catch (err) {
      setStatus({ error: err.message });
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="panel ids-panel">
      <div className="panel-title">
        <span>IDS</span>
        <ShieldAlert size={15} />
      </div>
      <div className="ids-status">
        <div className="status-row">
          <span>Suricata</span>
          <code className={status?.suricata?.running ? "status-ok" : "status-off"}>
            {status?.suricata?.running ? "RUNNING" : "STOPPED"}
          </code>
        </div>
        <div className="status-row">
          <span>Rules</span>
          <code>{status?.suricata?.rules_count || 0}</code>
        </div>
      </div>
      <div className="tool-controls">
        <button className="command-button" onClick={refresh} disabled={loading}>
          {loading ? "..." : "REFRESH"}
        </button>
        <button className="command-button" onClick={updateRules} disabled={loading}>
          UPDATE RULES
        </button>
      </div>
      <div className="alerts-list">
        {alerts.length === 0 && <div className="empty">No recent alerts</div>}
        {alerts.map((alert, i) => (
          <div key={i} className="alert-item">
            <span className={`severity-${alert.severity || 3}`}>SEV {alert.severity || "?"}</span>
            <code>{alert.alert || "unknown"}</code>
            <span>{alert.src_ip} {'\u2192'} {alert.dest_ip}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

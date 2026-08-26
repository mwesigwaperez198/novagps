import { useState, useEffect } from "react";
import { Webhook, Plus, Trash2, Loader2, ExternalLink } from "lucide-react";
import { api } from "../lib/api.js";

export default function WebhookPanel() {
  const [endpoints, setEndpoints] = useState([]);
  const [url, setUrl] = useState("");
  const [events, setEvents] = useState("location.updated,geofence.breach,vehicle.stolen");
  const [selectedEndpoint, setSelectedEndpoint] = useState(null);
  const [deliveries, setDeliveries] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function loadEndpoints() {
    setLoading(true); setError(null);
    try { const res = await api.webhooksList(); setEndpoints(res.endpoints || []); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function addEndpoint() {
    if (!url) { setError("URL required"); return; }
    setLoading(true); setError(null);
    try {
      await api.webhookRegister(url, events);
      setUrl("");
      await loadEndpoints();
    } catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function deleteEndpoint(id) {
    try { await api.webhookDelete(id); setEndpoints((prev) => prev.filter((e) => e.id !== id)); }
    catch (e) { setError(e.message); }
  }

  async function loadDeliveries(endpointId) {
    setLoading(true); setError(null);
    try {
      setSelectedEndpoint(endpointId);
      const res = await api.webhookDeliveries(endpointId);
      setDeliveries(res.deliveries || []);
    } catch (e) { setError(e.message); }
    setLoading(false);
  }

  useEffect(() => { loadEndpoints(); }, []);

  return (
    <div className="panel-inner">
      <h3><Webhook size={14} /> Webhooks</h3>
      <p className="muted">Event-driven webhook endpoints</p>

      <div className="input-row">
        <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="Webhook URL" style={{ width: "60%" }} />
        <input value={events} onChange={(e) => setEvents(e.target.value)} placeholder="Events (comma-sep)" style={{ width: "40%" }} />
      </div>
      <button onClick={addEndpoint} disabled={loading} className="btn-primary" style={{ marginTop: 6, width: "100%" }}>
        <Plus size={12} /> Register Webhook
      </button>

      {error && <div className="error-box">{error}</div>}

      {endpoints.length === 0 && !loading && <div className="muted">No webhooks registered</div>}

      {endpoints.map((ep) => (
        <div key={ep.id} className="list-item">
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <span><strong>{ep.url?.substring(0, 40)}...</strong></span>
            <span style={{ display: "flex", gap: 4 }}>
              <button className="btn-sm" onClick={() => loadDeliveries(ep.id)}>
                <ExternalLink size={10} />
              </button>
              <button className="btn-sm btn-danger" onClick={() => deleteEndpoint(ep.id)}>
                <Trash2 size={10} />
              </button>
            </span>
          </div>
          <div className="muted">Events: {ep.events?.join(", ")}</div>
        </div>
      ))}

      {selectedEndpoint && deliveries.length > 0 && (
        <div className="result-box">
          <div><strong>Deliveries:</strong></div>
          {deliveries.map((d, i) => (
            <div key={i} className="list-item">
              <span className={d.success ? "status-ok" : "status-err"}>{d.success ? "200" : "ERR"}</span>
              {" "}{d.event_type} - {d.created_at?.substring(0, 19)}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

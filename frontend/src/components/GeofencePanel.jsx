import { useState } from "react";
import { MapPin, Eye, Loader2 } from "lucide-react";
import { api } from "../lib/api.js";

export default function GeofencePanel() {
  const [geofences, setGeofences] = useState(null);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function loadGeofences() {
    setLoading(true); setError(null);
    try { setGeofences(await api.geofences()); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function viewGeofence(id) {
    setLoading(true); setError(null);
    try { setSelected(await api.getGeofence(id)); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  return (
    <div className="panel-inner">
      <h3><MapPin size={14} /> Geofences</h3>
      <p className="muted">View configured geofence zones</p>

      <button onClick={loadGeofences} disabled={loading} className="btn-primary" style={{ width: "100%" }}>
        {loading ? <Loader2 size={12} className="spin" /> : <MapPin size={12} />}
        Load Geofences
      </button>

      {error && <div className="error-box">{error}</div>}

      {geofences?.geofences?.length > 0 && (
        <div className="result-box">
          <div><strong>{geofences.geofences.length} geofences</strong></div>
          {geofences.geofences.map((f, i) => (
            <div key={i} className="list-item" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span><strong>{f.name}</strong> ({f.geofence_id})</span>
              <button className="btn-sm" onClick={() => viewGeofence(f.geofence_id)}>
                <Eye size={10} />
              </button>
            </div>
          ))}
        </div>
      )}

      {selected && (
        <div className="result-box">
          <div><strong>{selected.name}</strong> ({selected.geofence_id})</div>
          <div><strong>Vertices:</strong> {selected.coords?.length || 0}</div>
          {selected.coords?.length > 0 && (
            <table className="data-table">
              <thead><tr><th>#</th><th>Lat</th><th>Lng</th></tr></thead>
              <tbody>
                {selected.coords.map((c, i) => (
                  <tr key={i}><td>{i + 1}</td><td>{c.lat?.toFixed(6)}</td><td>{c.lng?.toFixed(6)}</td></tr>
                ))}
              </tbody>
            </table>
          )}
          <div style={{ marginTop: 6 }}><strong>WKT:</strong></div>
          <pre style={{ fontSize: 10, overflow: "auto" }}>{selected.polygon_wkt}</pre>
        </div>
      )}
    </div>
  );
}

import { useState } from "react";
import { Car, AlertTriangle, Camera, Loader2, MapPin } from "lucide-react";
import { api } from "../lib/api.js";

export default function VehicleRecoveryPanel({ device }) {
  const [recoveryId, setRecoveryId] = useState("");
  const [activeRecoveries, setActiveRecoveries] = useState(null);
  const [recoveryStatus, setRecoveryStatus] = useState(null);
  const [stolenResult, setStolenResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function reportStolen() {
    if (!device?.id) { setError("Select a device first"); return; }
    setLoading(true); setError(null); setStolenResult(null);
    try {
      const res = await api.vehicleReportStolen(device.id);
      setStolenResult(res);
      if (res.recovery_id) setRecoveryId(res.recovery_id);
    } catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function getStatus() {
    if (!recoveryId) { setError("Enter recovery ID"); return; }
    setLoading(true); setError(null); setRecoveryStatus(null);
    try { setRecoveryStatus(await api.vehicleRecoveryStatus(recoveryId)); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function endRecovery() {
    if (!recoveryId) return;
    setLoading(true); setError(null);
    try { await api.vehicleEndRecovery(recoveryId); setRecoveryStatus(null); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function loadActive() {
    setLoading(true); setError(null);
    try { setActiveRecoveries(await api.vehicleActiveRecoveries()); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  return (
    <div className="panel-inner">
      <h3><Car size={14} /> Vehicle Recovery</h3>
      <p className="muted">Report stolen, track recovery, link cameras</p>

      <button onClick={reportStolen} disabled={loading || !device?.id} className="btn-danger" style={{ width: "100%" }}>
        <AlertTriangle size={12} /> Report Vehicle Stolen
      </button>

      {stolenResult && (
        <div className="result-box">
          <div><strong>Recovery ID:</strong> {stolenResult.recovery_id}</div>
          <div><strong>Status:</strong> {stolenResult.status}</div>
          <div><strong>Message:</strong> {stolenResult.message}</div>
        </div>
      )}

      <div className="section-label">Recovery Lookup</div>
      <div className="input-row">
        <input value={recoveryId} onChange={(e) => setRecoveryId(e.target.value)} placeholder="Recovery ID" />
        <button onClick={getStatus} disabled={loading} className="btn-primary">
          {loading ? <Loader2 size={12} className="spin" /> : <MapPin size={12} />}
          Lookup
        </button>
      </div>

      {recoveryStatus && (
        <div className="result-box">
          <div><strong>Status:</strong> {recoveryStatus.status}</div>
          {recoveryStatus.device_id && <div><strong>Device:</strong> {recoveryStatus.device_id}</div>}
          {recoveryStatus.created_at && <div><strong>Reported:</strong> {recoveryStatus.created_at}</div>}
          {recoveryStatus.camera_count > 0 && (
            <div><Camera size={12} /> {recoveryStatus.camera_count} camera(s) linked</div>
          )}
          {recoveryStatus.latest_location && (
            <div><MapPin size={12} /> Last known: {recoveryStatus.latest_location.lat?.toFixed(6)}, {recoveryStatus.latest_location.lng?.toFixed(6)}</div>
          )}
          <button onClick={endRecovery} disabled={loading} className="btn-secondary" style={{ marginTop: 6 }}>
            End Recovery
          </button>
        </div>
      )}

      <button onClick={loadActive} disabled={loading} className="btn-secondary" style={{ marginTop: 8, width: "100%" }}>
        <Car size={12} /> Active Recoveries
      </button>

      {activeRecoveries?.recoveries?.length > 0 && (
        <div className="result-box">
          {activeRecoveries.recoveries.map((r, i) => (
            <div key={i} className="list-item" style={{ cursor: "pointer" }} onClick={() => setRecoveryId(r.recovery_id)}>
              <strong>{r.recovery_id.substring(0, 8)}...</strong> - {r.status} ({r.device_id})
            </div>
          ))}
        </div>
      )}

      {error && <div className="error-box">{error}</div>}
    </div>
  );
}

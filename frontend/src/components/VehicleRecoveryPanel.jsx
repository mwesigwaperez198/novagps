import { useState } from "react";
import { AlertTriangle, Camera, Car, Crosshair, Loader2, MapPin, ScanSearch } from "lucide-react";
import { api } from "../lib/api.js";
import { deviceContext } from "../lib/device.js";

export default function VehicleRecoveryPanel({ device }) {
  const ctx = deviceContext(device);
  const [recoveryId, setRecoveryId] = useState("");
  const [assets, setAssets] = useState(null);
  const [activeRecoveries, setActiveRecoveries] = useState(null);
  const [stolenResult, setStolenResult] = useState(null);
  const [linkCam, setLinkCam] = useState("");
  const [linkPort, setLinkPort] = useState(554);
  const [linkResult, setLinkResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const deviceRecoveryId = device?.recovery_id || "";

  async function reportStolen() {
    if (!device?.id) { setError("Select a device first"); return; }
    setLoading(true); setError(null); setStolenResult(null); setAssets(null);
    try {
      const res = await api.vehicleReportStolen(device.id);
      setStolenResult(res);
      if (res.recovery_id) {
        setRecoveryId(res.recovery_id);
        const prepared = await api.vehicleRecoveryAssets(res.recovery_id);
        setAssets(prepared);
      }
    } catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function prepareAssets() {
    if (!recoveryId) { setError("Enter recovery ID"); return; }
    setLoading(true); setError(null); setAssets(null);
    try { setAssets(await api.vehicleRecoveryAssets(recoveryId)); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function loadActive() {
    setLoading(true); setError(null);
    try { setActiveRecoveries(await api.vehicleActiveRecoveries()); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function endRecovery() {
    if (!recoveryId) return;
    setLoading(true); setError(null);
    try { await api.vehicleEndRecovery(recoveryId); setAssets(null); setStolenResult(null); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function linkCamera(cameraIp) {
    const useIp = cameraIp || linkCam;
    if (!recoveryId || !device?.id || !useIp) { setError("Recovery ID, device and camera IP required"); return; }
    setLoading(true); setError(null); setLinkResult(null);
    try {
      const res = await api.vehicleLinkCamera(recoveryId, device.id, useIp, linkPort);
      setLinkResult(res);
      if (assets) setAssets(await api.vehicleRecoveryAssets(recoveryId));
    } catch (e) { setError(e.message); }
    setLoading(false);
  }

  const dev = assets?.device;

  return (
    <div className="panel-inner">
      <h3><Car size={14} /> Vehicle Recovery</h3>
      <p className="muted">Recovery ID is generated once at device registration — report stolen, then pull the device IP + nearby cameras automatically.</p>

      {deviceRecoveryId && (
        <div className="tool-device-context">
          <Crosshair size={12} />
          {device.identifier} · RECOVER-{deviceRecoveryId}
          {ctx.ip ? ` · ${ctx.ip}` : ""}
        </div>
      )}

      <button onClick={reportStolen} disabled={loading || !device?.id} className="btn-danger" style={{ width: "100%" }}>
        <AlertTriangle size={12} /> Report Vehicle Stolen
      </button>

      {stolenResult && (
        <div className="result-box">
          <div><strong>Recovery ID:</strong> <code>{stolenResult.recovery_id}</code></div>
          <div><strong>Status:</strong> {stolenResult.status}</div>
          <div><strong>Message:</strong> {stolenResult.message}</div>
        </div>
      )}

      <div className="section-label">Recovery Lookup — auto-pulls device + cameras</div>
      <div className="input-row">
        <input value={recoveryId} onChange={(e) => setRecoveryId(e.target.value)} placeholder="Recovery ID" />
        <button onClick={prepareAssets} disabled={loading} className="btn-primary">
          {loading ? <Loader2 size={12} className="spin" /> : <ScanSearch size={12} />}
          Trigger assets
        </button>
      </div>

      {assets && (
        <div className="result-box">
          <div className="scan-meta-row">
            <span><strong>DEVICE</strong> {dev?.identifier || assets?.device_id}</span>
            <span>{assets?.status}</span>
          </div>
          {dev && (
            <div className="obs-ip-list">
              {dev.imei ? <code>IMEI {dev.imei}</code> : null}
              {dev.ip_address ? <code>PUB {dev.ip_address}</code> : null}
              {dev.local_ip ? <code>LOC {dev.local_ip}</code> : null}
              {dev.carrier ? <code>{dev.carrier}</code> : null}
            </div>
          )}
          {dev?.last_location && (
            <div className="muted">
              <MapPin size={10} /> Last: {dev.last_location.latitude?.toFixed(6)}, {dev.last_location.longitude?.toFixed(6)}
              {dev.last_location.place_name ? ` — ${dev.last_location.place_name}` : ""}
            </div>
          )}
          {assets.scan_note && <div className="muted">{assets.scan_note}</div>}

          <div className="scan-meta-row" style={{ marginTop: 8 }}>
            <span><strong>CAMERAS</strong> auto-found</span>
            <span>{assets.camera_count || 0}</span>
          </div>
          {(assets.cameras || []).length > 0 && (
            <table className="data-table">
              <thead><tr><th>IP</th><th>Ports</th><th>Kind</th><th /></tr></thead>
              <tbody>
                {assets.cameras.map((cam, i) => (
                  <tr key={`${cam.ip}-${i}`}>
                    <td><code>{cam.ip}</code></td>
                    <td>{(cam.ports || []).join(", ") || "—"}</td>
                    <td>{cam.kind}</td>
                    <td>
                      <button
                        className="btn-sm"
                        onClick={() => linkCamera(cam.ip)}
                        disabled={loading}
                        type="button"
                      >
                        <Camera size={10} /> LINK
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
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
            <button
              key={i}
              className="list-item"
              style={{ cursor: "pointer", width: "100%" }}
              onClick={() => { setRecoveryId(r.recovery_id); prepareAssets(); }}
            >
              <strong>{r.recovery_id.substring(0, 8)}...</strong> — device {r.device_id}
            </button>
          ))}
        </div>
      )}

      <div className="section-label">Link Camera Manually</div>
      <div className="input-row">
        <input value={linkCam} onChange={(e) => setLinkCam(e.target.value)} placeholder="Camera IP" />
        <input type="number" value={linkPort} min={1} max={65535} onChange={(e) => setLinkPort(Number(e.target.value))} style={{ width: 64 }} placeholder="Port" />
      </div>
      <button onClick={linkCamera} disabled={loading} className="btn-primary" style={{ width: "100%", marginTop: 6 }}>
        <Camera size={12} /> Link Camera
      </button>

      {linkResult && (
        <div className="result-box">
          <div><strong>Status:</strong> {linkResult.status || linkResult.message}</div>
        </div>
      )}

      {error && <div className="error-box">{error}</div>}
    </div>
  );
}
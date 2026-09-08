import { useEffect, useState } from "react";
import { Activity, Cpu, Globe, Radio, ShieldCheck, ShieldAlert, Smartphone } from "lucide-react";
import { api } from "../lib/api.js";
import { clockTime, getViewerLocation, isLive, relativeTime, reportViewerLocation } from "../lib/live.js";

function heartbeatLabel(heartbeat) {
  if (!heartbeat || typeof heartbeat !== "object") return "--";
  if (heartbeat.status === "healthy") return `HEALTHY · ${heartbeat.cadence_seconds ?? "--"}s cadence`;
  if (heartbeat.status === "no_heartbeat") return "NO SIGNAL";
  return String(heartbeat.status || "--").toUpperCase();
}

function fraudLabel(fraud) {
  if (!fraud || typeof fraud !== "object") return "--";
  const label = String(fraud.verdict || "--").toUpperCase();
  return fraud.anomaly_count > 0 ? `${label} · ${fraud.anomaly_count} ANOMALIES` : label;
}

function fingerprintSummary(fingerprint, device) {
  if (!fingerprint || typeof fingerprint !== "object" || fingerprint.error) {
    return { type: device?.device_type || "--", extra: "fingerprint pending" };
  }
  const extra = [
    fingerprint.manufacturer,
    fingerprint.model,
    fingerprint.firmware_version,
    (fingerprint.open_ports || []).length ? `ports:${fingerprint.open_ports.slice(0, 6).join(",")}` : "",
  ].filter(Boolean).join(" · ");
  return { type: fingerprint.device_type || device?.device_type || "--", extra };
}

export default function DeviceInsight({ device, onSimulated }) {
  const [last, setLast] = useState(null);
  const [fingerprint, setFingerprint] = useState(null);
  const [oui, setOui] = useState(null);
  const [fraud, setFraud] = useState(null);
  const [heartbeat, setHeartbeat] = useState(null);
  const [stats, setStats] = useState(null);
  const [now, setNow] = useState(Date.now());
  const [simulating, setSimulating] = useState(false);
  const [simError, setSimError] = useState("");

  useEffect(() => {
    const tick = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(tick);
  }, []);

  useEffect(() => {
    setLast(null);
    setFingerprint(null);
    setOui(null);
    setFraud(null);
    setHeartbeat(null);
    setStats(null);
    setSimError("");
    if (!device?.id) return undefined;

    let active = true;

    function snapshot() {
      api.locations(device.id, 1)
        .then((items) => { if (active && items.length) setLast(items[0]); })
        .catch(() => {});
      api.analyticsFraud(device.id)
        .then((data) => { if (active) setFraud(data); })
        .catch(() => {});
      api.analyticsHeartbeat(device.id)
        .then((data) => { if (active) setHeartbeat(data); })
        .catch(() => {});
      api.analyticsLocationStats(device.id)
        .then((data) => { if (active) setStats(data); })
        .catch(() => {});
    }

    snapshot();
    const poll = setInterval(snapshot, 5000);

    if (device.ip_address) {
      api.deviceFingerprint(device.id)
        .then((data) => { if (active) setFingerprint(data); })
        .catch(() => {});
    }
    if (device.mac_address) {
      api.deviceOui(device.id)
        .then((data) => { if (active) setOui(data); })
        .catch(() => {});
    }

    return () => { active = false; clearInterval(poll); };
  }, [device?.id]);

  if (!device) return null;

  const live = isLive(last || device.latest_location);
  const lastSeenLabel = relativeTime(last?.recorded_at || device?.latest_location?.recorded_at) || "no fix";
  const fingerprintInfo = fingerprintSummary(fingerprint, device);
  const distanceKm = stats?.distance_tracked_km;
  const peakSpeed = stats?.peak_speed_kph;

  async function report() {
    setSimulating(true);
    setSimError("");
    try {
      const viewer = await getViewerLocation();
      await reportViewerLocation(device, api, viewer);
      const items = await api.locations(device.id, 1);
      if (items.length) setLast(items[0]);
      onSimulated?.();
    } catch (err) {
      setSimError(err.message || "Could not report location (grant consent / location access first)");
    } finally {
      setSimulating(false);
    }
  }

  return (
    <section className="panel device-insight">
      <div className="panel-title">
        <span className="insight-name">
          {device.device_type === "vehicle" || device.device_type === "motorcycle"
            ? <TruckIcon /> : <Smartphone size={15} />}
          {device.name?.toUpperCase() || "DEVICE"}
        </span>
        <span className={`status-pill ${live ? "status-live" : "status-offline"}`}>
          {live ? "LIVE" : "SIGNAL AWAY"}
        </span>
      </div>

      <div className="insight-grid">
        <div className="insight-cell">
          <span>LAST FIX</span>
          <strong>{lastSeenLabel}{last?.recorded_at ? ` · ${clockTime(last.recorded_at)}` : ""}</strong>
        </div>
        <div className="insight-cell">
          <span>COORDS</span>
          <strong>{last ? `${last.latitude.toFixed(5)}, ${last.longitude.toFixed(5)}` : "--, --"}</strong>
        </div>
        <div className="insight-cell">
          <span>PLACE</span>
          <strong className="insight-wrap">{last?.place_name || device?.latest_location?.place_name || "unknown"}</strong>
        </div>
        <div className="insight-cell">
          <span>SPEED · HDG · ALT</span>
          <strong>
            {last ? `${Math.round(last.speed ?? 0)} km/h · ${Math.round(last.heading ?? 0)}° · ${Math.round(last.altitude ?? 0)} m` : "--"}
          </strong>
        </div>
      </div>

      <div className="insight-divider" />

      <div className="insight-list">
        <InsightRow icon={<Smartphone size={13} />} label="MODEL / OS">
          {device.model || "--"} {device.os_type || ""} {device.os_version || ""}
        </InsightRow>
        <InsightRow icon={<Activity size={13} />} label="IMEI">
          {device.imei || "--"}
        </InsightRow>
        <InsightRow icon={<Cpu size={13} />} label="FINGERPRINT">
          {fingerprintInfo.type} — {fingerprintInfo.extra}
        </InsightRow>
        {oui && oui.vendor && (
          <InsightRow icon={<Cpu size={13} />} label="MAC VENDOR">
            {oui.vendor} ({device.mac_address})
          </InsightRow>
        )}
        <InsightRow icon={fraud?.anomaly_count > 0 ? <ShieldAlert size={13} /> : <ShieldCheck size={13} />} label="FRAUD">
          {fraudLabel(fraud)}
        </InsightRow>
        <InsightRow icon={<Globe size={13} />} label="SOURCE / IP">
          {(last?.source || device?.latest_location?.source || "--").toUpperCase()}
          {" · "}
          {last?.ip_address || device?.ip_address || "--"}
        </InsightRow>
        <InsightRow icon={<Radio size={13} />} label="HEARTBEAT">
          {heartbeatLabel(heartbeat)} {heartbeat?.updates && heartbeat.updates.length ? `(${heartbeat.updates.length} pings)` : ""}
        </InsightRow>
        <InsightRow icon={<Activity size={13} />} label="TRIP">
          {distanceKm != null ? `${distanceKm} km tracked` : "--"} {peakSpeed != null ? ` · peak ${peakSpeed} km/h` : ""}
        </InsightRow>
      </div>

      {simError && <div className="inline-error">{simError}</div>}

      <button className="command-button insight-simulate" onClick={report} disabled={simulating} type="button">
        <Activity size={14} /> {simulating ? "REPORTING…" : "REPORT MY GPS LOCATION"}
      </button>
      <p className="insight-hint">
        No tracker feed yet? Reporting records this device's position as <strong>your current exact GPS coordinates</strong> through the real ingest pipeline, with this machine's true source IP — no mock movement.
      </p>
    </section>
  );
}

function InsightRow({ icon, label, children }) {
  return (
    <div className="insight-row">
      <span className="insight-row-icon">{icon}</span>
      <span className="insight-row-label">{label}</span>
      <strong className="insight-row-value">{children}</strong>
    </div>
  );
}

function TruckIcon() {
  return <span className="insight-truck">&#128666;</span>;
}
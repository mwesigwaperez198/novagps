import { useEffect, useRef, useState } from "react";
import { Camera, PlugZap, Radar, RefreshCw } from "lucide-react";
import { api } from "../lib/api.js";

function ipToSubnet(ip) {
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip || "")) return null;
  const parts = ip.split(".");
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

function deviceIp(device) {
  return (
    device?.local_ip ||
    device?.latest_location?.local_ip ||
    device?.ip_address ||
    device?.latest_location?.ip_address ||
    ""
  );
}

const CAM_SERVICES = { 554: "RTSP", 8080: "UI", 80: "HTTP", 443: "HTTPS" };

export default function NearbyScanPanel({ device, onResults }) {
  const [subnet, setSubnet] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [camerasOnly, setCamerasOnly] = useState(false);
  const [connecting, setConnecting] = useState("");
  const [snapResult, setSnapResult] = useState("");
  const [error, setError] = useState("");
  const lastScanned = useRef(null);

  async function runScan(targetSubnet, auto = false) {
    const target = targetSubnet || subnet;
    if (!target) return;
    lastScanned.current = target;
    setSubnet(target);
    setLoading(true);
    setError("");
    if (!auto) setSnapResult("");
    try {
      const data = await api.discoveryScanNetwork(target);
      setResult(data);
      if (typeof onResults === "function") {
        onResults({ subnet: target, hosts: data.hosts || [], engine: data.engine, truncated: data.truncated });
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    const ip = deviceIp(device);
    const derived = ipToSubnet(ip);
    if (!derived) return undefined;
    if (lastScanned.current === derived) return undefined;
    const timer = setTimeout(() => runScan(derived, true), 900);
    return () => clearTimeout(timer);
    }, [device?.id, device?.local_ip, device?.latest_location?.local_ip, device?.ip_address, device?.latest_location?.ip_address]);

  const hosts = (result?.hosts || []).filter((host) => !camerasOnly || host.is_camera);
  const cameraTotal = (result?.hosts || []).filter((host) => host.is_camera).length;

  async function connectCamera(host) {
    const rtspUrl = `rtsp://${host.ip}:554`;
    setConnecting(host.ip);
    setSnapResult("");
    try {
      const shot = await api.cameraScreenshot(rtspUrl);
      setSnapResult(`CAM ${host.ip} → rtsp request sent (${shot.status || "ok"})`);
    } catch (err) {
      setSnapResult(`CAM ${host.ip} → ${err.message}`);
    } finally {
      setConnecting("");
    }
  }

  return (
    <div className="panel-inner nearby-scan">
      <h3><Radar size={14} /> Nearby Network & Cameras</h3>
      <p className="muted">
        Auto-scans the subnet of the selected device (from its local/public IP) and classifies
        cameras by open RTSP / HTTP ports.
      </p>

      <div className="input-row">
        <input value={subnet} onChange={(e) => setSubnet(e.target.value)} placeholder="Subnet (CIDR)" />
        <button onClick={() => runScan()} disabled={loading} className="btn-primary">
          {loading ? <RefreshCw size={12} className="spin" /> : <RefreshCw size={12} />}
          {loading ? "Scanning…" : "Rescan"}
        </button>
        <button
          onClick={() => setCamerasOnly(!camerasOnly)}
          className={`btn-secondary ${camerasOnly ? "is-active" : ""}`}
          type="button"
        >
          <Camera size={12} /> Cameras only ({cameraTotal})
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}
      {snapResult && <div className="result-box">{snapResult}</div>}

      {result && (
        <div className="result-box">
          <div className="scan-meta-row">
            <span>
              <strong>{result.subnet}</strong> · {result.engine === "nmap" ? "nmap" : "built-in sweep"}
              {result.truncated ? " · truncated (large range)" : ""}
            </span>
            <span>{hosts.length} host(s) · {cameraTotal} camera(s)</span>
          </div>
          {result.note && <div className="muted">{result.note}</div>}
          <table className="data-table">
            <thead>
              <tr><th>IP</th><th>MAC / Vendor</th><th>Ports</th><th>Type</th><th /></tr>
            </thead>
            <tbody>
              {hosts.map((host, index) => {
                const cam = host.is_camera || host.kind === "rtsp-camera";
                const camTag = host.kind === "rtsp-camera" ? "STREET-CAM" : host.kind === "web-ui" ? "WEB-CAM UI" : "RTSP";
                return (
                  <tr key={`${host.ip}-${index}`}>
                    <td>
                      <code>{host.ip}</code>
                      {cam && <span className="badge cam-badge">CAM</span>}
                    </td>
                    <td className="muted">
                      {host.vendor || (host.mac ? host.mac : "—")}
                    </td>
                    <td>
                      {(host.ports || []).map((port) => CAM_SERVICES[port] || port).join(", ")}
                    </td>
                    <td>{cam ? camTag : host.method === "tcp" ? "HOST" : "HOST"}</td>
                    <td>
                      {host.ports?.includes(554) && (
                        <button
                          onClick={() => connectCamera(host)}
                          disabled={connecting === host.ip}
                          className="btn-secondary"
                          type="button"
                        >
                          {connecting === host.ip ? <RefreshCw size={12} className="spin" /> : <PlugZap size={12} />}
                          {connecting === host.ip ? "…" : "RTSP"}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
              {hosts.length === 0 && (
                <tr><td colSpan="5" className="empty">No hosts found. If the device is behind carrier NAT (no local IP reported), the public subnet may not respond to probes.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
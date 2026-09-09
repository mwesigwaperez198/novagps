import { useState } from "react";
import { Camera, Network, PlugZap, RefreshCw, Search, Usb } from "lucide-react";
import { api } from "../lib/api.js";

const CAM_SERVICES = { 554: "RTSP", 8080: "UI", 80: "HTTP", 443: "HTTPS" };

export default function DiscoveryPanel() {
  const [subnet, setSubnet] = useState("192.168.1.0/24");
  const [networkResult, setNetworkResult] = useState(null);
  const [usbResult, setUsbResult] = useState(null);
  const [arpResult, setArpResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [activeScan, setActiveScan] = useState(null);
  const [camerasOnly, setCamerasOnly] = useState(false);
  const [connecting, setConnecting] = useState("");
  const [snapResult, setSnapResult] = useState("");

  async function scanNetwork(target) {
    setLoading(true);
    setError(null);
    setActiveScan("network");
    try {
      const data = await api.discoveryScanNetwork(target);
      setNetworkResult(data);
    } catch (e) {
      setError(e.message);
    }
    setLoading(false);
  }

  async function scanUsb() {
    setLoading(true);
    setError(null);
    setActiveScan("usb");
    try {
      setUsbResult(await api.discoveryUsb());
    } catch (e) {
      setError(e.message);
    }
    setLoading(false);
  }

  async function scanArp() {
    setLoading(true);
    setError(null);
    setActiveScan("arp");
    try {
      setArpResult(await api.discoveryArp());
    } catch (e) {
      setError(e.message);
    }
    setLoading(false);
  }

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

  const hosts = (networkResult?.hosts || []).filter((host) => !camerasOnly || host.is_camera);

  return (
    <div className="panel-inner discovery-panel">
      <h3><Network size={14} /> Device Discovery</h3>
      <p className="muted">Scan a subnet, the local ARP table, or USB bus for nearby devices.</p>

      <div className="input-row">
        <input value={subnet} onChange={(e) => setSubnet(e.target.value)} placeholder="Subnet (CIDR)" />
        <button onClick={() => scanNetwork(subnet)} disabled={loading} className="btn-primary">
          {loading && activeScan === "network" ? <RefreshCw size={12} className="spin" /> : <Search size={12} />}
          Scan
        </button>
        <button
          onClick={() => setCamerasOnly(!camerasOnly)}
          disabled={!networkResult}
          className={`btn-secondary ${camerasOnly ? "is-active" : ""}`}
          type="button"
        >
          <Camera size={12} /> Cameras only
        </button>
        <button onClick={scanUsb} disabled={loading} className="btn-secondary">
          <Usb size={12} /> USB
        </button>
        <button onClick={scanArp} disabled={loading} className="btn-secondary">
          <RefreshCw size={12} /> ARP
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}
      {snapResult && <div className="result-box">{snapResult}</div>}

      {networkResult && (
        <div className="result-box">
          <div className="scan-meta-row">
            <span>
              <strong>{networkResult.subnet}</strong> · {networkResult.engine === "nmap" ? "nmap" : "built-in sweep"}
              {networkResult.truncated ? " · truncated" : ""}
            </span>
            <span>{networkResult.count} host(s)</span>
          </div>
          {networkResult.note && <div className="muted">{networkResult.note}</div>}
          <table className="data-table">
            <thead>
              <tr><th>IP</th><th>MAC / Vendor</th><th>Ports</th><th>Type</th><th /></tr>
            </thead>
            <tbody>
              {hosts.map((host, index) => {
                const cam = host.is_camera || host.kind === "rtsp-camera";
                const camTag = host.kind === "rtsp-camera" ? "STREET-CAM" : host.kind === "web-ui" ? "WEB-CAM UI" : "HOST";
                return (
                  <tr key={`${host.ip}-${index}`}>
                    <td>
                      <code>{host.ip}</code>
                      {cam && <span className="badge cam-badge">CAM</span>}
                    </td>
                    <td className="muted">{host.vendor || host.mac || "—"}</td>
                    <td>{(host.ports || []).map((port) => CAM_SERVICES[port] || port).join(", ") || "—"}</td>
                    <td>{camTag}</td>
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
                <tr><td colSpan="5" className="empty">No hosts reported.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {usbResult && (
        <div className="result-box">
          <div><strong>USB Devices:</strong> {(usbResult.devices || usbResult.usb_devices || []).length}</div>
          {(usbResult.devices || usbResult.usb_devices || []).map((d, i) => (
            <div key={i} className="list-item">{d.description || d.raw || "unknown device"}</div>
          ))}
        </div>
      )}

      {arpResult && (
        <div className="result-box">
          <div><strong>ARP Table:</strong> {(arpResult.devices || []).length} entries</div>
          <table className="data-table">
            <thead><tr><th>IP</th><th>MAC</th><th>Method</th></tr></thead>
            <tbody>
              {(arpResult.devices || []).map((d, i) => (
                <tr key={i}><td>{d.ip || "—"}</td><td>{d.mac || "—"}</td><td>{d.method || "arp"}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
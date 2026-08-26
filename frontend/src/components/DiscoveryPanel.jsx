import { useState } from "react";
import { Network, Wifi, Usb, Search, Loader2, RefreshCw } from "lucide-react";
import { api } from "../lib/api.js";

export default function DiscoveryPanel() {
  const [subnet, setSubnet] = useState("192.168.1.0/24");
  const [networkResult, setNetworkResult] = useState(null);
  const [usbResult, setUsbResult] = useState(null);
  const [arpResult, setArpResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [activeScan, setActiveScan] = useState(null);

  async function scanNetwork() {
    setLoading(true); setError(null); setNetworkResult(null); setActiveScan("network");
    try { setNetworkResult(await api.discoveryScanNetwork(subnet)); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function scanUsb() {
    setLoading(true); setError(null); setUsbResult(null); setActiveScan("usb");
    try { setUsbResult(await api.discoveryUsb()); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function scanArp() {
    setLoading(true); setError(null); setArpResult(null); setActiveScan("arp");
    try { setArpResult(await api.discoveryArp()); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  return (
    <div className="panel-inner">
      <h3><Network size={14} /> Device Discovery</h3>
      <p className="muted">Scan network, USB, and ARP table for nearby devices</p>

      <div className="input-row">
        <input value={subnet} onChange={(e) => setSubnet(e.target.value)} placeholder="Subnet (CIDR)" />
        <button onClick={scanNetwork} disabled={loading} className="btn-primary">
          {loading && activeScan === "network" ? <Loader2 size={12} className="spin" /> : <Search size={12} />}
          Scan
        </button>
      </div>

      <div style={{ display: "flex", gap: 6, marginTop: 6 }}>
        <button onClick={scanUsb} disabled={loading} className="btn-secondary">
          <Usb size={12} /> USB
        </button>
        <button onClick={scanArp} disabled={loading} className="btn-secondary">
          <RefreshCw size={12} /> ARP
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}

      {networkResult && (
        <div className="result-box">
          <div><strong>Subnet:</strong> {networkResult.subnet}</div>
          <div><strong>Hosts Scanned:</strong> {networkResult.hosts_scanned}</div>
          <div><strong>Devices Found:</strong> {networkResult.devices_found}</div>
          {networkResult.devices?.length > 0 && (
            <table className="data-table">
              <thead><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Status</th></tr></thead>
              <tbody>
                {networkResult.devices.map((d, i) => (
                  <tr key={i}><td>{d.ip}</td><td>{d.mac}</td><td>{d.vendor}</td><td>{d.status}</td></tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {usbResult && (
        <div className="result-box">
          <div><strong>USB Devices:</strong> {usbResult.usb_devices?.length || 0}</div>
          {usbResult.usb_devices?.map((d, i) => (
            <div key={i} className="list-item">{d.product} ({d.vendor_id}:{d.product_id}) - {d.bus}</div>
          ))}
          {usbResult.serial_devices?.length > 0 && (
            <>
              <div style={{ marginTop: 6 }}><strong>Serial Ports:</strong></div>
              {usbResult.serial_devices.map((s, i) => (
                <div key={i} className="list-item">{s.device} - {s.description}</div>
              ))}
            </>
          )}
        </div>
      )}

      {arpResult && (
        <div className="result-box">
          <div><strong>ARP Table:</strong> {arpResult.devices?.length || 0} entries</div>
          {arpResult.devices?.length > 0 && (
            <table className="data-table">
              <thead><tr><th>IP</th><th>MAC</th><th>Vendor</th></tr></thead>
              <tbody>
                {arpResult.devices.map((d, i) => (
                  <tr key={i}><td>{d.ip}</td><td>{d.mac}</td><td>{d.vendor}</td></tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}

import { useState } from "react";
import { Fingerprint, Search, Shield, Loader2 } from "lucide-react";
import { api } from "../lib/api.js";

export default function FingerprintPanel({ device }) {
  const [ip, setIp] = useState("");
  const [result, setResult] = useState(null);
  const [ouiResult, setOuiResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function runFingerprint(targetIp) {
    const useIp = targetIp || ip || device?.ip_address;
    if (!useIp) { setError("No IP address available"); return; }
    setLoading(true); setError(null); setResult(null);
    try {
      const res = await api.fingerprintIp(useIp);
      setResult(res);
    } catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function runOui() {
    if (!device?.id) { setError("Select a device first"); return; }
    setLoading(true); setError(null); setOuiResult(null);
    try {
      const res = await api.deviceOui(device.id);
      setOuiResult(res);
    } catch (e) { setError(e.message); }
    setLoading(false);
  }

  return (
    <div className="panel-inner">
      <h3><Fingerprint size={14} /> Device Fingerprinting</h3>
      <p className="muted">OS fingerprint via TCP/IP stack analysis &amp; MAC vendor lookup</p>

      <div className="input-row">
        <input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="IP (uses device IP if empty)" />
        <button onClick={() => runFingerprint()} disabled={loading} className="btn-primary">
          {loading ? <Loader2 size={12} className="spin" /> : <Search size={12} />}
          Fingerprint
        </button>
      </div>

      <button onClick={runOui} disabled={loading || !device?.id} className="btn-secondary" style={{ marginTop: 6 }}>
        <Shield size={12} /> MAC Vendor Lookup
      </button>

      {error && <div className="error-box">{error}</div>}

      {result && (
        <div className="result-box">
          <div><strong>IP:</strong> {result.ip}</div>
          <div><strong>OS Guess:</strong> {result.os_guess || "Unknown"}</div>
          <div><strong>Confidence:</strong> {(result.confidence * 100).toFixed(0)}%</div>
          <div><strong>TTL:</strong> {result.ttl}</div>
          <div><strong>TCP Window:</strong> {result.tcp_window_size}</div>
          <div><strong>DF Bit:</strong> {result.dont_fragment ? "Yes" : "No"}</div>
          {result.initial_ttl_guess && <div><strong>Initial TTL:</strong> {result.initial_ttl_guess}</div>}
          {result.raw_flags && <div><strong>Raw Flags:</strong> {JSON.stringify(result.raw_flags)}</div>}
          {result.metadata && Object.keys(result.metadata).length > 0 && (
            <div><strong>Metadata:</strong> <pre>{JSON.stringify(result.metadata, null, 2)}</pre></div>
          )}
        </div>
      )}

      {ouiResult && (
        <div className="result-box">
          <div><strong>MAC:</strong> {ouiResult.mac}</div>
          <div><strong>Vendor:</strong> {ouiResult.vendor || "Unknown"}</div>
          {ouiResult.device_id && <div><strong>Device:</strong> {ouiResult.device_id}</div>}
        </div>
      )}
    </div>
  );
}

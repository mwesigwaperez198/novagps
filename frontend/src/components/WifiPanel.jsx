import { useState } from "react";
import { Radio, Wifi, Search, Loader2, Zap, Ban, KeyRound } from "lucide-react";
import { api } from "../lib/api.js";

export default function WifiPanel() {
  const [iface, setIface] = useState("wlan0");
  const [scanResult, setScanResult] = useState(null);
  const [handshakeResult, setHandshakeResult] = useState(null);
  const [wpsResult, setWpsResult] = useState(null);
  const [deauthResult, setDeauthResult] = useState(null);
  const [crackResult, setCrackResult] = useState(null);
  const [crackFile, setCrackFile] = useState("");
  const [wordlist, setWordlist] = useState("/usr/share/wordlists/rockyou.txt");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState("scan");

  async function doScan() {
    setLoading(true); setError(null); setScanResult(null);
    try { setScanResult(await api.wifiScan(iface)); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function doHandshake(bssid) {
    setLoading(true); setError(null); setHandshakeResult(null); setCrackResult(null);
    try {
      const res = await api.wifiCaptureHandshake(iface, bssid);
      setHandshakeResult(res);
      if (res && res.capture_file) setCrackFile(res.capture_file);
    }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function doWps(bssid) {
    setLoading(true); setError(null); setWpsResult(null);
    try { setWpsResult(await api.wifiWpsAttack(iface, bssid)); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function doDeauth(bssid) {
    setLoading(true); setError(null); setDeauthResult(null);
    try { setDeauthResult(await api.wifiDeauth(iface, bssid)); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function doCrack() {
    if (!crackFile) { setError("Capture file required"); return; }
    setLoading(true); setError(null); setCrackResult(null);
    try { setCrackResult(await api.wifiCrackWpa(crackFile, wordlist)); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  return (
    <div className="panel-inner">
      <h3><Radio size={14} /> WiFi Security Tools</h3>
      <p className="muted">Scan, capture handshakes, WPS attacks, deauth, crack</p>

      <div className="tab-row">
        {["scan", "handshake", "wps", "crack"].map((t) => (
          <button key={t} className={`tab-btn ${activeTab === t ? "active" : ""}`} onClick={() => setActiveTab(t)}>
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      <div className="input-row" style={{ marginTop: 8 }}>
        <input value={iface} onChange={(e) => setIface(e.target.value)} placeholder="Interface" />
        <button onClick={doScan} disabled={loading} className="btn-primary">
          {loading ? <Loader2 size={12} className="spin" /> : <Search size={12} />}
          Scan
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}

      {scanResult && scanResult.networks?.length > 0 && (
        <div className="result-box">
          <div><strong>Networks Found:</strong> {scanResult.networks.length}</div>
          {scanResult.networks.map((n, i) => (
            <div key={i} className="list-item" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span>
                <strong>{n.ssid || "Hidden"}</strong> - CH{n.channel} {n.encryption} PWR:{n.power}
              </span>
              <span style={{ display: "flex", gap: 4 }}>
                <button className="btn-sm" onClick={() => doHandshake(n.bssid)} title="Capture handshake">
                  <Wifi size={10} />
                </button>
                {n.wps && (
                  <button className="btn-sm" onClick={() => doWps(n.bssid)} title="WPS attack">
                    <Zap size={10} />
                  </button>
                )}
                <button className="btn-sm btn-danger" onClick={() => doDeauth(n.bssid)} title="Deauth attack">
                  <Ban size={10} />
                </button>
              </span>
            </div>
          ))}
        </div>
      )}

      {handshakeResult && (
        <div className="result-box">
          <div><strong>Handshake Capture:</strong></div>
          <div><strong>Status:</strong> {handshakeResult.status}</div>
          {handshakeResult.capture_file && <div><strong>File:</strong> {handshakeResult.capture_file}</div>}
          {handshakeResult.error && <div className="error-box">{handshakeResult.error}</div>}
        </div>
      )}

      {deauthResult && (
        <div className="result-box">
          <div><strong>Deauth:</strong></div>
          <div><strong>Status:</strong> {deauthResult.status || deauthResult.message}</div>
          {deauthResult.error && <div className="error-box">{deauthResult.error}</div>}
        </div>
      )}

      {wpsResult && (
        <div className="result-box">
          <div><strong>WPS Attack:</strong></div>
          <div><strong>Status:</strong> {wpsResult.status}</div>
          {wpsResult.pin && <div><strong>PIN:</strong> {wpsResult.pin}</div>}
          {wpsResult.psk && <div><strong>PSK:</strong> {wpsResult.psk}</div>}
          {wpsResult.error && <div className="error-box">{wpsResult.error}</div>}
        </div>
      )}

      {activeTab === "crack" && (
        <div className="result-box">
          <div><strong>WPA Dictionary Crack</strong></div>
          <div className="input-row" style={{ marginTop: 6 }}>
            <input value={crackFile} onChange={(e) => setCrackFile(e.target.value)} placeholder="Capture .cap file" />
          </div>
          <div className="input-row" style={{ marginTop: 6 }}>
            <input value={wordlist} onChange={(e) => setWordlist(e.target.value)} placeholder="Wordlist path" />
          </div>
          <button className="btn-primary" onClick={doCrack} disabled={loading} style={{ marginTop: 6, width: "100%" }}>
            {loading ? <Loader2 size={12} className="spin" /> : <KeyRound size={12} />} Crack WPA
          </button>
          {crackResult && (
            <div className="result-box" style={{ marginTop: 6 }}>
              <strong>Result:</strong>
              <div><span className={crackResult.password ? "status-ok" : "status-err"}>{crackResult.status || crackResult.message}</span></div>
              {crackResult.password && <div><strong>KEY:</strong> <span className="status-ok">{crackResult.password}</span></div>}
              {crackResult.error && <div className="error-box">{crackResult.error}</div>}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

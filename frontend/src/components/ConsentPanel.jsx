import { useState, useEffect } from "react";
import { ShieldCheck, ShieldOff, Link2, History, FileCheck2, Loader2 } from "lucide-react";
import { api } from "../lib/api.js";

export default function ConsentPanel({ device }) {
  const [source, setSource] = useState("app");
  const [scope, setScope] = useState("location tracking, remote commands");
  const [reason, setReason] = useState("");
  const [history, setHistory] = useState([]);
  const [chain, setChain] = useState(null);
  const [active, setActive] = useState("capture");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  async function captureConsent() {
    if (!device?.id) return;
    setLoading(true); setError(null); setResult(null);
    try {
      const res = await api.consent({ device_id: device.id, source, scope });
      setResult({ type: "success", message: "Consent captured", data: res });
      await loadHistory();
    } catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function revokeConsent() {
    if (!device?.id) return;
    setLoading(true); setError(null); setResult(null);
    try {
      const res = await api.consentRevoke({ device_id: device.id, reason });
      setResult({ type: "success", message: `Consent revoked for ${res.revoked} active record(s)`, data: res });
      await loadHistory();
    } catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function loadHistory() {
    if (!device?.id) return;
    setLoading(true); setError(null);
    try { setHistory(await api.consentHistory(device.id)); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function verifyChain() {
    setLoading(true); setError(null);
    try { setChain(await api.consentVerifyChain()); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  useEffect(() => {
    if (device?.id) loadHistory();
  }, [device?.id]);

  if (!device) {
    return (
      <div className="panel-inner">
        <h3><ShieldCheck size={14} /> Consent & Proof</h3>
        <div className="muted">Select a device first</div>
      </div>
    );
  }

  return (
    <div className="panel-inner">
      <h3><ShieldCheck size={14} /> Consent & Proof</h3>
      <p className="muted">Record, revoke and verify lawful use consent</p>

      <div className="input-row" style={{ flexWrap: "wrap" }}>
        <button className={`btn-sm ${active === "capture" ? "btn-primary" : ""}`} onClick={() => setActive("capture")}>Capture</button>
        <button className={`btn-sm ${active === "revoke" ? "btn-primary" : ""}`} onClick={() => setActive("revoke")}>Revoke</button>
        <button className={`btn-sm ${active === "history" ? "btn-primary" : ""}`} onClick={() => { setActive("history"); loadHistory(); }}>History</button>
        <button className={`btn-sm ${active === "chain" ? "btn-primary" : ""}`} onClick={() => { setActive("chain"); verifyChain(); }}>Verify</button>
      </div>

      <div className="remote-device-info">
        <div className="device-info-row"><span className="info-label">Device</span><span>{device.name}</span></div>
        <div className="device-info-row"><span className="info-label">Email</span><span>{device.email}</span></div>
      </div>

      {error && <div className="error-box">{error}</div>}
      {result && (
        <div className="result-box">
          <div className="status-ok">{result.message}</div>
          {result.data?.chain_hash && <div className="muted" style={{ wordBreak: "break-all" }}>Hash: {result.data.chain_hash}</div>}
          {result.data?.consent_id && <div className="muted">ID: {result.data.consent_id}</div>}
        </div>
      )}

      {active === "capture" && (
        <div className="remote-section">
          <div className="section-label"><Link2 size={12} /> <span>Capture Consent</span></div>
          <input className="text-input" value={source} onChange={(e) => setSource(e.target.value)} placeholder="Source" />
          <textarea
            className="sms-input"
            value={scope}
            onChange={(e) => setScope(e.target.value)}
            placeholder="Scope of consent"
            rows={3}
          />
          <button className="btn-primary" onClick={captureConsent} disabled={loading} style={{ width: "100%" }}>
            {loading ? <Loader2 size={12} className="spin" /> : <FileCheck2 size={12} />} Capture Consent
          </button>
        </div>
      )}

      {active === "revoke" && (
        <div className="remote-section">
          <div className="section-label"><ShieldOff size={12} /> <span>Revoke Consent</span></div>
          <input className="text-input" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason (optional)" />
          <button className="btn-primary btn-danger" onClick={revokeConsent} disabled={loading} style={{ width: "100%" }}>
            {loading ? <Loader2 size={12} className="spin" /> : <ShieldOff size={12} />} Revoke
          </button>
        </div>
      )}

      {active === "history" && (
        <div className="remote-section">
          <div className="section-label"><History size={12} /> <span>Anchored History</span></div>
          {history.length === 0 && !loading && <div className="muted">No consent history</div>}
          {history.map((h, i) => (
            <div key={i} className="list-item">
              <div style={{ display: "flex", justifyContent: "space-between" }}>
                <span className={`verdict verdict-${h.action === "capture" ? "healthy" : "offline"}`}>{h.action.toUpperCase()}</span>
                <span className="muted">{h.anchored_at?.substring(0, 19)}</span>
              </div>
              <div className="muted" style={{ wordBreak: "break-all" }} title={h.chain_hash}>Hash: {h.chain_hash?.substring(0, 24)}...</div>
            </div>
          ))}
        </div>
      )}

      {active === "chain" && (
        <div className="remote-section">
          <div className="section-label"><FileCheck2 size={12} /> <span>Chain Integrity</span></div>
          {!chain && !loading && <div className="muted">Verify the consent hash chain</div>}
          {chain && (
            <div className="result-box">
              <div className={chain.valid ? "status-ok" : "status-err"}>
                {chain.valid ? "CHAIN VALID" : "CHAIN BROKEN"}
              </div>
              <div className="list-item" style={{ display: "flex", justifyContent: "space-between" }}>
                <span className="muted">Checked</span><span>{chain.checked}</span>
              </div>
              <div className="list-item" style={{ display: "flex", justifyContent: "space-between" }}>
                <span className="muted">Broken at</span><span>{chain.broken_at ?? "None"}</span>
              </div>
              {chain.last_chain_hash && <div className="muted" style={{ wordBreak: "break-all" }}>Head: {chain.last_chain_hash.substring(0, 32)}...</div>}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

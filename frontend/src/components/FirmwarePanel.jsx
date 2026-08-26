import { useState } from "react";
import { Cpu, Search, Activity, AlertTriangle, Loader2 } from "lucide-react";
import { api } from "../lib/api.js";

export default function FirmwarePanel({ device }) {
  const [cveKeyword, setCveKeyword] = useState("");
  const [diagIp, setDiagIp] = useState("");
  const [manufacturer, setManufacturer] = useState("");
  const [model, setModel] = useState("");
  const [firmwareVer, setFirmwareVer] = useState("");
  const [cveResult, setCveResult] = useState(null);
  const [diagResult, setDiagResult] = useState(null);
  const [healthResult, setHealthResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function searchCve() {
    if (!cveKeyword) return;
    setLoading(true); setError(null); setCveResult(null);
    try { setCveResult(await api.firmwareCve(cveKeyword)); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function diagnose() {
    const useIp = diagIp || device?.ip_address;
    if (!useIp) { setError("No IP address"); return; }
    setLoading(true); setError(null); setDiagResult(null);
    try { setDiagResult(await api.firmwareDiagnose(useIp, manufacturer, model, firmwareVer)); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function checkHealth() {
    const useIp = diagIp || device?.ip_address;
    if (!useIp) { setError("No IP address"); return; }
    setLoading(true); setError(null); setHealthResult(null);
    try { setHealthResult(await api.firmwareHealth(useIp)); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  return (
    <div className="panel-inner">
      <h3><Cpu size={14} /> Firmware Analysis</h3>
      <p className="muted">CVE lookup, firmware diagnosis, health check</p>

      <div className="section-label">CVE Search</div>
      <div className="input-row">
        <input value={cveKeyword} onChange={(e) => setCveKeyword(e.target.value)} placeholder="Firmware/kernel version" />
        <button onClick={searchCve} disabled={loading} className="btn-primary">
          {loading ? <Loader2 size={12} className="spin" /> : <Search size={12} />}
          Search
        </button>
      </div>

      {cveResult && cveResult.vulnerabilities?.length > 0 && (
        <div className="result-box">
          <div><strong>{cveResult.total_results} CVEs found</strong> (showing {cveResult.vulnerabilities.length})</div>
          {cveResult.vulnerabilities.map((v, i) => (
            <div key={i} className="list-item">
              <strong>{v.cve_id}</strong> <span className={`severity-${v.severity}`}>{v.severity}</span>
              <div className="muted">{v.description?.substring(0, 120)}...</div>
            </div>
          ))}
        </div>
      )}

      <div className="section-label">Firmware Diagnosis</div>
      <div className="input-row">
        <input value={diagIp} onChange={(e) => setDiagIp(e.target.value)} placeholder="IP" style={{ width: "30%" }} />
        <input value={manufacturer} onChange={(e) => setManufacturer(e.target.value)} placeholder="Manufacturer" style={{ width: "25%" }} />
        <input value={model} onChange={(e) => setModel(e.target.value)} placeholder="Model" style={{ width: "22%" }} />
        <input value={firmwareVer} onChange={(e) => setFirmwareVer(e.target.value)} placeholder="FW ver" style={{ width: "23%" }} />
      </div>
      <div style={{ display: "flex", gap: 6, marginTop: 6 }}>
        <button onClick={diagnose} disabled={loading} className="btn-primary">
          {loading ? <Loader2 size={12} className="spin" /> : <Cpu size={12} />}
          Diagnose
        </button>
        <button onClick={checkHealth} disabled={loading} className="btn-secondary">
          <Activity size={12} /> Health Check
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}

      {diagResult && (
        <div className="result-box">
          <div><strong>Firmware Info:</strong></div>
          <pre>{JSON.stringify(diagResult.firmware_info || diagResult, null, 2)}</pre>
          {diagResult.vulnerabilities?.length > 0 && (
            <>
              <div style={{ marginTop: 6 }}><AlertTriangle size={12} /> Vulnerabilities:</div>
              {diagResult.vulnerabilities.map((v, i) => (
                <div key={i} className="list-item"><strong>{v.cve_id || v.id}</strong> - {v.description?.substring(0, 100)}</div>
              ))}
            </>
          )}
          {diagResult.recommendations?.length > 0 && (
            <>
              <div style={{ marginTop: 6 }}>Recommendations:</div>
              {diagResult.recommendations.map((r, i) => (
                <div key={i} className="list-item">{r}</div>
              ))}
            </>
          )}
        </div>
      )}

      {healthResult && (
        <div className="result-box">
          <div><strong>Health Check:</strong> <span className={healthResult.status === "ok" ? "status-ok" : "status-warn"}>{healthResult.status}</span></div>
          {healthResult.details && <pre>{JSON.stringify(healthResult.details, null, 2)}</pre>}
          {healthResult.checks?.map((c, i) => (
            <div key={i} className="list-item">
              <span className={c.status === "ok" ? "status-ok" : "status-warn"}>{c.status}</span> {c.name}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

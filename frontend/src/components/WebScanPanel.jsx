import { useState } from "react";
import { Globe } from "lucide-react";
import { api } from "../lib/api.js";

export default function WebScanPanel() {
  const [scanType, setScanType] = useState("headers");
  const [target, setTarget] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const scans = [
    { id: "headers", label: "Security Headers", fn: (t) => api.osintHttpHeaders(t) },
    { id: "nikto", label: "Nikto Scan", fn: (t) => api.osintNikto(t) },
    { id: "sqlmap", label: "SQL Injection", fn: (t) => api.osintSqlmap(t) },
  ];

  async function runScan() {
    if (!target.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const scan = scans.find((s) => s.id === scanType);
      const data = await scan.fn(target);
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="panel webscan-panel">
      <div className="panel-title">
        <span>WEB_SCAN</span>
        <Globe size={15} />
      </div>
      <div className="tool-controls">
        <select value={scanType} onChange={(e) => setScanType(e.target.value)}>
          {scans.map((s) => (
            <option key={s.id} value={s.id}>{s.label}</option>
          ))}
        </select>
        <div className="target-row">
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://target.com"
            onKeyDown={(e) => e.key === "Enter" && runScan()}
          />
          <button className="command-button" onClick={runScan} disabled={loading}>
            {loading ? "..." : "ANALYZE"}
          </button>
        </div>
      </div>
      {error && <div className="inline-error">{error}</div>}
      {result && (
        <div className="scan-result">
          <pre>{JSON.stringify(result, null, 2)}</pre>
        </div>
      )}
    </section>
  );
}

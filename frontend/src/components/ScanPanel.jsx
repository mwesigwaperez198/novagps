import { useState } from "react";
import { Radar } from "lucide-react";
import { api } from "../lib/api.js";

export default function ScanPanel() {
  const [scanType, setScanType] = useState("topports");
  const [target, setTarget] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const scans = [
    { id: "topports", label: "Top 20 Ports", tool: "net.scan.topports" },
    { id: "full", label: "Full TCP", tool: "net.scan.full" },
    { id: "udp", label: "Top 20 UDP", tool: "net.scan.udp" },
    { id: "services", label: "Service Versions", tool: "net.scan.services" },
    { id: "masscan", label: "Masscan (Fast)", tool: "net.scan.masscan" },
  ];

  async function runScan() {
    if (!target.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const scan = scans.find((s) => s.id === scanType);
      const data = await api.diagnose({ command_id: scan.tool, args: { target } });
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="panel scan-panel">
      <div className="panel-title">
        <span>PORT_SCAN</span>
        <Radar size={15} />
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
            placeholder="IP or domain"
            onKeyDown={(e) => e.key === "Enter" && runScan()}
          />
          <button className="command-button" onClick={runScan} disabled={loading}>
            {loading ? "..." : "SCAN"}
          </button>
        </div>
      </div>
      {error && <div className="inline-error">{error}</div>}
      {result && (
        <div className="scan-result">
          <div className="scan-meta">
            <span>exit={result.exit_code}</span>
            <code>{result.output_hash?.slice(0, 12)}</code>
          </div>
          <pre>{result.output}</pre>
        </div>
      )}
    </section>
  );
}

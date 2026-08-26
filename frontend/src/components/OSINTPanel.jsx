import { useState } from "react";
import { Search } from "lucide-react";
import { api } from "../lib/api.js";

export default function OSINTPanel() {
  const [tool, setTool] = useState("whois");
  const [target, setTarget] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const tools = [
    { id: "whois", label: "WHOIS", placeholder: "example.com" },
    { id: "dns-brute", label: "DNS Brute", placeholder: "example.com" },
    { id: "reverse-dns", label: "Reverse DNS", placeholder: "8.8.8.8" },
    { id: "http-headers", label: "HTTP Headers", placeholder: "https://example.com" },
    { id: "nikto", label: "Nikto Scan", placeholder: "example.com" },
    { id: "sqlmap", label: "SQLMap", placeholder: "https://example.com/page?id=1" },
  ];

  async function runScan() {
    if (!target.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      let data;
      switch (tool) {
        case "whois": data = await api.osintWhois(target); break;
        case "dns-brute": data = await api.osintDnsBrute(target); break;
        case "reverse-dns": data = await api.osintReverseDns(target); break;
        case "http-headers": data = await api.osintHttpHeaders(target); break;
        case "nikto": data = await api.osintNikto(target); break;
        case "sqlmap": data = await api.osintSqlmap(target); break;
        default: data = { error: "unknown tool" };
      }
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  const currentTool = tools.find((t) => t.id === tool);

  return (
    <section className="panel osint-panel">
      <div className="panel-title">
        <span>OSINT</span>
        <Search size={15} />
      </div>
      <div className="tool-controls">
        <select value={tool} onChange={(e) => { setTool(e.target.value); setResult(null); setError(""); }}>
          {tools.map((t) => (
            <option key={t.id} value={t.id}>{t.label}</option>
          ))}
        </select>
        <div className="target-row">
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={currentTool?.placeholder || "target"}
            onKeyDown={(e) => e.key === "Enter" && runScan()}
          />
          <button className="command-button" onClick={runScan} disabled={loading}>
            {loading ? "..." : "RUN"}
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

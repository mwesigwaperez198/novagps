import { useState } from "react";
import { FileSearch } from "lucide-react";
import { api } from "../lib/api.js";

export default function ForensicsPanel() {
  const [tool, setTool] = useState("hash");
  const [target, setTarget] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const tools = [
    { id: "hash", label: "SHA-256 Hash", command: "forensics.hash.file", argKey: "path" },
    { id: "yara", label: "YARA Scan", command: "forensics.yara.scan", argKey: "path" },
    { id: "crack", label: "John the Ripper", command: "cred.crack.hash", argKey: "path" },
    { id: "cert", label: "TLS Certificate", command: "crypto.info", argKey: "target" },
  ];

  async function runTool() {
    if (!target.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const t = tools.find((x) => x.id === tool);
      const data = await api.diagnose({ command_id: t.command, args: { [t.argKey]: target } });
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="panel forensics-panel">
      <div className="panel-title">
        <span>FORENSICS</span>
        <FileSearch size={15} />
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
            placeholder={tool === "cert" ? "example.com:443" : "/path/to/file"}
            onKeyDown={(e) => e.key === "Enter" && runTool()}
          />
          <button className="command-button" onClick={runTool} disabled={loading}>
            {loading ? "..." : "RUN"}
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

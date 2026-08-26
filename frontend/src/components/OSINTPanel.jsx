import { useState } from "react";
import { Search, Globe, Mail, Server, Shield, Code, Database } from "lucide-react";
import { api } from "../lib/api.js";

const OSINT_TOOLS = [
  { id: "whois", label: "WHOIS", icon: Globe, argKey: "domain", apiCall: "osintWhois", placeholder: "example.com" },
  { id: "dnsbrute", label: "DNS Bruteforce", icon: Server, argKey: "domain", apiCall: "osintDnsBrute", placeholder: "example.com" },
  { id: "revdns", label: "Reverse DNS", icon: Globe, argKey: "ip", apiCall: "osintReverseDns", placeholder: "8.8.8.8" },
  { id: "headers", label: "HTTP Headers", icon: Code, argKey: "url", apiCall: "osintHttpHeaders", placeholder: "https://example.com" },
  { id: "harvester", label: "theHarvester", icon: Mail, argKey: "domain", apiCall: "osintTheharvester", placeholder: "example.com" },
  { id: "whatweb", label: "WhatWeb", icon: Globe, argKey: "url", apiCall: "osintWhatweb", placeholder: "https://example.com" },
  { id: "wpscan", label: "WPScan", icon: Shield, argKey: "url", apiCall: "osintWpscan", placeholder: "https://wordpress-site.com" },
  { id: "dirb", label: "Dirb", icon: Database, argKey: "url", apiCall: "osintDirb", placeholder: "https://example.com" },
  { id: "sublist3r", label: "Sublist3r", icon: Globe, argKey: "domain", apiCall: "osintSublist3r", placeholder: "example.com" },
  { id: "nikto", label: "Nikto", icon: Shield, argKey: "target", apiCall: "osintNikto", placeholder: "example.com" },
  { id: "sqlmap", label: "SQLMap", icon: Database, argKey: "url", apiCall: "osintSqlmap", placeholder: "https://example.com/page?id=1" },
];

const PENTEST_TOOLS = [
  { id: "vulnscan", label: "Vuln Scan", icon: Shield, argKey: "target", apiCall: "pentestVulnScan", placeholder: "example.com" },
  { id: "authscan", label: "Auth Scan", icon: Shield, argKey: "target", apiCall: "pentestAuthScan", placeholder: "example.com" },
  { id: "topports", label: "Top 20 Ports", icon: Server, argKey: "target", apiCall: "toolRun", placeholder: "example.com", commandId: "net.scan.topports" },
  { id: "fulltcp", label: "Full TCP", icon: Server, argKey: "target", apiCall: "toolRun", placeholder: "example.com", commandId: "net.scan.full" },
  { id: "udpscan", label: "UDP Scan", icon: Server, argKey: "target", apiCall: "toolRun", placeholder: "example.com", commandId: "net.scan.udp" },
  { id: "sversion", label: "Service Version", icon: Server, argKey: "target", apiCall: "toolRun", placeholder: "example.com", commandId: "net.scan.services" },
  { id: "masscan", label: "Masscan", icon: Server, argKey: "target", apiCall: "toolRun", placeholder: "example.com", commandId: "net.scan.masscan" },
  { id: "vulnscript", label: "Nmap Vuln Script", icon: Shield, argKey: "target", apiCall: "toolRun", placeholder: "example.com", commandId: "pentest.nmap.vuln" },
  { id: "exploitscript", label: "Nmap Exploit", icon: Shield, argKey: "target", apiCall: "toolRun", placeholder: "example.com", commandId: "pentest.nmap.exploit" },
  { id: "brutescript", label: "Nmap Brute", icon: Shield, argKey: "target", apiCall: "toolRun", placeholder: "example.com", commandId: "pentest.nmap.brute" },
  { id: "dosscript", label: "Nmap DoS", icon: Shield, argKey: "target", apiCall: "toolRun", placeholder: "example.com", commandId: "pentest.nmap.dos" },
  { id: "fuzzscript", label: "Nmap Fuzz", icon: Shield, argKey: "target", apiCall: "toolRun", placeholder: "example.com", commandId: "pentest.nmap.fuzz" },
];

export default function OSINTPanel() {
  const [activeTab, setActiveTab] = useState("osint");
  const [selectedTool, setSelectedTool] = useState(OSINT_TOOLS[0]);
  const [input, setInput] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const tools = activeTab === "osint" ? OSINT_TOOLS : PENTEST_TOOLS;

  const handleRun = async () => {
    if (!input.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      let data;
      if (selectedTool.apiCall === "toolRun") {
        data = await api.toolRun(selectedTool.commandId, { [selectedTool.argKey]: input.trim() });
      } else {
        data = await api[selectedTool.apiCall](input.trim());
      }
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="panel tool-panel">
      <div className="panel-title">
        <span>OSINT & PENTEST</span>
      </div>
      <div className="panel-tabs">
        <button className={`panel-tab ${activeTab === "osint" ? "is-active" : ""}`} onClick={() => { setActiveTab("osint"); setSelectedTool(OSINT_TOOLS[0]); setResult(null); }}>
          OSINT
        </button>
        <button className={`panel-tab ${activeTab === "pentest" ? "is-active" : ""}`} onClick={() => { setActiveTab("pentest"); setSelectedTool(PENTEST_TOOLS[0]); setResult(null); }}>
          PENTEST
        </button>
      </div>
      <div className="tool-controls">
        <div className="tool-selector">
          {tools.map((tool) => (
            <button
              key={tool.id}
              className={`command-button ${selectedTool.id === tool.id ? "is-active" : ""}`}
              onClick={() => { setSelectedTool(tool); setResult(null); setError(""); }}
              title={tool.label}
            >
              {tool.label}
            </button>
          ))}
        </div>
        <div className="target-row">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={selectedTool.placeholder}
            onKeyDown={(e) => e.key === "Enter" && handleRun()}
          />
          <button className="command-button" onClick={handleRun} disabled={loading || !input.trim()}>
            {loading ? "RUNNING..." : "RUN"}
          </button>
        </div>
      </div>
      {error && <div className="inline-error">{error}</div>}
      {result && (
        <div className="scan-result">
          <div className="scan-meta">
            <span>{selectedTool.label}</span>
            <span>{new Date().toLocaleTimeString()}</span>
          </div>
          <pre>{JSON.stringify(result, null, 2)}</pre>
        </div>
      )}
    </section>
  );
}

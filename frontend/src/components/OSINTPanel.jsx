import { useState } from "react";
import { Search, Globe, Mail, Server, Shield, Code, Database, Phone, User } from "lucide-react";
import { api } from "../lib/api.js";

const OSINT_TOOLS = [
  { id: "phone", label: "Phone Lookup", icon: Phone, argKey: "phone", apiCall: "osintPhoneLookup", placeholder: "+256786419318" },
  { id: "email", label: "Email Lookup", icon: Mail, argKey: "email", apiCall: "osintEmailLookup", placeholder: "user@example.com" },
  { id: "whois", label: "WHOIS", icon: Globe, argKey: "domain", apiCall: "osintWhois", placeholder: "example.com" },
  { id: "dnsbrute", label: "DNS Bruteforce", icon: Server, argKey: "domain", apiCall: "osintDnsBrute", placeholder: "example.com" },
  { id: "revdns", label: "Reverse DNS", icon: Globe, argKey: "ip", apiCall: "osintReverseDns", placeholder: "8.8.8.8" },
  { id: "headers", label: "HTTP Headers", icon: Code, argKey: "url", apiCall: "osintHttpHeaders", placeholder: "https://example.com" },
  { id: "harvester", label: "Email Harvest", icon: Mail, argKey: "domain", apiCall: "osintTheharvester", placeholder: "example.com" },
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

function renderPhoneResult(data) {
  return (
    <div className="result-card">
      <div className="result-section">
        <div className="result-label">Phone Number</div>
        <div className="result-value large">{data.phone}</div>
      </div>
      <div className="result-grid">
        {data.carrier && <div className="result-field"><span className="result-key">Carrier</span><span>{data.carrier}</span></div>}
        {data.country && <div className="result-field"><span className="result-key">Country</span><span>{data.country}</span></div>}
        {data.line_type && <div className="result-field"><span className="result-key">Type</span><span>{data.line_type}</span></div>}
        {data.email_provider && <div className="result-field"><span className="result-key">Email Provider</span><span>{data.email_provider}</span></div>}
        {data.carrier_domain && <div className="result-field"><span className="result-key">Carrier Domain</span><span>{data.carrier_domain}</span></div>}
        {data.local && <div className="result-field"><span className="result-key">Local Format</span><span>{data.local}</span></div>}
      </div>
      {data.mx_records && data.mx_records.length > 0 && (
        <div className="result-section">
          <div className="result-label">MX Records (Email Infrastructure)</div>
          {data.mx_records.map((mx, i) => <div key={i} className="result-code">{mx}</div>)}
        </div>
      )}
    </div>
  );
}

function renderEmailResult(data) {
  return (
    <div className="result-card">
      <div className="result-section">
        <div className="result-label">Email Address</div>
        <div className="result-value large">{data.email}</div>
      </div>
      <div className="result-grid">
        {data.email_provider && <div className="result-field"><span className="result-key">Provider</span><span>{data.email_provider}</span></div>}
        {data.domain_registrar && <div className="result-field"><span className="result-key">Domain Registrar</span><span>{data.domain_registrar}</span></div>}
        {data.domain_created && <div className="result-field"><span className="result-key">Domain Created</span><span>{data.domain_created}</span></div>}
        {data.domain_expires && <div className="result-field"><span className="result-key">Domain Expires</span><span>{data.domain_expires}</span></div>}
        {data.domain_organization && <div className="result-field"><span className="result-key">Organization</span><span>{data.domain_organization}</span></div>}
      </div>
      {data.mx_records && data.mx_records.length > 0 && (
        <div className="result-section">
          <div className="result-label">MX Records</div>
          {data.mx_records.map((mx, i) => <div key={i} className="result-code">{mx}</div>)}
        </div>
      )}
      {data.spf_record && (
        <div className="result-section">
          <div className="result-label">SPF Record</div>
          <div className="result-code">{data.spf_record}</div>
        </div>
      )}
      {data.dmarc_record && (
        <div className="result-section">
          <div className="result-label">DMARC Record</div>
          <div className="result-code">{data.dmarc_record}</div>
        </div>
      )}
    </div>
  );
}

function renderWhoisResult(data) {
  return (
    <div className="result-card">
      <div className="result-section">
        <div className="result-label">Domain: {data.domain}</div>
      </div>
      <div className="result-grid">
        {data.registrar && <div className="result-field"><span className="result-key">Registrar</span><span>{data.registrar}</span></div>}
        {data.created && <div className="result-field"><span className="result-key">Created</span><span>{data.created}</span></div>}
        {data.expires && <div className="result-field"><span className="result-key">Expires</span><span>{data.expires}</span></div>}
        {data.organization && <div className="result-field"><span className="result-key">Organization</span><span>{data.organization}</span></div>}
        {data.country && <div className="result-field"><span className="result-key">Country</span><span>{data.country}</span></div>}
      </div>
      {data.nameservers && data.nameservers.length > 0 && (
        <div className="result-section">
          <div className="result-label">Nameservers</div>
          {data.nameservers.map((ns, i) => <div key={i} className="result-code">{ns}</div>)}
        </div>
      )}
    </div>
  );
}

function renderGenericResult(data, toolLabel) {
  if (data.error) {
    return <div className="result-error">{data.error}</div>;
  }

  const skipKeys = new Set(["raw"]);
  const sections = [];

  const mainFields = [];
  const listFields = [];

  for (const [key, value] of Object.entries(data)) {
    if (skipKeys.has(key) || key === "error") continue;
    if (Array.isArray(value) && value.length > 0) {
      listFields.push({ key, value });
    } else if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      mainFields.push({ key, value: String(value) });
    } else if (typeof value === "object" && value !== null && !Array.isArray(value)) {
      const entries = Object.entries(value);
      if (entries.length > 0) {
        listFields.push({ key, value: entries.map(([k, v]) => `${k}: ${v}`) });
      }
    }
  }

  return (
    <div className="result-card">
      {mainFields.length > 0 && (
        <div className="result-grid">
          {mainFields.map(({ key, value }) => (
            <div key={key} className="result-field">
              <span className="result-key">{key.replace(/_/g, " ")}</span>
              <span>{value}</span>
            </div>
          ))}
        </div>
      )}
      {listFields.map(({ key, value }) => (
        <div key={key} className="result-section">
          <div className="result-label">{key.replace(/_/g, " ")} ({Array.isArray(value) ? value.length : value.length})</div>
          <div className="result-list">
            {value.map((item, i) => <div key={i} className="result-code">{typeof item === "string" ? item : JSON.stringify(item)}</div>)}
          </div>
        </div>
      ))}
      {data.raw && (
        <details className="result-raw">
          <summary>Raw Output</summary>
          <pre>{data.raw}</pre>
        </details>
      )}
    </div>
  );
}

function renderResult(data, tool) {
  if (data.error) return <div className="result-error">{data.error}</div>;
  if (tool.apiCall === "osintPhoneLookup") return renderPhoneResult(data);
  if (tool.apiCall === "osintEmailLookup") return renderEmailResult(data);
  if (tool.apiCall === "osintWhois") return renderWhoisResult(data);
  return renderGenericResult(data, tool.label);
}

export default function OSINTPanel() {
  const [activeTab, setActiveTab] = useState("osint");
  const [selectedTool, setSelectedTool] = useState(OSINT_TOOLS[0]);
  const [input, setInput] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [history, setHistory] = useState([]);

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
      } else if (selectedTool.apiCall === "osintPhoneLookup") {
        data = await api.osintPhoneLookup(input.trim());
      } else {
        data = await api[selectedTool.apiCall](input.trim());
      }
      setResult(data);
      setHistory((prev) => [{ tool: selectedTool.label, target: input.trim(), time: new Date().toLocaleTimeString() }, ...prev].slice(0, 20));
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
        {history.length > 0 && (
          <button className={`panel-tab ${activeTab === "history" ? "is-active" : ""}`} onClick={() => setActiveTab("history")}>
            LOG ({history.length})
          </button>
        )}
      </div>

      {activeTab === "history" ? (
        <div className="history-list">
          {history.map((item, i) => (
            <div key={i} className="history-item" onClick={() => { setSelectedTool(tools.find((t) => t.label === item.tool) || OSINT_TOOLS[0]); setInput(item.target); setActiveTab("osint"); }}>
              <span className="history-time">{item.time}</span>
              <span className="history-tool">{item.tool}</span>
              <span className="history-target">{item.target}</span>
            </div>
          ))}
        </div>
      ) : (
        <>
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
              {renderResult(result, selectedTool)}
            </div>
          )}
        </>
      )}
    </section>
  );
}

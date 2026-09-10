import { useState, useRef, useEffect } from "react";
import {
  Braces, Camera, Crosshair, Fingerprint, Loader2, MapPin,
  Network, Radio, ScanLine, Send, ShieldCheck, ShieldAlert,
  Truck, Unlock, Wifi, Zap,
} from "lucide-react";
import { api } from "../lib/api.js";

const QUICK_ACTIONS = [
  { id: "health", label: "System Health", icon: Zap, command: "analyze system health and status" },
  { id: "ports", label: "Port Scan", icon: ScanLine, command: "scan open ports on localhost" },
  { id: "network", label: "Network Info", icon: Network, command: "show network interfaces and connectivity" },
  { id: "processes", label: "Processes", icon: Radio, command: "list running processes" },
  { id: "cameras", label: "Find Cameras", icon: Camera, command: "discover cameras on the network" },
  { id: "fingerprint", label: "Fingerprint", icon: Fingerprint, command: "fingerprint the connected device" },
  { id: "locate", label: "Locate Device", icon: MapPin, command: "locate the connected device" },
  { id: "track", label: "Track Vehicle", icon: Truck, command: "track the vehicle" },
  { id: "shield", label: "Shield Validate", icon: ShieldCheck, command: "run all shield validators" },
  { id: "vuln", label: "Vuln Scan", icon: ShieldAlert, command: "run vulnerability scan" },
  { id: "dns", label: "DNS Resolve", icon: Wifi, command: "resolve dns for google.com" },
  { id: "traceroute", label: "Traceroute", icon: Crosshair, command: "traceroute to 8.8.8.8" },
];

function ThoughtStep({ index, text }) {
  return (
    <div className="lau-thought-step">
      <span className="lau-thought-num">{index + 1}</span>
      <span className="lau-thought-text">{text}</span>
    </div>
  );
}

function ActionResult({ result }) {
  if (!result) return null;
  const intent = result.intent || "unknown";
  const action = result.action;
  const response = result.response || "";
  const thoughtProcess = result.thought_process || [];
  const toolsExecuted = result.tools_executed || [];
  const results = result.results || {};
  const engine = result.engine || "";

  return (
    <div className="lau-result-card">
      <div className="lau-result-header">
        <div className="lau-result-intent">
          <Zap size={12} /> {intent.replace(/_/g, " ")}
        </div>
        {engine && <span className="lau-result-engine">{engine}</span>}
      </div>

      {thoughtProcess.length > 0 && (
        <div className="lau-thought-block">
          {thoughtProcess.map((step, i) => <ThoughtStep key={i} index={i} text={step} />)}
        </div>
      )}

      <div className="lau-result-response">{response}</div>

      {toolsExecuted.length > 0 && (
        <div className="lau-result-tools">
          Tools: {toolsExecuted.map((t) => <code key={t}>{t}</code>)}
        </div>
      )}

      {Object.keys(results).length > 0 && Object.entries(results).map(([key, val]) => {
        if (key === "_reasoning") return null;
        const output = val?.output || val;
        if (!output || (typeof output === "object" && Object.keys(output).length === 0)) return null;
        return (
          <div key={key} className="lau-result-section">
            <div className="lau-result-section-label">{key.replace(/_/g, " ")}</div>
            {typeof output === "string" ? (
              <pre className="lau-result-code">{output}</pre>
            ) : (
              <pre className="lau-result-code">{JSON.stringify(output, null, 2)}</pre>
            )}
          </div>
        );
      })}

      {action && (
        <div className="lau-result-action">
          <span className="lau-action-badge">{action.method}</span>
          <code>{action.endpoint}</code>
        </div>
      )}
    </div>
  );
}

export default function LAUAgentPanel() {
  const [input, setInput] = useState("");
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [engineState, setEngineState] = useState(null);
  const scrollRef = useRef(null);
  const inputRef = useRef(null);

  useEffect(() => {
    api.novaEngineStatus()
      .then(setEngineState)
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [history]);

  async function dispatch(command) {
    if (!command.trim() || loading) return;
    const entry = { id: Date.now(), role: "user", text: command };
    setHistory((h) => [...h, entry]);
    setInput("");
    setLoading(true);
    try {
      const result = await api.novaAgentDispatch(command);
      setHistory((h) => [...h, { id: Date.now(), role: "lau", result }]);
    } catch (err) {
      setHistory((h) => [...h, {
        id: Date.now(),
        role: "lau",
        result: { intent: "error", response: `LAU error: ${err.message}`, thought_process: [] },
      }]);
    } finally {
      setLoading(false);
      inputRef.current?.focus();
    }
  }

  function handleSubmit(e) {
    e.preventDefault();
    dispatch(input);
  }

  const engineReady = engineState?.state === "ready" || engineState?.state === "shield_only";

  return (
    <div className="lau-panel">
      <div className="lau-header">
        <div className="lau-header-left">
          <Braces size={16} className="lau-icon" />
          <div>
            <div className="lau-title">LAU AGENT</div>
            <div className="lau-subtitle">Queen of the System</div>
          </div>
        </div>
        <div className="lau-header-right">
          <span className={engineReady ? "lau-status-dot online" : "lau-status-dot"}>
            {engineState?.state || "loading"}
          </span>
        </div>
      </div>

      <div className="lau-scroll" ref={scrollRef}>
        {history.length === 0 && (
          <div className="lau-welcome">
            <div className="lau-welcome-text">
              I am LAU. I can analyze, scan, track, secure, and protect.
              Tell me what you need or pick an action below.
            </div>
            <div className="lau-actions-grid">
              {QUICK_ACTIONS.map((a) => (
                <button
                  key={a.id}
                  className="lau-action-btn"
                  onClick={() => dispatch(a.command)}
                  disabled={loading}
                  type="button"
                >
                  <a.icon size={13} />
                  <span>{a.label}</span>
                </button>
              ))}
            </div>
          </div>
        )}

        {history.map((entry) => (
          <div key={entry.id} className={entry.role === "user" ? "lau-msg-user" : "lau-msg-agent"}>
            {entry.role === "user" ? (
              <div className="lau-msg-user-bubble">{entry.text}</div>
            ) : (
              <ActionResult result={entry.result} />
            )}
          </div>
        ))}

        {loading && (
          <div className="lau-msg-agent">
            <div className="lau-thinking">
              <Loader2 size={13} className="spin" /> LAU is thinking...
            </div>
          </div>
        )}

        {history.length > 0 && !loading && (
          <div className="lau-actions-row">
            {QUICK_ACTIONS.slice(0, 6).map((a) => (
              <button
                key={a.id}
                className="lau-action-chip"
                onClick={() => dispatch(a.command)}
                type="button"
              >
                <a.icon size={11} /> {a.label}
              </button>
            ))}
          </div>
        )}
      </div>

      <form className="lau-input-bar" onSubmit={handleSubmit}>
        <input
          ref={inputRef}
          className="lau-input"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask LAU anything..."
          disabled={loading}
        />
        <button
          className="lau-send-btn"
          type="submit"
          disabled={loading || !input.trim()}
        >
          {loading ? <Loader2 size={14} className="spin" /> : <Send size={14} />}
        </button>
      </form>
    </div>
  );
}
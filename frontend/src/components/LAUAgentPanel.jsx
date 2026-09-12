import { useState, useEffect, useRef, useCallback } from "react";
import { api, request } from "../lib/api.js";

const QUICK_ACTIONS = [
  { id: "health", label: "System Health", cmd: "analyze system health and status" },
  { id: "ports", label: "Port Scan", cmd: "scan open ports on localhost" },
  { id: "network", label: "Network Info", cmd: "show network interfaces and connectivity" },
  { id: "processes", label: "Processes", cmd: "list running processes" },
  { id: "cameras", label: "Find Cameras", cmd: "discover cameras on the network" },
  { id: "fingerprint", label: "Fingerprint", cmd: "fingerprint the connected device" },
  { id: "locate", label: "Locate Device", cmd: "locate the connected device" },
  { id: "track", label: "Track Vehicle", cmd: "track the vehicle" },
  { id: "shield", label: "Shield Validate", cmd: "run all shield validators" },
  { id: "vuln", label: "Vuln Scan", cmd: "run vulnerability scan" },
  { id: "dns", label: "DNS Resolve", cmd: "resolve dns for google.com" },
  { id: "traceroute", label: "Traceroute", cmd: "traceroute to 8.8.8.8" },
];

export default function LAUHud({ isOpen, onClose, deviceId = "" }) {
  const [logs, setLogs] = useState([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [engineState, setEngineState] = useState(null);
  const scrollRef = useRef(null);
  const inputRef = useRef(null);

  useEffect(() => {
    if (isOpen) {
      api.novaEngineStatus().then(setEngineState).catch(() => {});
      inputRef.current?.focus();
    }
  }, [isOpen]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  const executeAction = useCallback(async (action) => {
    if (!action?.endpoint) return;
    setLoading(true);
    try {
      const opts = { method: action.method };
      let endpoint = action.endpoint;
      if (action.extract_body) {
        const lastUser = [...logs].reverse().find((l) => l.role === "user");
        const text = (lastUser?.text || "").trim();
        if (!/[?&]message=/.test(endpoint)) {
          endpoint += (endpoint.includes("?") ? "&" : "?") + `message=${encodeURIComponent(text)}`;
        }
      }
      const isGet = action.method === "GET";
      const data = await request(endpoint, isGet ? {} : opts);
      setLogs((prev) => [...prev, {
        id: Date.now(),
        timestamp: new Date().toLocaleTimeString("en-GB", { hour12: false }),
        engine: "EXECUTIVE_ACTION",
        thoughtProcess: null,
        outputPayload: {
          verdict: "ACTION_COMPLETED",
          actionEnforced: `${action.method} ${action.endpoint}`,
          frontendBadgeColor: "CYAN_OPERATIONAL",
        },
        rawResult: data,
      }]);
    } catch (err) {
      setLogs((prev) => [...prev, {
        id: Date.now(),
        timestamp: new Date().toLocaleTimeString("en-GB", { hour12: false }),
        engine: "EXECUTIVE_ACTION",
        thoughtProcess: null,
        outputPayload: {
          verdict: "ACTION_FAILED",
          actionEnforced: `${action.method} ${action.endpoint}: ${err.message}`,
          frontendBadgeColor: "CRITICAL_RED_FLASH",
        },
        rawResult: null,
      }]);
    } finally {
      setLoading(false);
    }
  }, [logs]);

  async function dispatch(command) {
    if (!command.trim() || loading) return;
    const ts = new Date().toLocaleTimeString("en-GB", { hour12: false });
    setInput("");
    setLoading(true);
    setLogs((prev) => [...prev, { id: `u-${Date.now()}`, timestamp: ts, role: "user", text: command }]);
    try {
      const result = await api.novaAgentDispatch(command, deviceId);
      const thoughts = (result.thought_process || []).map((t, i) => `${i === 0 ? "\u251c\u2500" : i === result.thought_process.length - 1 ? "\u2514\u2500" : "\u251c\u2500"} ${t}`).join("\n");
      setLogs((prev) => [...prev, {
        id: Date.now(),
        timestamp: new Date().toLocaleTimeString("en-GB", { hour12: false }),
        engine: (result.engine || "DETERMINISTIC_SHIELD").toUpperCase(),
        thoughtProcess: thoughts || null,
        outputPayload: {
          verdict: (result.intent || "PROCESSED").toUpperCase().replace(/_/g, " "),
          actionEnforced: result.response || "Command processed.",
          frontendBadgeColor: result.action ? "CYAN_OPERATIONAL" : "EMERALD_SUCCESS",
        },
        action: result.action || null,
        rawResult: result.results || null,
      }]);
    } catch (err) {
      setLogs((prev) => [...prev, {
        id: Date.now(),
        timestamp: new Date().toLocaleTimeString("en-GB", { hour12: false }),
        engine: "ERROR",
        thoughtProcess: null,
        outputPayload: {
          verdict: "DISPATCH_FAILED",
          actionEnforced: err.message,
          frontendBadgeColor: "CRITICAL_RED_FLASH",
        },
        rawResult: null,
      }]);
    } finally {
      setLoading(false);
      inputRef.current?.focus();
    }
  }

  const engineReady = engineState?.state === "ready" || engineState?.state === "shield_only";

  return (
    <div
      className={`lau-hud ${isOpen ? "lau-hud-open" : ""}`}
    >
      <div className="lau-hud-header">
        <div className="lau-hud-header-left">
          <span className={`lau-hud-dot ${engineReady ? "online" : ""}`} />
          <span className="lau-hud-title">LAU // COGNITIVE_SHIELD</span>
        </div>
        <button className="lau-hud-close" onClick={onClose} type="button">ESC</button>
      </div>

      <div className="lau-hud-terminal" ref={scrollRef}>
        {logs.length === 0 && (
          <div className="lau-hud-idle">
            [LAU Terminal Idle &mdash; Monitoring Background Telemetry Matrix]
          </div>
        )}

        {logs.map((log) => {
          if (log.role === "user") {
            return (
              <div key={log.id} className="lau-hud-user-line">
                <span className="lau-hud-prompt">&gt;_</span> {log.text}
              </div>
            );
          }
          return (
            <div key={log.id} className="lau-hud-entry">
              <div className="lau-hud-entry-header">
                <span>ENG: {log.engine}</span>
                <span>{log.timestamp}</span>
              </div>
              {log.thoughtProcess && (
                <div className="lau-hud-monologue">
                  <p className="lau-hud-monologue-title">INTERNAL_MONOLOGUE:</p>
                  <pre className="lau-hud-monologue-text">{log.thoughtProcess}</pre>
                </div>
              )}
              <div className="lau-hud-verdict">
                <span>VERDICT: </span>
                <span className={
                  log.outputPayload.frontendBadgeColor === "CRITICAL_RED_FLASH"
                    ? "lau-verdict-critical"
                    : "lau-verdict-ok"
                }>
                  {log.outputPayload.verdict}
                </span>
              </div>
              <div className="lau-hud-action-line">
                ENFORCED_ACTION:{" "}
                <code className="lau-hud-action-code">{log.outputPayload.actionEnforced}</code>
              </div>
              {log.action && (
                <button
                  className="lau-hud-execute-btn"
                  onClick={() => executeAction(log.action)}
                  type="button"
                >
                  EXECUTE {log.action.method} {log.action.endpoint}
                </button>
              )}
              {log.rawResult && (
                <pre className="lau-hud-raw">
                  {typeof log.rawResult === "string" ? log.rawResult : JSON.stringify(log.rawResult, null, 2)}
                </pre>
              )}
            </div>
          );
        })}

        {loading && (
          <div className="lau-hud-loading">
            <span className="lau-hud-blink">&gt;</span> Processing...
          </div>
        )}
      </div>

      <div className="lau-hud-input-bar">
        <span className="lau-hud-input-prompt">&gt;_</span>
        <input
          ref={inputRef}
          className="lau-hud-input"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") dispatch(input);
          }}
          placeholder="Command LAU or request tactical scan..."
          disabled={loading}
        />
      </div>

      <div className="lau-hud-actions-row">
        {QUICK_ACTIONS.slice(0, 8).map((a) => (
          <button
            key={a.id}
            className="lau-hud-chip"
            onClick={() => dispatch(a.cmd)}
            disabled={loading}
            type="button"
          >
            {a.label}
          </button>
        ))}
      </div>
    </div>
  );
}

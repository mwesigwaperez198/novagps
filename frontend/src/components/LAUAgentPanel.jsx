import { useState, useEffect, useRef, useCallback } from "react";
import { api, request, novaAgentStream } from "../lib/api.js";
import LAUOpsPanel from "./LAUOpsPanel.jsx";

const MODES = [
  { id: "console", label: "CONSOLE" },
  { id: "theft", label: "THEFT" },
  { id: "skills", label: "SKILLS" },
  { id: "live", label: "LIVE" },
];

const QUICK_ACTIONS = [
  { id: "health", label: "System Health", cmd: "analyze system health and status" },
  { id: "ports", label: "Port Scan", cmd: "scan open ports on localhost" },
  { id: "network", label: "Network Info", cmd: "show network interfaces and connectivity" },
  { id: "processes", label: "Processes", cmd: "list running processes" },
  { id: "cameras", label: "Find Cameras", cmd: "discover cameras on the network" },
  { id: "fingerprint", label: "Fingerprint", cmd: "fingerprint the connected device" },
  { id: "locate", label: "Locate Device", cmd: "locate the connected device" },
  { id: "stolen", label: "Stolen Phone", cmd: "track my stolen phone" },
  { id: "shield", label: "Shield Validate", cmd: "run all shield validators" },
  { id: "vuln", label: "Vuln Scan", cmd: "run vulnerability scan" },
  { id: "dns", label: "DNS Resolve", cmd: "resolve dns for google.com" },
  { id: "traceroute", label: "Traceroute", cmd: "traceroute to 8.8.8.8" },
];

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// Small, dependency-free markdown renderer so LAU answers can carry headings,
// code blocks, lists and links without pulling a parser into the bundle.
function renderMarkdown(source) {
  if (!source) return "";
  const inline = (text) => {
    let out = escapeHtml(text);
    out = out.replace(/`([^`]+)`/g, "<code>$1</code>");
    out = out.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    out = out.replace(/(^|[^*])\*([^*]+)\*/g, "$1<em>$2</em>");
    out = out.replace(
      /\[([^\]]+)\]\((https?:[^)\s]+)\)/g,
      '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>',
    );
    return out;
  };

  const html = [];
  let inCode = false;
  let codeBuf = [];
  let listType = null;
  const closeList = () => {
    if (listType) {
      html.push(`</${listType}>`);
      listType = null;
    }
  };

  for (const line of source.replace(/\r\n/g, "\n").split("\n")) {
    const fence = line.match(/^```(\w*)\s*$/);
    if (fence) {
      if (inCode) {
        html.push(`<pre class="lau-md-pre"><code>${escapeHtml(codeBuf.join("\n"))}</code></pre>`);
        codeBuf = [];
        inCode = false;
      } else {
        closeList();
        inCode = true;
      }
      continue;
    }
    if (inCode) {
      codeBuf.push(line);
      continue;
    }
    const heading = line.match(/^(#{1,3})\s+(.*)$/);
    if (heading) {
      closeList();
      html.push(`<div class="lau-md-h${heading[1].length}">${inline(heading[2])}</div>`);
      continue;
    }
    const bullet = line.match(/^\s*[-*]\s+(.*)$/);
    const numbered = line.match(/^\s*\d+[.)]\s+(.*)$/);
    if (bullet) {
      if (listType !== "ul") { closeList(); html.push('<ul class="lau-md-list">'); listType = "ul"; }
      html.push(`<li>${inline(bullet[1])}</li>`);
      continue;
    }
    if (numbered) {
      if (listType !== "ol") { closeList(); html.push('<ol class="lau-md-list">'); listType = "ol"; }
      html.push(`<li>${inline(numbered[1])}</li>`);
      continue;
    }
    if (!line.trim()) {
      closeList();
      continue;
    }
    closeList();
    html.push(`<p class="lau-md-p">${inline(line)}</p>`);
  }
  if (inCode && codeBuf.length) {
    html.push(`<pre class="lau-md-pre"><code>${escapeHtml(codeBuf.join("\n"))}</code></pre>`);
  }
  closeList();
  return html.join("");
}

function clock() {
  return new Date().toLocaleTimeString("en-GB", { hour12: false });
}

export default function LAUHud({ isOpen, onClose, deviceId = "" }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [engineState, setEngineState] = useState(null);
  const [mode, setMode] = useState("console");
  const scrollRef = useRef(null);
  const inputRef = useRef(null);
  const abortRef = useRef(null);
  const activeIdRef = useRef(null);

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
  }, [messages]);

  useEffect(() => () => abortRef.current?.abort(), []);

  const patchActive = useCallback((patch) => {
    const id = activeIdRef.current;
    setMessages((prev) => prev.map((m) => (m.id === id ? { ...m, ...patch(m) } : m)));
  }, []);

  const executeAction = useCallback(async (action, sourceText = "") => {
    if (!action?.endpoint) return;
    if (action.requiresTypedConfirmation) {
      const confirmation = window.prompt("This is destructive. Type WIPE to authorize LAU to continue.");
      if (confirmation !== "WIPE") {
        setMessages((prev) => [...prev, {
          id: `sys-${Date.now()}`, role: "system", engine: "EXECUTIVE_ACTION",
          text: "Destructive action cancelled — typed confirmation not accepted.",
        }]);
        return;
      }
    } else if (action.requiresConfirmation && !window.confirm(`Authorize LAU to run ${action.method} ${action.endpoint}?`)) {
      return;
    }
    setBusy(true);
    try {
      let endpoint = action.endpoint;
      if (action.extract_body && sourceText && !/[?&]message=/.test(endpoint)) {
        endpoint += (endpoint.includes("?") ? "&" : "?") + `message=${encodeURIComponent(sourceText)}`;
      }
      const data = await request(endpoint, action.method === "GET" ? {} : { method: action.method });
      api.novaActionOutcome({
        method: action.method, endpoint: action.endpoint, success: true,
        detail: JSON.stringify(data).slice(0, 500),
      }).catch(() => {});
      setMessages((prev) => [...prev, {
        id: `evt-${Date.now()}`, role: "system", engine: "EXECUTIVE_ACTION",
        text: `${action.method} ${action.endpoint}\n${JSON.stringify(data, null, 2)}`,
        ok: true,
      }]);
    } catch (err) {
      api.novaActionOutcome({
        method: action.method, endpoint: action.endpoint, success: false, detail: err.message,
      }).catch(() => {});
      setMessages((prev) => [...prev, {
        id: `evt-${Date.now()}`, role: "system", engine: "EXECUTIVE_ACTION",
        text: `${action.method} ${action.endpoint} failed: ${err.message}`,
        ok: false,
      }]);
    } finally {
      setBusy(false);
    }
  }, []);

  const dispatch = useCallback(async (command) => {
    const text = (command || "").trim();
    if (!text || busy) return;
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    const assistantId = `a-${Date.now()}`;
    activeIdRef.current = assistantId;
    setInput("");
    setBusy(true);
    setMessages((prev) => [
      ...prev,
      { id: `u-${Date.now()}`, role: "user", text, timestamp: clock() },
      {
        id: assistantId, role: "assistant", timestamp: clock(),
        text: "", thoughts: [], tools: [], sources: [], engine: null, streaming: true, action: null, results: null, error: null,
      },
    ]);

    try {
      await novaAgentStream(text, deviceId, {
        signal: controller.signal,
        onEvent: ({ event, data }) => {
          if (event === "thought") {
            patchActive((m) => ({ thoughts: [...m.thoughts, data.text] }));
          } else if (event === "tool") {
            patchActive((m) => (m.tools.includes(data.name) ? {} : { tools: [...m.tools, data.name] }));
          } else if (event === "sources") {
            patchActive(() => ({ sources: data.items || [] }));
          } else if (event === "action") {
            patchActive(() => ({ action: data }));
          } else if (event === "ui_control") {
            window.dispatchEvent(new CustomEvent("nova-ui-control", { detail: data }));
            patchActive(() => ({ uiControl: data }));
          } else if (event === "token") {
            patchActive((m) => ({ text: m.text + data.text }));
          } else if (event === "done") {
            patchActive(() => ({
              streaming: false,
              engine: data.engine || null,
              intent: data.intent || null,
              tools: data.tools_executed || [],
              results: data.results || null,
            }));
          } else if (event === "error") {
            patchActive(() => ({ streaming: false, error: data.message || "stream error" }));
          }
        },
      });
    } catch (err) {
      if (err.name !== "AbortError") {
        patchActive(() => ({ streaming: false, error: err.message }));
      }
    } finally {
      patchActive((m) => (m.streaming ? { streaming: false } : {}));
      setBusy(false);
      inputRef.current?.focus();
    }
  }, [busy, deviceId, patchActive]);

  const engineReady = engineState?.state === "ready" || engineState?.state === "shield_only";

  return (
    <div
      className={`lau-hud-overlay ${isOpen ? "is-open" : ""}`}
      onClick={onClose}
    >
      <div className="lau-hud-panel" onClick={(e) => e.stopPropagation()}>
      <div className="lau-hud-header">
        <div className="lau-hud-header-left">
          <span className={`lau-hud-dot ${engineReady ? "online" : ""}`} />
          <span className="lau-hud-title">LAU // COGNITIVE_SHIELD</span>
        </div>
        <div className="lau-hud-modes">
          {MODES.map((item) => (
            <button
              key={item.id}
              type="button"
              className={`lau-hud-mode ${mode === item.id ? "active" : ""}`}
              onClick={() => setMode(item.id)}
            >
              {item.label}
            </button>
          ))}
          <button className="lau-hud-close" onClick={onClose} type="button">ESC</button>
        </div>
      </div>

      {mode !== "console" ? (
        <LAUOpsPanel mode={mode} deviceId={deviceId} />
      ) : (
        <>
          <div className="lau-chat" ref={scrollRef}>
            {messages.length === 0 && (
              <div className="lau-chat-hello">
                <div className="lau-chat-hello-mark">LAU</div>
                <div className="lau-chat-hello-title">How can I help?</div>
                <div className="lau-chat-hello-sub">
                  Ask in plain language. I&apos;ll reason, run the right tools, and answer with what I actually found.
                </div>
              </div>
            )}

            {messages.map((m) => {
              if (m.role === "user") {
                return (
                  <div key={m.id} className="lau-msg-row lau-msg-row-user">
                    <div className="lau-bubble lau-bubble-user">{m.text}</div>
                  </div>
                );
              }
              if (m.role === "system") {
                return (
                  <div key={m.id} className="lau-msg-row">
                    <div className={`lau-bubble lau-bubble-system ${m.ok === false ? "is-error" : ""}`}>
                      <div className="lau-bubble-tag">{m.engine}</div>
                      <pre className="lau-bubble-pre">{m.text}</pre>
                    </div>
                  </div>
                );
              }
              const showThinking = m.streaming && !m.text && !m.error;
              return (
                <div key={m.id} className="lau-msg-row lau-msg-row-agent">
                  <div className="lau-avatar">LAU</div>
                  <div className="lau-bubble lau-bubble-agent">
                    {m.thoughts?.length > 0 && (
                      <details className="lau-thinking" open={m.streaming}>
                        <summary>
                          <span className="lau-thinking-dots"><i /><i /><i /></span>
                          Reasoning &middot; {m.thoughts.length} step{m.thoughts.length === 1 ? "" : "s"}
                        </summary>
                        <ol className="lau-thinking-list">
                          {m.thoughts.map((t, i) => <li key={i}>{t}</li>)}
                        </ol>
                      </details>
                    )}

                    {m.tools?.length > 0 && (
                      <div className="lau-tool-chips">
                        {m.tools.map((t) => <span key={t} className="lau-tool-chip">{t}</span>)}
                      </div>
                    )}

                    {m.error ? (
                      <div className="lau-bubble-error">Stream interrupted: {m.error}</div>
                    ) : showThinking ? (
                      <div className="lau-typing"><i /><i /><i /></div>
                    ) : (
                      <div
                        className="lau-md"
                        dangerouslySetInnerHTML={{ __html: renderMarkdown(m.text) }}
                      />
                    )}

                    {m.streaming && m.text && <span className="lau-caret" />}

                    {m.sources?.length > 0 && (
                      <div className="lau-sources">
                        <div className="lau-sources-title">Sources</div>
                        <ul className="lau-sources-list">
                          {m.sources.map((s) => (
                            <li key={s.url}>
                              <a href={s.url} target="_blank" rel="noopener noreferrer">
                                {s.title || s.url}
                              </a>
                              {s.fetched === false && <span className="lau-sources-tag">snippet</span>}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {m.action && (
                      <button
                        className="lau-hud-execute-btn"
                        onClick={() => executeAction(m.action, m.text)}
                        type="button"
                      >
                        {m.action.risk === "destructive" ? "AUTHORIZE DESTRUCTIVE" : "EXECUTE"} {m.action.method} {m.action.endpoint}
                      </button>
                    )}

                    <div className="lau-bubble-foot">
                      {m.engine && <span>{m.engine}</span>}
                      {m.timestamp && <span>{m.timestamp}</span>}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          <div className="lau-composer">
            <span className="lau-composer-prompt">&gt;_</span>
            <input
              ref={inputRef}
              className="lau-composer-input"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) dispatch(input);
              }}
              placeholder="Message LAU — ask, scan, or investigate…"
              disabled={busy}
            />
            <button
              className="lau-send-btn"
              onClick={() => dispatch(input)}
              disabled={busy || !input.trim()}
              type="button"
            >
              {busy ? "…" : "SEND"}
            </button>
          </div>

          <div className="lau-hud-actions-row">
            {QUICK_ACTIONS.map((a) => (
              <button
                key={a.id}
                className="lau-hud-chip"
                onClick={() => dispatch(a.cmd)}
                disabled={busy}
                type="button"
              >
                {a.label}
              </button>
            ))}
          </div>
        </>
      )}
      </div>
    </div>
  );
}

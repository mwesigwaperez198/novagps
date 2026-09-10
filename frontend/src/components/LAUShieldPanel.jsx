import { useState } from "react";
import { AlertTriangle, Braces, CheckCircle2, ChevronDown, ChevronRight, Loader2, Play, Send, ShieldCheck, Terminal } from "lucide-react";
import { api } from "../lib/api.js";

const DEFAULT_PROMPT =
  "A compromised asset terminal is streaming fabricated GPS fixes with NaN latitude and 1e300 " +
  "out-of-range coordinates to escape the tracking validation stream. Run the localized tracking " +
  "logic and emit a validation filter that drops invalid fixes before the routing pipeline.";

function laneChip(lane) {
  const ok = lane.route_matched && lane.compile_ok && lane.run_ok && !lane.error;
  return ok
    ? <span className="status-ok"><CheckCircle2 size={11} /> PASS</span>
    : <span className="status-err"><AlertTriangle size={11} /> FAIL</span>;
}

function badgeChip(badge) {
  const cls = typeof badge === "object" && badge ? (badge.level === "critical" ? "shld-badge critical" : badge.level === "warn" ? "shld-badge warn" : "shld-badge") : "shld-badge";
  const text = typeof badge === "object" && badge ? (badge.label || badge.badge || badge.message || JSON.stringify(badge)) : badge;
  return <span key={String(text)} className={cls}>{text}</span>;
}

function LaneCard({ lane }) {
  const [open, setOpen] = useState(false);
  const payload = lane.payload || {};
  const badges = Array.isArray(payload.alert_badges) ? payload.alert_badges : [];
  const matrix = payload.matrix;
  const ssl = payload.ssl_telemetry;
  const toggleable = Boolean(matrix || ssl || payload.vulnerability_surface || lane.directives?.length);

  return (
    <div className="result-box shld-lane">
      <div className="shld-lane-head">
        <div className="shld-lane-title">
          <Braces size={13} /> {lane.name}
          <span className="muted">→ <code>{lane.action_enforced}</code></span>
        </div>
        {laneChip(lane)}
      </div>

      <div className="scan-meta-row">
        <span>expected route</span>
        <code>{lane.expected_action}</code>
      </div>
      <div className="scan-meta-row">
        <span>verdict</span>
        <span>{lane.verdict || "—"}</span>
      </div>
      <div className="scan-meta-row">
        <span>compile / run / status</span>
        <span>
          <span className={lane.compile_ok ? "status-ok" : "status-err"}>{lane.compile_ok ? "COMPILE OK" : "COMPILE FAIL"}</span>
          {" · "}
          <span className={lane.run_ok ? "status-ok" : "status-err"}>{lane.run_ok ? "RUN OK" : "RUN FAIL"}</span>
          {lane.status ? <code> · {lane.status}</code> : null}
        </span>
      </div>

      {lane.error && <div className="error-box">{lane.error}</div>}

      {lane.thought_sequence && lane.thought_sequence.length > 0 && (
        <div className="think-steps" style={{ marginTop: 8 }}>
          {lane.thought_sequence.map((step, i) => <div key={i} className="think-step"><span>{i + 1}</span><code>{step}</code></div>)}
        </div>
      )}
      {lane.thought_process && Object.keys(lane.thought_process).length > 0 && (
        <div className="think-steps" style={{ marginTop: 8 }}>
          {Object.entries(lane.thought_process).map(([k, v]) => (
            <div key={k} className="think-step"><span>{k}</span><code>{v}</code></div>
          ))}
        </div>
      )}

      {badges.length > 0 && (
        <div className="alert-badges" style={{ marginTop: 8 }}>
          {badges.map(badgeChip)}
        </div>
      )}

      {matrix && (
        <div className="shld-matrix" style={{ marginTop: 8 }}>
          <div className="section-title">matrix</div>
          {Object.entries(matrix).map(([k, v]) => (
            <div className="scan-meta-row" key={k}>
              <span>{k}</span>
              <code>{typeof v === "object" ? JSON.stringify(v) : String(v)}</code>
            </div>
          ))}
        </div>
      )}

      {ssl && (
        <div className="shld-matrix" style={{ marginTop: 8 }}>
          <div className="section-title">ssl telemetry</div>
          {Object.entries(ssl).map(([k, v]) => (
            <div className="scan-meta-row" key={k}>
              <span>{k}</span>
              <code>{typeof v === "object" ? JSON.stringify(v) : String(v)}</code>
            </div>
          ))}
        </div>
      )}

      {lane.directives && lane.directives.length > 0 && (
        <div className="directives" style={{ marginTop: 8, display: "flex", gap: 6, flexWrap: "wrap" }}>
          {lane.directives.map((d) => <code key={d}>{d}</code>)}
        </div>
      )}

      {toggleable && (
        <button className="btn-ghost shld-toggle" type="button" onClick={() => setOpen(!open)} style={{ marginTop: 8 }}>
          {open ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
          {open ? "Hide" : "Show"} emitted payload
        </button>
      )}
      {open && <pre className="result-code shld-source">{JSON.stringify(payload, null, 2)}</pre>}
    </div>
  );
}

export default function LAUShieldPanel() {
  const [lanes, setLanes] = useState(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [prompt, setPrompt] = useState(DEFAULT_PROMPT);
  const [emit, setEmit] = useState(null);
  const [emitting, setEmitting] = useState(false);
  const [emitError, setEmitError] = useState("");

  async function runValidators() {
    setRunning(true);
    setError("");
    setLanes(null);
    try {
      setLanes(await api.novaShieldValidate());
    } catch (err) {
      setError(err.message);
    } finally {
      setRunning(false);
    }
  }

  async function runEmit() {
    if (!prompt.trim()) return;
    setEmitting(true);
    setEmitError("");
    setEmit(null);
    try {
      setEmit(await api.novaShieldEmit(prompt));
    } catch (err) {
      setEmitError(err.message);
    } finally {
      setEmitting(false);
    }
  }

  return (
    <div className="shld">
      <div className="toolbar-row" style={{ marginTop: 4 }}>
        <button onClick={runValidators} disabled={running} className="btn-primary" type="button">
          {running ? <Loader2 size={12} className="spin" /> : <Play size={12} />} Run Module Validators
        </button>
      </div>

      {error && <div className="error-box" style={{ marginTop: 8 }}>{error}</div>}

      {lanes && (
        <div style={{ marginTop: 10 }}>
          <div className="scan-meta-row">
            <span><strong>Definitive module validators</strong></span>
            <span>{lanes.passed ? <span className="status-ok"><ShieldCheck size={11} /> ALL LANES PASS</span> : <span className="status-err">LANE FAILURE</span>}</span>
          </div>
          <div className="shld-lanes" style={{ marginTop: 8, display: "grid", gap: 10 }}>
            {lanes.lanes.map((lane) => <LaneCard key={lane.name} lane={lane} />)}
          </div>
        </div>
      )}
      {running && !lanes && <div className="empty-row"><Loader2 size={12} className="spin" /> dispatching staging loop…</div>}

      <div className="result-box" style={{ marginTop: 16 }}>
        <div className="scan-meta-row"><span><strong>Shield intent passthrough</strong></span><Terminal size={13} /></div>
        <textarea
          className="text-input shld-prompt"
          rows={4}
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
          placeholder="Describe the threat surface to route through the shield…"
        />
        <button onClick={runEmit} disabled={emitting || !prompt.trim()} className="btn-primary" type="button" style={{ marginTop: 8 }}>
          {emitting ? <Loader2 size={12} className="spin" /> : <Send size={12} />} Route through shield
        </button>
        {emitError && <div className="error-box">{emitError}</div>}

        {emit && (
          <div className="verify-result" style={{ marginTop: 10 }}>
            <div className="scan-meta-row"><span>Action enforced</span><code>{emit.action_enforced}</code></div>
            <div className="scan-meta-row"><span>Verdict</span><span className="status-ok">{emit.verdict}</span></div>
            <div className="scan-meta-row"><span>Engine</span><code>{emit.engine}</code> · <span className="muted">latency {emit.latency_ms} ms</span></div>

            {emit.thought_sequence && emit.thought_sequence.length > 0 && (
              <div className="think-steps" style={{ marginTop: 8 }}>
                {emit.thought_sequence.map((step, i) => <div key={i} className="think-step"><span>{i + 1}</span><code>{step}</code></div>)}
              </div>
            )}
            {emit.thought_process && Object.keys(emit.thought_process).length > 0 && (
              <div className="think-steps" style={{ marginTop: 8 }}>
                {Object.entries(emit.thought_process).map(([k, v]) => (
                  <div key={k} className="think-step"><span>{k}</span><code>{v}</code></div>
                ))}
              </div>
            )}

            {emit.directives && emit.directives.length > 0 && (
              <div className="directives" style={{ marginTop: 8, display: "flex", gap: 6, flexWrap: "wrap" }}>
                {emit.directives.map((d) => <code key={d}>{d}</code>)}
              </div>
            )}

            {emit.source && (
              <>
                <div className="section-title" style={{ marginTop: 8 }}>emitted source</div>
                <pre className="result-code shld-source">{emit.source}</pre>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
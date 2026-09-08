import { useState } from "react";
import { Send, Lock, AlertTriangle, Phone, ExternalLink, Shield, LocateFixed, MessageSquare, Trash2, Clock } from "lucide-react";
import { api } from "../lib/api.js";

export default function RemotePanel({ device }) {
  const [smsMessage, setSmsMessage] = useState("");
  const [smsResult, setSmsResult] = useState(null);
  const [lockGuide, setLockGuide] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState("sms");

  const [cmdMessage, setCmdMessage] = useState("");
  const [cmdContact, setCmdContact] = useState("");
  const [cmdResult, setCmdResult] = useState(null);
  const [cmdHistory, setCmdHistory] = useState([]);
  const [cmdPending, setCmdPending] = useState([]);
  const [showHistory, setShowHistory] = useState(false);

  const templates = [
    { label: "Recovery", text: "This phone has been reported lost. Please contact the owner immediately at 0765866555. A reward is offered for its return." },
    { label: "Warning", text: "This device is tracked and monitored. Return it to avoid legal action. Contact: 0765866555" },
    { label: "Lock Notice", text: "This phone has been remotely locked. It is useless to you. Return it to the owner at Namwongo-Kanyogoga or call 0765866555." },
    { label: "Police", text: "STOLEN DEVICE — This phone is being tracked by law enforcement. Surrender it immediately. Case ref: NOVA-GPS" },
  ];

  async function handleSendSms() {
    if (!device?.id || !smsMessage.trim()) return;
    setLoading(true);
    setError("");
    setSmsResult(null);
    try {
      const result = await api.remoteSms(device.id, smsMessage.trim());
      setSmsResult(result);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function handleLockGuide() {
    if (!device?.id) return;
    setLoading(true);
    setError("");
    setLockGuide(null);
    try {
      const result = await api.remoteLockGuide(device.id);
      setLockGuide(result);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function runCommand(call) {
    if (!device?.id) return;
    setLoading(true);
    setError("");
    setCmdResult(null);
    try {
      const result = await call();
      setCmdResult({ ok: true, data: result });
    } catch (err) {
      setCmdResult({ ok: false, data: err.message });
    } finally {
      setLoading(false);
    }
  }

  async function loadCommands() {
    if (!device?.id) return;
    setLoading(true);
    setError("");
    setCmdResult(null);
    try {
      const [history, pending] = await Promise.all([
        api.deviceCommands(device.id, 20),
        api.devicePendingCommands(device.id),
      ]);
      setCmdHistory(history.commands || history || []);
      setCmdPending(pending.pending || pending || []);
      setShowHistory(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  if (!device) {
    return (
      <section className="panel remote-panel">
        <div className="panel-title"><span>REMOTE</span><Shield size={15} /></div>
        <div className="inline-error">Select a device first</div>
      </section>
    );
  }

  const devicePhone = device.phone || "No phone number";
  const deviceOs = device.os_type || "Unknown";
  const deviceImei = device.imei || "N/A";

  return (
    <section className="panel remote-panel">
      <div className="panel-title">
        <span>REMOTE_ACTIONS</span>
        <Shield size={15} />
      </div>

      <div className="panel-tabs">
        <button className={`panel-tab ${activeTab === "sms" ? "is-active" : ""}`} onClick={() => setActiveTab("sms")}>
          SMS
        </button>
        <button className={`panel-tab ${activeTab === "lock" ? "is-active" : ""}`} onClick={() => setActiveTab("lock")}>
          LOCK
        </button>
        <button className={`panel-tab ${activeTab === "cmd" ? "is-active" : ""}`} onClick={() => setActiveTab("cmd")}>
          CMD
        </button>
      </div>

      <div className="remote-device-info">
        <div className="device-info-row"><span className="info-label">Device</span><span>{device.name}</span></div>
        <div className="device-info-row"><span className="info-label">Phone</span><span>{devicePhone}</span></div>
        <div className="device-info-row"><span className="info-label">OS</span><span>{deviceOs}</span></div>
        <div className="device-info-row"><span className="info-label">IMEI</span><span>{deviceImei}</span></div>
      </div>

      {activeTab === "sms" && (
        <div className="remote-section">
          <div className="section-label">
            <Send size={12} />
            <span>Send SMS to Device</span>
          </div>

          <div className="template-grid">
            {templates.map((tpl) => (
              <button
                key={tpl.label}
                className="template-btn"
                onClick={() => setSmsMessage(tpl.text)}
              >
                {tpl.label}
              </button>
            ))}
          </div>

          <textarea
            className="sms-input"
            value={smsMessage}
            onChange={(e) => setSmsMessage(e.target.value)}
            placeholder="Type your message..."
            rows={3}
          />

          <div className="sms-footer">
            <span className="char-count">{smsMessage.length}/500</span>
            <button
              className="command-button send-btn"
              onClick={handleSendSms}
              disabled={loading || !smsMessage.trim()}
            >
              {loading ? "SENDING..." : "SEND SMS"}
            </button>
          </div>

          {error && <div className="inline-error">{error}</div>}

          {smsResult && (
            <div className="sms-result">
              {smsResult.success ? (
                <div className="result-success">
                  <span className="success-icon">&#10003;</span>
                  <span>SMS sent to {smsResult.phone}</span>
                  {smsResult.cost && <span className="result-cost">Cost: {smsResult.cost}</span>}
                </div>
              ) : (
                <div className="result-pending">
                  <AlertTriangle size={14} />
                  <span>{smsResult.error || smsResult.status || "SMS provider not configured"}</span>
                </div>
              )}
              {smsResult.instructions && (
                <div className="setup-instructions">
                  <div className="section-label">Setup Instructions</div>
                  <pre>{JSON.stringify(smsResult.instructions, null, 2)}</pre>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {activeTab === "lock" && (
        <div className="remote-section">
          <div className="section-label">
            <Lock size={12} />
            <span>Remote Lock & Recovery</span>
          </div>

          <button
            className="command-button lock-btn"
            onClick={handleLockGuide}
            disabled={loading}
          >
            {loading ? "LOADING..." : "GET LOCK INSTRUCTIONS"}
          </button>

          {error && <div className="inline-error">{error}</div>}

          {lockGuide && (
            <div className="lock-guide">
              <div className="guide-service">{lockGuide.service}</div>
              {lockGuide.url && (
                <a href={lockGuide.url} target="_blank" rel="noopener noreferrer" className="guide-link">
                  <ExternalLink size={12} />
                  Open {lockGuide.service}
                </a>
              )}

              {lockGuide.capabilities && (
                <div className="guide-section">
                  <div className="guide-label">Capabilities</div>
                  {Object.entries(lockGuide.capabilities).map(([key, val]) => (
                    <div key={key} className="guide-cap">
                      <span className="cap-name">{key.replace(/_/g, " ")}</span>
                      <span className="cap-desc">{val}</span>
                    </div>
                  ))}
                </div>
              )}

              {lockGuide.steps && (
                <div className="guide-section">
                  <div className="guide-label">Steps</div>
                  <ol className="guide-steps">
                    {lockGuide.steps.map((step, i) => (
                      <li key={i}>{step}</li>
                    ))}
                  </ol>
                </div>
              )}

              {lockGuide.requirements && (
                <div className="guide-section">
                  <div className="guide-label">Requirements</div>
                  {lockGuide.requirements.map((req, i) => (
                    <div key={i} className="guide-req">{req}</div>
                  ))}
                </div>
              )}

              {lockGuide.notes && (
                <div className="guide-section">
                  <div className="guide-label">Notes</div>
                  {lockGuide.notes.map((note, i) => (
                    <div key={i} className="guide-note">{note}</div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {activeTab === "cmd" && (
        <div className="remote-section">
          <div className="section-label">
            <LocateFixed size={12} />
            <span>Device Commands</span>
          </div>

          <div className="command-grid">
            <button className="command-button" onClick={() => runCommand(() => api.deviceTriggerLocate(device.id))} disabled={loading}>
              <LocateFixed size={12} /> TRIGGER LOCATE
            </button>
            <button className="command-button" onClick={() => runCommand(() => api.remoteLostMode(device.id, cmdMessage || "This device is lost. Please call the owner.", cmdContact))} disabled={loading}>
              LOST MODE
            </button>
          </div>

          <div className="section-label" style={{ marginTop: 8 }}>
            <Lock size={12} />
            <span>Lock Message</span>
          </div>
          <textarea
            className="sms-input"
            value={cmdMessage}
            onChange={(e) => setCmdMessage(e.target.value)}
            placeholder="Lock / lost-mode message shown on device"
            rows={2}
          />
          <input
            className="text-input"
            value={cmdContact}
            onChange={(e) => setCmdContact(e.target.value)}
            placeholder="Contact number (optional)"
          />

          <div className="command-grid">
            <button className="command-button lock-btn" onClick={() => runCommand(() => api.remoteLock(device.id, cmdMessage || "This device has been remotely locked.", cmdContact))} disabled={loading}>
              <Lock size={12} /> REMOTE LOCK
            </button>
            <button className="command-button send-btn" onClick={() => runCommand(() => api.remoteSendMessage(device.id, cmdMessage))} disabled={loading || !cmdMessage.trim()}>
              <MessageSquare size={12} /> PUSH MESSAGE
            </button>
            <button className="command-button warn-btn" onClick={() => runCommand(() => api.remoteWipe(device.id, "CONFIRM-WIPE"))} disabled={loading}>
              <Trash2 size={12} /> REMOTE WIPE
            </button>
            <button className="command-button" onClick={loadCommands} disabled={loading}>
              <Clock size={12} /> COMMAND LOG
            </button>
          </div>

          {error && <div className="inline-error">{error}</div>}

          {cmdResult && (
            <div className={cmdResult.ok ? "result-success" : "result-pending"}>
              {cmdResult.ok ? (
                <span><span className="success-icon">&#10003;</span> Command accepted</span>
              ) : (
                <span><AlertTriangle size={14} /> {cmdResult.data}</span>
              )}
            </div>
          )}

          {showHistory && (
            <div className="lock-guide">
              <div className="guide-label">Pending Commands ({cmdPending.length})</div>
              {cmdPending.length === 0 && <div className="guide-note">No pending commands</div>}
              {cmdPending.map((cmd, i) => (
                <div key={i} className="guide-req">
                  {cmd.command || cmd.name || cmd.action} — {cmd.status || "queued"}
                </div>
              ))}
              <div className="guide-label" style={{ marginTop: 8 }}>Recent Commands</div>
              {cmdHistory.length === 0 && <div className="guide-note">No command history</div>}
              {cmdHistory.map((cmd, i) => (
                <div key={i} className="guide-req">
                  {cmd.command || cmd.name || cmd.action || cmd.id} — {cmd.status || cmd.exit_code !== null ? `exit ${cmd.exit_code}` : "done"}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </section>
  );
}

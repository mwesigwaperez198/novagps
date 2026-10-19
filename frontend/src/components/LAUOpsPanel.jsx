import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../lib/api.js";

const PLAYBOOK = [
  "Google Find My Device — android.com/find (sign in as the owner account).",
  "Samsung Find My Mobile — findmymobile.samsung.com if a Samsung account is linked.",
  "File a police report quoting the true 15-digit IMEI and subscriber number.",
  "Police -> UCC/NITA-U -> carrier can blacklist the IMEI at the EIR.",
  "Rotate any credentials the phone could unlock once a report exists.",
];

const STATUS_MARK = { watching: "o", sighted: "!", recovered: "x" };

function useAsync(loader, deps) {
  const [state, setState] = useState({ loading: true, error: null, data: null });
  const run = useCallback(() => {
    let alive = true;
    setState((s) => ({ ...s, loading: true }));
    loader()
      .then((data) => alive && setState({ loading: false, error: null, data }))
      .catch((err) => alive && setState({ loading: false, error: err, data: null }));
    return () => {
      alive = false;
    };
  }, deps);
  useEffect(() => run(), [run]);
  return [state, run];
}

function TheftView() {
  const [entries, reload] = useAsync(() => api.watchlistList(), []);
  const [form, setForm] = useState({ imei: "", phone: "", email: "", label: "Stolen device" });
  const [caseData, setCaseData] = useState(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState(null);

  const openCase = async (watchId) => {
    setBusy(true);
    try {
      const trail = await api.watchlistSightings(watchId);
      setCaseData(trail);
    } catch (err) {
      setNotice({ kind: "error", text: err.message });
    } finally {
      setBusy(false);
    }
  };

  const add = async (event) => {
    event.preventDefault();
    if (!form.imei && !form.phone) {
      setNotice({ kind: "error", text: "Enter an IMEI or a phone number." });
      return;
    }
    setBusy(true);
    try {
      await api.watchlistAdd(form);
      setNotice({ kind: "ok", text: "Device registered on the watchlist." });
      setForm({ imei: "", phone: "", email: "", label: "Stolen device" });
      reload();
    } catch (err) {
      setNotice({ kind: "error", text: err.message });
    } finally {
      setBusy(false);
    }
  };

  const recover = async (watchId) => {
    setBusy(true);
    try {
      await api.watchlistRecover(watchId);
      setNotice({ kind: "ok", text: "Marked recovered." });
      setCaseData(null);
      reload();
    } catch (err) {
      setNotice({ kind: "error", text: err.message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="lau-ops-body">
      <form className="lau-ops-form" onSubmit={add}>
        <input className="lau-ops-input" placeholder="IMEI / IMEISV (15-16 digits)" value={form.imei}
          onChange={(e) => setForm({ ...form, imei: e.target.value })} />
        <input className="lau-ops-input" placeholder="Phone  +256..." value={form.phone}
          onChange={(e) => setForm({ ...form, phone: e.target.value })} />
        <input className="lau-ops-input" placeholder="Owner email" value={form.email}
          onChange={(e) => setForm({ ...form, email: e.target.value })} />
        <input className="lau-ops-input" placeholder="Label" value={form.label}
          onChange={(e) => setForm({ ...form, label: e.target.value })} />
        <button className="lau-ops-btn" type="submit" disabled={busy}>REGISTER WATCH</button>
      </form>

      {notice && <div className={`lau-ops-notice ${notice.kind}`}>{notice.text}</div>}

      {entries.error && <div className="lau-ops-notice error">{entries.error.message}</div>}
      {entries.loading && <div className="lau-ops-muted">Loading watchlist…</div>}

      {(entries.data || []).map((entry) => (
        <div key={entry.id} className="lau-ops-card">
          <div className="lau-ops-card-head">
            <span className={`lau-ops-status ${entry.status}`}>{STATUS_MARK[entry.status] || "?"} {entry.status}</span>
            <strong>{entry.label}</strong>
            <span className="lau-ops-muted">{entry.imei || "-"} · {entry.phone || "-"}</span>
          </div>
          <div className="lau-ops-card-actions">
            <button className="lau-ops-btn ghost" onClick={() => openCase(entry.id)} disabled={busy}>CASE FILE</button>
            {entry.status !== "recovered" && (
              <button className="lau-ops-btn ghost" onClick={() => recover(entry.id)} disabled={busy}>RECOVERED</button>
            )}
          </div>
        </div>
      ))}

      {!entries.loading && (entries.data || []).length === 0 && (
        <div className="lau-ops-muted">No devices on the watchlist yet.</div>
      )}

      {caseData && (
        <div className="lau-ops-card">
          <div className="lau-ops-card-head"><strong>CASE FILE</strong></div>
          {(caseData.sightings || []).length === 0 && (
            <div className="lau-ops-muted">No sightings yet — the reporting client has not pinged.</div>
          )}
          {(caseData.sightings || []).map((fix, i) => (
            <div key={i} className="lau-ops-row">
              <span className="lau-ops-muted">{(fix.recorded_at || "").slice(0, 19).replace("T", " ")}</span>
              <span>{fix.place_name || `${Number(fix.latitude).toFixed(5)}, ${Number(fix.longitude).toFixed(5)}`}</span>
              <span className="lau-ops-muted">{fix.source}</span>
            </div>
          ))}
          {(caseData.alerts || []).map((alert, i) => (
            <div key={`a-${i}`} className="lau-ops-row critical">{alert.message}</div>
          ))}
          <div className="lau-ops-playbook">
            <div className="lau-ops-muted">RECOVERY PLAYBOOK</div>
            {PLAYBOOK.map((line) => <div key={line}>· {line}</div>)}
          </div>
        </div>
      )}
    </div>
  );
}

function SkillsView() {
  const [skills, reload] = useAsync(() => api.novaSkills(), []);
  const [targets, setTargets] = useState({});
  const [runs, setRuns] = useState({});
  const [busy, setBusy] = useState(null);

  const run = async (key) => {
    setBusy(key);
    try {
      const result = await api.novaSkillRun(key, targets[key] || "");
      setRuns((prev) => ({ ...prev, [key]: result }));
    } catch (err) {
      setRuns((prev) => ({ ...prev, [key]: { status: "error", stderr: err.message } }));
    } finally {
      setBusy(null);
    }
  };

  const list = skills.data?.skills || [];
  return (
    <div className="lau-ops-body">
      {skills.error && <div className="lau-ops-notice error">{skills.error.message}</div>}
      {skills.loading && <div className="lau-ops-muted">Loading skills registry…</div>}
      {list.map((skill) => {
        const result = runs[skill.name];
        return (
          <div key={skill.name} className="lau-ops-card">
            <div className="lau-ops-card-head">
              <span className={`lau-ops-pri ${skill.priority}`}>{skill.priority}</span>
              <strong>{skill.title}</strong>
              <span className={skill.available ? "lau-ops-ready" : "lau-ops-muted"}>
                {skill.available ? "ready" : "missing"}
              </span>
            </div>
            <div className="lau-ops-muted">{skill.purpose}</div>
            <div className="lau-ops-card-actions">
              <input className="lau-ops-input grow" placeholder="target / args"
                value={targets[skill.name] || ""}
                onChange={(e) => setTargets({ ...targets, [skill.name]: e.target.value })} />
              <button className="lau-ops-btn" onClick={() => run(skill.name)} disabled={busy === skill.name || !skill.available}>
                RUN
              </button>
            </div>
            {!skill.available && skill.install && <div className="lau-ops-muted">install: {skill.install}</div>}
            {result && (
              <div className="lau-ops-run">
                <div className={`lau-ops-notice ${result.status === "ok" ? "ok" : "error"}`}>
                  {(result.command || []).join(" ")} → {result.status}
                </div>
                {result.stdout && <pre className="lau-hud-raw">{result.stdout}</pre>}
                {result.stderr && <pre className="lau-hud-raw">{result.stderr}</pre>}
                {result.timeout && <div className="lau-ops-muted">timed out after {result.timeout}s</div>}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function LiveView() {
  const [health, setHealth] = useState(null);
  const [cases, setCases] = useState([]);
  const timer = useRef(null);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const [h, wl] = await Promise.all([api.devicesHealth(), api.watchlistList()]);
        if (!alive) return;
        setHealth(h);
        const trails = await Promise.all(
          (wl || []).slice(0, 8).map((entry) =>
            api.watchlistSightings(entry.id).catch(() => null)
          )
        );
        if (!alive) return;
        setCases(trails.filter(Boolean));
      } catch {
        /* keep last known board */
      }
    };
    tick();
    timer.current = setInterval(tick, 6000);
    return () => {
      alive = false;
      clearInterval(timer.current);
    };
  }, []);

  const devices = health?.devices || [];
  return (
    <div className="lau-ops-body">
      <div className="lau-ops-card-head">
        <strong>LIVE RADAR</strong>
        <span className="lau-ops-muted">
          {health ? `${health.count} devices · ${devices.filter((d) => d.watchlisted).length} watched` : "syncing…"}
        </span>
      </div>
      {devices.map((device) => (
        <div key={device.device_id} className={`lau-ops-row ${device.watchlisted ? "watched" : ""} ${device.stale ? "stale" : ""}`}>
          <span>{device.watchlisted ? "◆" : "·"} {device.name || device.identifier}</span>
          <span className="lau-ops-muted">
            {device.age_seconds == null ? "no fix" : `${Math.round(device.age_seconds)}s ago`}
          </span>
          <span className="lau-ops-muted">{device.stale ? "QUIET" : "LIVE"}</span>
        </div>
      ))}
      {cases.map((trail, i) => (
        <div key={`case-${i}`} className="lau-ops-card">
          <div className="lau-ops-card-head">
            <strong>{(trail.entry || {}).label || (trail.sightings || []).map((s) => s.imei).find(Boolean) || "watch"}</strong>
            <span className="lau-ops-muted">{(trail.sightings || []).length} fixes</span>
          </div>
          {(trail.sightings || []).slice(0, 4).map((fix, j) => (
            <div key={j} className="lau-ops-row">
              <span>{fix.place_name || `${Number(fix.latitude).toFixed(4)}, ${Number(fix.longitude).toFixed(4)}`}</span>
              <span className="lau-ops-muted">{(fix.recorded_at || "").slice(11, 19)}</span>
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

export default function LAUOpsPanel({ mode }) {
  if (mode === "skills") return <SkillsView />;
  if (mode === "live") return <LiveView />;
  return <TheftView />;
}

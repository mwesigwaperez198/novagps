import { useState, useEffect } from "react";
import { Clock, Plus, Trash2, Loader2, Power, PowerOff } from "lucide-react";
import { api } from "../lib/api.js";

export default function SchedulerPanel() {
  const [tasks, setTasks] = useState([]);
  const [name, setName] = useState("");
  const [cronExpr, setCronExpr] = useState("");
  const [commandId, setCommandId] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function loadTasks() {
    setLoading(true); setError(null);
    try { const res = await api.tasksList(); setTasks(res.tasks || []); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function addTask() {
    if (!name || !cronExpr) { setError("Name and cron expression required"); return; }
    setLoading(true); setError(null);
    try {
      await api.taskSchedule(name, cronExpr, commandId);
      setName(""); setCronExpr(""); setCommandId("");
      await loadTasks();
    } catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function toggleTask(id, enabled) {
    try {
      await api.taskToggle(id, enabled);
      setTasks((prev) => prev.map((t) => t.id === id ? { ...t, enabled } : t));
    } catch (e) { setError(e.message); }
  }

  async function deleteTask(id) {
    try { await api.taskDelete(id); setTasks((prev) => prev.filter((t) => t.id !== id)); }
    catch (e) { setError(e.message); }
  }

  useEffect(() => { loadTasks(); }, []);

  return (
    <div className="panel-inner">
      <h3><Clock size={14} /> Scheduled Tasks</h3>
      <p className="muted">Cron-based task scheduling</p>

      <div className="input-row">
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Task name" style={{ width: "35%" }} />
        <input value={cronExpr} onChange={(e) => setCronExpr(e.target.value)} placeholder="Cron (e.g. */5 * * * *)" style={{ width: "40%" }} />
        <input value={commandId} onChange={(e) => setCommandId(e.target.value)} placeholder="Command ID (opt)" style={{ width: "25%" }} />
      </div>
      <button onClick={addTask} disabled={loading} className="btn-primary" style={{ marginTop: 6, width: "100%" }}>
        <Plus size={12} /> Schedule Task
      </button>

      {error && <div className="error-box">{error}</div>}

      {tasks.length === 0 && !loading && <div className="muted">No scheduled tasks</div>}

      {tasks.map((task) => (
        <div key={task.id} className="list-item" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <strong>{task.name}</strong>
            <div className="muted">{task.cron_expr} {task.command_id ? `-> ${task.command_id}` : ""}</div>
          </div>
          <div style={{ display: "flex", gap: 4 }}>
            <button className="btn-sm" onClick={() => toggleTask(task.id, !task.enabled)} title={task.enabled ? "Disable" : "Enable"}>
              {task.enabled ? <PowerOff size={10} /> : <Power size={10} />}
            </button>
            <button className="btn-sm btn-danger" onClick={() => deleteTask(task.id)} title="Delete">
              <Trash2 size={10} />
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}

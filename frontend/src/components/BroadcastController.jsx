import { Radio } from "lucide-react";
import { useState } from "react";
import { api } from "../lib/api.js";

export default function BroadcastController({ onEvent }) {
  const [channel, setChannel] = useState("map");
  const [token, setToken] = useState("");

  async function createSession() {
    try {
      const result = await api.broadcast({ channel, scope: "viewer", expires_in_minutes: 60 });
      setToken(result.token);
      onEvent({ level: "BCAST", text: `${result.channel} ${result.expires_at}` });
    } catch (error) {
      onEvent({ level: "ERR", text: error.message });
    }
  }

  return (
    <section className="panel broadcast-panel">
      <div className="panel-title">
        <span>BROADCAST</span>
        <button className="icon-button" onClick={createSession} title="Create broadcast session">
          <Radio size={15} />
        </button>
      </div>
      <div className="command-row">
        <select value={channel} onChange={(event) => setChannel(event.target.value)}>
          <option value="map">map</option>
          <option value="terminal">terminal</option>
          <option value="alerts">alerts</option>
        </select>
      </div>
      {token && <code className="token-line">{token}</code>}
    </section>
  );
}

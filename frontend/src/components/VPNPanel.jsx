import { useState, useEffect } from "react";
import { Shield, ShieldOff } from "lucide-react";
import { api } from "../lib/api.js";

export default function VPNPanel() {
  const [status, setStatus] = useState(null);
  const [configPath, setConfigPath] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    refreshStatus();
  }, []);

  async function refreshStatus() {
    try {
      const data = await api.vpnStatus();
      setStatus(data);
    } catch (err) {
      setStatus({ error: err.message });
    }
  }

  async function connect() {
    if (!configPath.trim()) return;
    setLoading(true);
    try {
      await api.vpnConnect(configPath);
      await refreshStatus();
    } catch (err) {
      setStatus({ error: err.message });
    } finally {
      setLoading(false);
    }
  }

  async function disconnect() {
    setLoading(true);
    try {
      const wg = status?.wireguard?.interfaces?.[0];
      if (wg) {
        await api.vpnDisconnect(wg.name);
      }
      await refreshStatus();
    } catch (err) {
      setStatus({ error: err.message });
    } finally {
      setLoading(false);
    }
  }

  const wgActive = status?.wireguard?.active;
  const ovpnActive = status?.openvpn?.active;

  return (
    <section className="panel vpn-panel">
      <div className="panel-title">
        <span>VPN</span>
        {wgActive || ovpnActive ? <Shield size={15} className="status-ok" /> : <ShieldOff size={15} />}
      </div>
      <div className="vpn-status">
        <div className="status-row">
          <span>WireGuard</span>
          <code className={wgActive ? "status-ok" : "status-off"}>{wgActive ? "ACTIVE" : "INACTIVE"}</code>
        </div>
        <div className="status-row">
          <span>OpenVPN</span>
          <code className={ovpnActive ? "status-ok" : "status-off"}>{ovpnActive ? "ACTIVE" : "INACTIVE"}</code>
        </div>
      </div>
      <div className="tool-controls">
        <div className="target-row">
          <input
            value={configPath}
            onChange={(e) => setConfigPath(e.target.value)}
            placeholder="/etc/wg/nova.conf"
          />
          <button className="command-button" onClick={connect} disabled={loading || wgActive}>
            {loading ? "..." : "CONNECT"}
          </button>
          <button className="command-button command-button-danger" onClick={disconnect} disabled={loading || !wgActive}>
            DISCONNECT
          </button>
        </div>
      </div>
      {status?.error && <div className="inline-error">{status.error}</div>}
      <button className="icon-button refresh-btn" onClick={refreshStatus} title="Refresh status">REFRESH</button>
    </section>
  );
}

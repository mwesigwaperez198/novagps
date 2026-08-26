import { useEffect, useMemo, useRef, useState } from "react";
import { Monitor, Map, Menu, X, LogOut, Search } from "lucide-react";
import AlertsLog from "./components/AlertsLog.jsx";
import BroadcastController from "./components/BroadcastController.jsx";
import CameraPanel from "./components/CameraPanel.jsx";
import DeviceList from "./components/DeviceList.jsx";
import DeviceRegisterForm from "./components/DeviceRegisterForm.jsx";
import ForensicsPanel from "./components/ForensicsPanel.jsx";
import IDSPanel from "./components/IDSPanel.jsx";
import LoginScreen from "./components/LoginScreen.jsx";
import MapPanel from "./components/MapPanel.jsx";
import OSINTPanel from "./components/OSINTPanel.jsx";
import ScanPanel from "./components/ScanPanel.jsx";
import TerminalPanel from "./components/TerminalPanel.jsx";
import VPNPanel from "./components/VPNPanel.jsx";
import WebScanPanel from "./components/WebScanPanel.jsx";
import { api, getAuthToken, setAuthToken, WS_URL } from "./lib/api.js";

function hashLine(value) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  let hash = 0;
  for (let index = 0; index < text.length; index += 1) {
    hash = (hash << 5) - hash + text.charCodeAt(index);
    hash |= 0;
  }
  return `#${Math.abs(hash).toString(16).padStart(8, "0")}`;
}

const PANEL_TABS = [
  { id: "terminal", label: "DIAG" },
  { id: "scan", label: "SCAN" },
  { id: "osint", label: "OSINT" },
  { id: "webscan", label: "WEB" },
  { id: "camera", label: "CAM" },
  { id: "vpn", label: "VPN" },
  { id: "ids", label: "IDS" },
  { id: "forensics", label: "FORE" },
];

export default function App() {
  const [user, setUser] = useState(null);
  const [devices, setDevices] = useState([]);
  const [selectedDeviceId, setSelectedDeviceId] = useState(null);
  const [events, setEvents] = useState([]);
  const [status, setStatus] = useState("BOOT");
  const [viewMode, setViewMode] = useState("consumer");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [toasts, setToasts] = useState([]);
  const [activePanel, setActivePanel] = useState("terminal");
  const [searchQuery, setSearchQuery] = useState("");
  const wsRef = useRef(null);

  const selectedDevice = useMemo(
    () => devices.find((device) => device.id === selectedDeviceId) || devices[0],
    [devices, selectedDeviceId],
  );

  useEffect(() => {
    if (getAuthToken()) {
      setUser({ token: getAuthToken() });
    }
  }, []);

  function addToast(message, type = "info") {
    const id = Date.now();
    setToasts((items) => [...items, { id, message, type }]);
    setTimeout(() => {
      setToasts((items) => items.filter((t) => t.id !== id));
    }, 4000);
  }

  async function loadDevices() {
    try {
      const nextDevices = searchQuery ? await api.search(searchQuery) : await api.devices();
      setDevices(nextDevices);
      if (!selectedDeviceId && nextDevices.length) {
        setSelectedDeviceId(nextDevices[0].id);
      }
    } catch (error) {
      addToast(`Failed to load devices: ${error.message}`, "error");
    }
  }

  function connectWebSocket() {
    if (wsRef.current) return;
    try {
      const ws = new WebSocket(`${WS_URL}?channel=map`);
      ws.onopen = () => {
        addToast("WebSocket connected", "info");
      };
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.event === "location.updated" && data.device_id) {
            setDevices((items) =>
              items.map((device) =>
                device.id === data.device_id
                  ? { ...device, latest_location: data }
                  : device,
              ),
            );
          }
        } catch (e) {
          // ignore parse errors
        }
      };
      ws.onclose = () => {
        wsRef.current = null;
        setTimeout(connectWebSocket, 5000);
      };
      ws.onerror = () => {
        ws.close();
      };
      wsRef.current = ws;
    } catch (e) {
      // WebSocket not available, fall back to polling
    }
  }

  useEffect(() => {
    if (!user) return;
    api.health()
      .then(() => setStatus("ONLINE"))
      .catch(() => setStatus("DEGRADED"));
    loadDevices();
    connectWebSocket();
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [user]);

  useEffect(() => {
    if (!user) return;
    if (viewMode === "developer") return;
    const interval = setInterval(async () => {
      if (!selectedDeviceId) return;
      try {
        const locations = await api.locations(selectedDeviceId, 1);
        if (locations.length > 0) {
          const loc = locations[0];
          setDevices((items) =>
            items.map((device) =>
              device.id === selectedDeviceId
                ? { ...device, latest_location: loc }
                : device,
            ),
          );
        }
      } catch (e) {
        // silent
      }
    }, 5000);
    return () => clearInterval(interval);
  }, [selectedDeviceId, viewMode, user]);

  function handleLogout() {
    setAuthToken(null);
    setUser(null);
    setDevices([]);
    setSelectedDeviceId(null);
    setEvents([]);
    setStatus("BOOT");
  }

  if (!user) {
    return <LoginScreen onLogin={(data) => setUser(data)} />;
  }

  return (
    <main className="nova-shell">
      <header className="topbar">
        <div className="brand">NOVA GPS</div>
        <div className="search-bar">
          <Search size={14} />
          <input
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && loadDevices()}
            placeholder="Search devices..."
          />
        </div>
        <div className="view-toggle">
          <button
            className={`icon-button ${viewMode === "consumer" ? "is-active" : ""}`}
            onClick={() => setViewMode("consumer")}
            title="Consumer View"
            type="button"
          >
            <Map size={15} />
          </button>
          <button
            className={`icon-button ${viewMode === "developer" ? "is-active" : ""}`}
            onClick={() => setViewMode("developer")}
            title="Developer View"
            type="button"
          >
            <Monitor size={15} />
          </button>
        </div>
        <div className="hash">SYS:{hashLine(status)}</div>
        <div className={`status status-${status.toLowerCase()}`}>{status}</div>
        <button className="icon-button logout-btn" onClick={handleLogout} title="Logout">
          <LogOut size={15} />
        </button>
      </header>

      <section className="workspace">
        {viewMode === "consumer" ? (
          <>
            <button
              className="mobile-menu-toggle"
              onClick={() => setSidebarOpen(!sidebarOpen)}
              type="button"
              aria-label="Toggle sidebar"
            >
              {sidebarOpen ? <X size={20} /> : <Menu size={20} />}
            </button>
            <div className={`sidebar ${sidebarOpen ? "open" : ""}`}>
              <DeviceList devices={devices} selectedId={selectedDevice?.id} onSelect={(id) => {
                setSelectedDeviceId(id);
                setSidebarOpen(false);
              }} onRefresh={loadDevices} />
            </div>
            <div className="main-content">
              <MapPanel device={selectedDevice} />
            </div>
          </>
        ) : (
          <>
            <DeviceList devices={devices} selectedId={selectedDevice?.id} onSelect={setSelectedDeviceId} onRefresh={loadDevices} />
            <MapPanel device={selectedDevice} />
            <aside className="right-rail">
              <div className="panel-tabs">
                {PANEL_TABS.map((tab) => (
                  <button
                    key={tab.id}
                    className={`panel-tab ${activePanel === tab.id ? "is-active" : ""}`}
                    onClick={() => setActivePanel(tab.id)}
                    type="button"
                  >
                    {tab.label}
                  </button>
                ))}
              </div>
              <div className="panel-content">
                {activePanel === "terminal" && <TerminalPanel />}
                {activePanel === "scan" && <ScanPanel />}
                {activePanel === "osint" && <OSINTPanel />}
                {activePanel === "webscan" && <WebScanPanel />}
                {activePanel === "camera" && <CameraPanel />}
                {activePanel === "vpn" && <VPNPanel />}
                {activePanel === "ids" && <IDSPanel />}
                {activePanel === "forensics" && <ForensicsPanel />}
              </div>
              <BroadcastController onEvent={(event) => setEvents((items) => [event, ...items])} />
              <DeviceRegisterForm
                onRegistered={(device) => {
                  setDevices((items) => [device, ...items]);
                  setSelectedDeviceId(device.id);
                  addToast(`Device ${device.name} registered`, "success");
                  setEvents((items) => [{ level: "REG", text: `${hashLine(device.id)} ${device.name}` }, ...items]);
                }}
                onError={(error) => addToast(error, "error")}
              />
            </aside>
          </>
        )}
      </section>

      {viewMode === "developer" && <AlertsLog events={events} />}

      <div className="toast-container">
        {toasts.map((toast) => (
          <div key={toast.id} className={`toast toast-${toast.type}`}>
            {toast.message}
          </div>
        ))}
      </div>
    </main>
  );
}

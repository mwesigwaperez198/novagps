import { useEffect, useMemo, useState } from "react";
import { Monitor, Map, Menu, X } from "lucide-react";
import AlertsLog from "./components/AlertsLog.jsx";
import BroadcastController from "./components/BroadcastController.jsx";
import DeviceList from "./components/DeviceList.jsx";
import DeviceRegisterForm from "./components/DeviceRegisterForm.jsx";
import MapPanel from "./components/MapPanel.jsx";
import TerminalPanel from "./components/TerminalPanel.jsx";
import { api } from "./lib/api.js";

function hashLine(value) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  let hash = 0;
  for (let index = 0; index < text.length; index += 1) {
    hash = (hash << 5) - hash + text.charCodeAt(index);
    hash |= 0;
  }
  return `#${Math.abs(hash).toString(16).padStart(8, "0")}`;
}

export default function App() {
  const [devices, setDevices] = useState([]);
  const [selectedDeviceId, setSelectedDeviceId] = useState(null);
  const [events, setEvents] = useState([]);
  const [status, setStatus] = useState("BOOT");
  const [viewMode, setViewMode] = useState("consumer"); // "consumer" or "developer"
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [toasts, setToasts] = useState([]);

  const selectedDevice = useMemo(
    () => devices.find((device) => device.id === selectedDeviceId) || devices[0],
    [devices, selectedDeviceId],
  );

  function addToast(message, type = "info") {
    const id = Date.now();
    setToasts((items) => [...items, { id, message, type }]);
    setTimeout(() => {
      setToasts((items) => items.filter((t) => t.id !== id));
    }, 4000);
  }

  async function loadDevices() {
    try {
      const nextDevices = await api.devices();
      setDevices(nextDevices);
      if (!selectedDeviceId && nextDevices.length) {
        setSelectedDeviceId(nextDevices[0].id);
      }
    } catch (error) {
      addToast(`Failed to load devices: ${error.message}`, "error");
    }
  }

  useEffect(() => {
    api.health()
      .then(() => setStatus("ONLINE"))
      .catch(() => setStatus("DEGRADED"));
    loadDevices();
  }, []);

  // Poll for location updates (serverless-friendly alternative to WebSocket)
  useEffect(() => {
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
                ? {
                    ...device,
                    latest_location: loc,
                  }
                : device,
            ),
          );
        }
      } catch (error) {
        // Silent fail for polling
      }
    }, 5000);

    return () => clearInterval(interval);
  }, [selectedDeviceId, viewMode]);

  return (
    <main className="nova-shell">
      <header className="topbar">
        <div className="brand">NOVA GPS</div>
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
              <TerminalPanel />
              <BroadcastController onEvent={(event) => setEvents((items) => [event, ...items])} />
              <DeviceRegisterForm
                onRegistered={(device) => {
                  setDevices((items) => [device, ...items]);
                  setSelectedDeviceId(device.id);
                  addToast(`Device ${device.name} registered successfully`, "success");
                  setEvents((items) => [{ level: "REG", text: `${hashLine(device.id)} ${device.name}` }, ...items]);
                }}
                onError={(error) => addToast(error, "error")}
              />
            </aside>
          </>
        )}
      </section>

      {viewMode === "developer" && <AlertsLog events={events} />}

      {/* Toast notifications */}
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
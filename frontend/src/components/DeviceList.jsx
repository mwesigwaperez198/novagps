import { RefreshCw, Smartphone, Truck } from "lucide-react";

function DeviceIcon({ type }) {
  return type === "vehicle" || type === "motorcycle" ? <Truck size={16} /> : <Smartphone size={16} />;
}

export default function DeviceList({ devices, selectedId, onSelect, onRefresh }) {
  return (
    <aside className="panel device-list">
      <div className="panel-title">
        <span>DEVICES</span>
        <button className="icon-button" onClick={onRefresh} title="Refresh devices">
          <RefreshCw size={15} />
        </button>
      </div>
      <div className="device-scroll">
        {devices.map((device) => (
          <button
            key={device.id}
            className={`device-row ${selectedId === device.id ? "is-selected" : ""}`}
            onClick={() => onSelect(device.id)}
          >
            <DeviceIcon type={device.device_type} />
            <span className="device-main">
              <span>{device.name}</span>
              <code>{device.identifier}</code>
            </span>
            <span className="device-type">{device.device_type}</span>
          </button>
        ))}
        {!devices.length && <div className="empty">NO DEVICES</div>}
      </div>
    </aside>
  );
}

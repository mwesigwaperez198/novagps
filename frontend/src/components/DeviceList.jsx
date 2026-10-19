import { Plus, RefreshCw, Smartphone, Truck } from "lucide-react";

function DeviceIcon({ type }) {
  return type === "vehicle" || type === "motorcycle" ? <Truck size={16} /> : <Smartphone size={16} />;
}

function formatPlace(loc) {
  if (!loc?.place_name) return null;
  const parts = loc.place_name.split(",");
  return parts[0]?.trim() || null;
}

export default function DeviceList({ devices, selectedId, onSelect, onRefresh, onAddDevice }) {
  return (
    <aside className="panel device-list">
      <div className="panel-title">
        <span>DEVICES</span>
        <span className="device-list-actions">
          {onAddDevice && (
            <button className="icon-button" onClick={onAddDevice} title="Add a device" type="button">
              <Plus size={15} />
            </button>
          )}
          <button className="icon-button" onClick={onRefresh} title="Refresh devices" type="button">
            <RefreshCw size={15} />
          </button>
        </span>
      </div>
      <div className="device-scroll">
        {devices.map((device) => {
          const place = formatPlace(device.latest_location);
          return (
            <button
              key={device.id}
              className={`device-row ${selectedId === device.id ? "is-selected" : ""}`}
              onClick={() => onSelect(device.id)}
            >
              <DeviceIcon type={device.device_type} />
              <span className="device-main">
                <span>{device.name}</span>
                {place && <code className="device-place">{place}</code>}
                <code>{device.phone} | IMEI: {device.imei || "--"}</code>
              </span>
              <span className="device-type">{device.device_type}</span>
            </button>
          );
        })}
        {!devices.length && (
          <div className="empty device-empty">
            <p>No devices yet.</p>
            <p className="device-empty-hint">
              Add a phone or vehicle to start tracking its live location.
            </p>
            {onAddDevice && (
              <button className="command-button" onClick={onAddDevice} type="button">
                <Plus size={14} /> ADD DEVICE
              </button>
            )}
          </div>
        )}
      </div>
    </aside>
  );
}


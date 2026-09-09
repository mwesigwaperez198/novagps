import { useEffect, useRef, useState } from "react";
import { Camera, Crosshair, Wifi, Video } from "lucide-react";
import { api } from "../lib/api.js";
import { deviceContext } from "../lib/device.js";

export default function CameraPanel({ device }) {
  const ctx = deviceContext(device);
  const [cameras, setCameras] = useState([]);
  const [subnet, setSubnet] = useState(ctx.subnet || "192.168.1.0/24");
  const [scanning, setScanning] = useState(false);
  const [screenshotUrl, setScreenshotUrl] = useState("");
  const [screenshotResult, setScreenshotResult] = useState(null);
  const [recordUrl, setRecordUrl] = useState("");
  const [duration, setDuration] = useState(30);
  const [recordResult, setRecordResult] = useState(null);
  const autoRan = useRef(false);

  useEffect(() => {
    if (ctx.ip) {
      setScreenshotUrl(`rtsp://${ctx.ip}:554/live`);
      setRecordUrl(`rtsp://${ctx.ip}:554/live`);
    }
    if (ctx.subnet) setSubnet(ctx.subnet);
    if (ctx.subnet && ctx.ip && !autoRan.current) {
      autoRan.current = true;
      discover(ctx.subnet);
    }
  }, [ctx.ip, ctx.subnet]);

  async function discover(targetSubnet) {
    const target = targetSubnet || subnet;
    if (!target) return;
    setScanning(true);
    setCameras([]);
    try {
      const result = await api.cameraDiscover(target);
      setCameras(result.cameras || []);
    } catch (err) {
      setCameras([{ error: err.message }]);
    } finally {
      setScanning(false);
    }
  }

  async function takeScreenshot() {
    if (!screenshotUrl.trim()) return;
    try {
      const result = await api.cameraScreenshot(screenshotUrl);
      setScreenshotResult(result);
    } catch (err) {
      setScreenshotResult({ error: err.message });
    }
  }

  async function startRecord() {
    if (!recordUrl.trim()) return;
    try {
      setRecordResult(null);
      const result = await api.cameraRecord(recordUrl, duration);
      setRecordResult(result);
    } catch (err) {
      setRecordResult({ error: err.message });
    }
  }

  return (
    <section className="panel camera-panel">
      <div className="panel-title">
        <span>CAMERA</span>
        <Camera size={15} />
      </div>
      {device?.id && (
        <div className="tool-device-context">
          <Crosshair size={12} />
          {device.identifier}
          {ctx.imei ? ` · IMEI ${ctx.imei}` : ""}
          {ctx.ip ? ` · ${ctx.ip}` : ""}
        </div>
      )}
      {!device?.id && <div className="inline-error">No connected device — pick one from the device list first.</div>}
      <div className="tool-controls">
        <div className="target-row">
          <input
            value={subnet}
            onChange={(e) => setSubnet(e.target.value)}
            placeholder="192.168.1.0/24"
          />
          <button className="command-button" onClick={() => discover()} disabled={scanning}>
            {scanning ? "..." : "DISCOVER"}
          </button>
        </div>
      </div>
      <div className="camera-results">
        {cameras.map((cam, i) => (
          <div key={i} className="camera-item">
            {cam.error ? (
              <span className="inline-error">{cam.error}</span>
            ) : (
              <span>{cam.ip}:{cam.port} ({cam.protocol})</span>
            )}
          </div>
        ))}
        {!scanning && cameras.length === 0 && (
          <div className="camera-item empty-row">
            <Wifi size={13} /> No cameras on this subnet yet.
          </div>
        )}
      </div>
      <div className="tool-controls">
        <div className="target-row">
          <input
            value={screenshotUrl}
            onChange={(e) => setScreenshotUrl(e.target.value)}
            placeholder="rtsp://ip:554/live"
          />
          <button className="command-button" onClick={takeScreenshot}>SNAP</button>
        </div>
      </div>
      {screenshotResult && (
        <div className="scan-result">
          <pre>{JSON.stringify(screenshotResult, null, 2)}</pre>
        </div>
      )}
      <div className="tool-controls">
        <div className="target-row">
          <input
            value={recordUrl}
            onChange={(e) => setRecordUrl(e.target.value)}
            placeholder="rtsp://ip:554/live (record)"
          />
          <input
            type="number"
            value={duration}
            min={5}
            max={300}
            onChange={(e) => setDuration(Number(e.target.value))}
            style={{ width: 54 }}
            placeholder="sec"
          />
          <button className="command-button" onClick={startRecord} title="Record video">
            <Video size={13} /> REC
          </button>
        </div>
      </div>
      {recordResult && (
        <div className="scan-result">
          <pre>{JSON.stringify(recordResult, null, 2)}</pre>
        </div>
      )}
    </section>
  );
}
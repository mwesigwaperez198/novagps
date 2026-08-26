import { useState } from "react";
import { Camera, Wifi } from "lucide-react";
import { api } from "../lib/api.js";

export default function CameraPanel() {
  const [cameras, setCameras] = useState([]);
  const [subnet, setSubnet] = useState("192.168.1.0/24");
  const [scanning, setScanning] = useState(false);
  const [screenshotUrl, setScreenshotUrl] = useState("");
  const [screenshotResult, setScreenshotResult] = useState(null);

  async function discover() {
    setScanning(true);
    try {
      const result = await api.cameraDiscover(subnet);
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

  return (
    <section className="panel camera-panel">
      <div className="panel-title">
        <span>CAMERA</span>
        <Camera size={15} />
      </div>
      <div className="tool-controls">
        <div className="target-row">
          <input
            value={subnet}
            onChange={(e) => setSubnet(e.target.value)}
            placeholder="192.168.1.0/24"
          />
          <button className="command-button" onClick={discover} disabled={scanning}>
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
    </section>
  );
}

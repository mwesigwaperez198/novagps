import { useEffect, useRef, useState } from "react";
import { Activity, Globe2, Map as MapIcon, Maximize2, Minimize2, Radar, Satellite } from "lucide-react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { api } from "../lib/api.js";
import GlobeView from "./GlobeView.jsx";
import { KAMPALA, getViewerLocation, relativeTime, reportViewerLocation, speedColor } from "../lib/live.js";

function asNumber(value) {
  const next = Number(value);
  return Number.isFinite(next) ? next : null;
}

function normalizeLocation(location) {
  if (!location) return null;
  const latitude = asNumber(location.latitude);
  const longitude = asNumber(location.longitude);
  if (latitude === null || longitude === null) return null;
  return {
    ...location,
    latitude,
    longitude,
    altitude: asNumber(location.altitude),
    speed: asNumber(location.speed),
    heading: asNumber(location.heading),
    accuracy: asNumber(location.accuracy),
  };
}

function samePoint(left, right) {
  return (
    left &&
    right &&
    Math.abs(left.latitude - right.latitude) < 1e-6 &&
    Math.abs(left.longitude - right.longitude) < 1e-6 &&
    left.recorded_at === right.recorded_at
  );
}

function makeBeaconIcon(deviceType) {
  const color = deviceType === "vehicle" || deviceType === "motorcycle" ? "#29e06b" : "#40d7ff";
  return L.divIcon({
    className: "gps-beacon-icon",
    html: `<div class="gps-beacon" style="--beacon:${color}"><div class="gps-beacon-core"></div><div class="gps-beacon-ring"></div></div>`,
    iconSize: [34, 34],
    iconAnchor: [17, 17],
    popupAnchor: [0, -20],
  });
}

function popupHtml(device, loc) {
  const speed = loc?.speed ?? "--";
  const heading = loc?.heading ?? "--";
  return [
    `<strong>${device?.name || "Device"}</strong>`,
    device?.model ? `<div>${device.model}${device.manufacturer ? ` · ${device.manufacturer}` : ""}</div>` : "",
    device?.phone ? `<div>${device.phone}</div>` : "",
    loc?.place_name ? `<div class="gps-poptip">${loc.place_name}</div>` : "",
    `<div class="gps-poptip">${loc?.latitude?.toFixed(6)}, ${loc?.longitude?.toFixed(6)}</div>`,
    `<div>Speed ${speed} km/h · Heading ${heading}° · ${relativeTime(loc?.recorded_at) || "no fix"}</div>`,
  ].filter(Boolean).join("");
}

export default function LiveMap({ device, onScanNet, nearby }) {
  const containerRef = useRef(null);
  const mapRef = useRef(null);
  const dataLayerRef = useRef(null);
  const layerRefs = useRef({});
  const [routeHistory, setRouteHistory] = useState([]);
  const [geofences, setGeofences] = useState([]);
  const [simulating, setSimulating] = useState(false);
  const [simError, setSimError] = useState("");
  const [mapReady, setMapReady] = useState(false);
  const [mode, setMode] = useState("map");
  const [base, setBase] = useState("streets");
  const [floating, setFloating] = useState(false);
  const [win, setWin] = useState({ x: 60, y: 60, w: 660, h: 480 });
  const dragRef = useRef(null);

  const liveLocation = normalizeLocation(device?.latest_location);
  const publicIp = device?.latest_location?.ip_address || device?.ip_address || "";
  const localIp = device?.latest_location?.local_ip || device?.local_ip || "";
  const cameraCount = (nearby?.hosts || []).filter((host) => host.is_camera).length;

  // ---- init map once ----
  useEffect(() => {
    if (!containerRef.current || mapRef.current) return;
    const map = L.map(containerRef.current, {
      zoomControl: true,
      doubleClickZoom: true,
      dragging: true,
      scrollWheelZoom: true,
      attributionControl: true,
    }).setView([KAMPALA.latitude, KAMPALA.longitude], 13);

    const streets = L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      maxZoom: 20,
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
    });
    const satellite = L.tileLayer(
      "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}",
      { maxZoom: 19, attribution: "Tiles &copy; Esri &mdash; Source: Esri, Maxar, Earthstar Geographics" },
    );
    streets.addTo(map);
    layerRefs.current = { streets, satellite };

    L.control.scale({ imperial: false, metric: true }).addTo(map);

    const dataLayer = L.layerGroup().addTo(map);
    mapRef.current = map;
    dataLayerRef.current = dataLayer;
    setMapReady(true);
    return () => {
      map.remove();
      mapRef.current = null;
      dataLayerRef.current = null;
      layerRefs.current = {};
    };
  }, []);

  useEffect(() => {
    const map = mapRef.current;
    const layers = layerRefs.current;
    if (!map || !layers.streets || !layers.satellite) return;
    if (base === "satellite") {
      map.removeLayer(layers.streets);
      layers.satellite.addTo(map);
    } else {
      map.removeLayer(layers.satellite);
      layers.streets.addTo(map);
    }
  }, [base]);

  useEffect(() => {
    mapRef.current?.invalidateSize();
  }, [floating, win.w, win.h]);

  function startDrag(event) {
    dragRef.current = { startX: event.clientX, startY: event.clientY, x: win.x, y: win.y };
  }

  function moveDrag(event) {
    if (!dragRef.current) return;
    const dx = event.clientX - dragRef.current.startX;
    const dy = event.clientY - dragRef.current.startY;
    setWin((current) => ({
      ...current,
      x: dragRef.current.x + dx,
      y: dragRef.current.y + dy,
    }));
  }

  function endDrag() {
    dragRef.current = null;
  }

  function startResize(event) {
    const startW = win.w;
    const startH = win.h;
    const startX = event.clientX;
    const startY = event.clientY;
    function onMove(move) {
      setWin((current) => ({
        ...current,
        w: Math.max(360, startW + move.clientX - startX),
        h: Math.max(260, startH + move.clientY - startY),
      }));
    }
    function onUp() {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
    }
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
  }

  // ---- load data for the selected device ----
  useEffect(() => {
    let active = true;
    setRouteHistory([]);
    if (!device?.id) return () => { active = false; };
    api.locations(device.id, 160)
      .then((items) => { if (active) setRouteHistory(items); })
      .catch(() => { if (active) setRouteHistory([]); });
    return () => { active = false; };
  }, [device?.id]);

  useEffect(() => {
    let active = true;
    api.geofences()
      .then((data) => { if (active) setGeofences(data.geofences || []); })
      .catch(() => {});
    return () => { active = false; };
  }, []);

  // ---- live poll: keep the trail fresh without a restart ----
  useEffect(() => {
    if (!device?.id) return undefined;
    const interval = setInterval(() => {
      api.locations(device.id, 160)
        .then(setRouteHistory)
        .catch(() => {});
    }, 6000);
    return () => clearInterval(interval);
  }, [device?.id]);

  // ---- render layers ----
  useEffect(() => {
    const map = mapRef.current;
    const dataLayer = dataLayerRef.current;
    if (!map || !dataLayer || !device) return;

    dataLayer.clearLayers();

    const path = routeHistory.map(normalizeLocation).filter(Boolean).reverse();
    if (liveLocation && !samePoint(path[path.length - 1], liveLocation)) {
      path.push(liveLocation);
    }

    const latest = path[path.length - 1] || null;

    if (latest) {
      const accuracy = Math.max(8, latest.accuracy ?? 25);
      L.circle([latest.latitude, latest.longitude], {
        radius: accuracy,
        color: speedColor(latest.speed),
        weight: 1,
        opacity: 0.35,
        fillColor: speedColor(latest.speed),
        fillOpacity: 0.12,
      }).addTo(dataLayer);

      const marker = L.marker([latest.latitude, latest.longitude], { icon: makeBeaconIcon(device?.device_type) })
        .addTo(dataLayer)
        .bindPopup(popupHtml(device, latest), { closeButton: true });
      marker.openPopup();
    }

    if (path.length >= 2) {
      for (let i = 1; i < path.length; i += 1) {
        L.polyline(
          [
            [path[i - 1].latitude, path[i - 1].longitude],
            [path[i].latitude, path[i].longitude],
          ],
          { color: speedColor(path[i].speed), weight: 3, opacity: 0.85 },
        ).addTo(dataLayer);
      }
      path.forEach((loc) => {
        if (loc !== latest) {
          L.circleMarker([loc.latitude, loc.longitude], {
            radius: 3,
            color: speedColor(loc.speed),
            fillColor: speedColor(loc.speed),
            fillOpacity: 0.6,
          }).addTo(dataLayer);
        }
      });
    }

    geofences.forEach((fence) => {
      if (fence.coords && fence.coords.length >= 3) {
        const coordinates = fence.coords.map((c) => [Number(c.latitude), Number(c.longitude)]);
        L.polygon(coordinates, {
          color: "#40d7ff",
          weight: 2,
          fillColor: "#40d7ff",
          fillOpacity: 0.08,
        }).bindPopup(`<strong>${fence.name || "Geofence"}</strong><br/>${fence.description || ""}`).addTo(dataLayer);
      }
    });

    // Frame the device when switching to it, so the user is never lost.
    if (latest) {
      const bounds = L.latLngBounds(path.map((p) => [p.latitude, p.longitude]));
      const anchorReset = (dataLayer.options || {}).resetAnchorDeviceId !== device.id;
      if (anchorReset || bounds.getNorth() - bounds.getSouth() < 1e-9) {
        map.fitBounds(bounds.pad(0.3), { maxZoom: 17 });
        dataLayer.options.resetAnchorDeviceId = device.id;
      }
    }
  }, [device?.id, device?.device_type, device?.latest_location, mapReady, routeHistory, geofences, liveLocation]);

  async function reportLocation() {
    if (!device?.identifier) return;
    setSimulating(true);
    setSimError("");
    try {
      const viewer = await getViewerLocation();
      await reportViewerLocation(device, api, viewer);
      const items = await api.locations(device.id, 160);
      setRouteHistory(items);
      dataLayerRef.current.options.resetAnchorDeviceId = undefined;
      if (mapRef.current && items.length) {
        const latestItem = items[0];
        mapRef.current.setView([latestItem.latitude, latestItem.longitude], 17, { animate: true });
      }
    } catch (err) {
      setSimError(err.message || "Could not report location (grant consent / location access first)");
    } finally {
      setSimulating(false);
    }
  }

  return (
    <section
      className={`panel live-map-panel ${floating ? "is-floating" : ""} ${mode === "globe" ? "is-globe" : ""}`}
      style={floating ? { left: win.x, top: win.y, width: win.w, height: win.h } : undefined}
    >
      {floating && (
        <div
          className="map-pop-bar"
          onPointerDown={startDrag}
          onPointerMove={moveDrag}
          onPointerUp={endDrag}
          onPointerCancel={endDrag}
        >
          <span className="map-pop-title">NOVA MAP</span>
          <button
            className="map-pop-btn"
            onClick={() => setFloating(false)}
            title="Dock map back into the layout"
            type="button"
          >
            <Minimize2 size={14} />
          </button>
        </div>
      )}
      <div className="map-stage">
        <div ref={containerRef} className="live-map" style={mode === "globe" ? { display: "none" } : {}} />
        {mode === "globe" && <GlobeView device={device} />}
        <div className="map-topbar">
        <code className="map-coords">
          {liveLocation ? `${liveLocation.latitude.toFixed(6)}, ${liveLocation.longitude.toFixed(6)}`
            : "NO FIX — select a device"}
        </code>
        {publicIp && <code className="map-ip public">{publicIp}</code>}
        {localIp && <code className="map-ip local">{localIp}</code>}
        <div className="map-dimension">
          <button
            className={`command-button ${mode === "map" ? "is-active" : ""}`}
            onClick={() => setMode("map")}
            title="2D map"
            type="button"
          >
            <MapIcon size={14} /> 2D
          </button>
          <button
            className={`command-button ${mode === "globe" ? "is-active" : ""}`}
            onClick={() => setMode("globe")}
            title="3D satellite globe"
            type="button"
          >
            <Globe2 size={14} /> 3D
          </button>
        </div>
        {mode === "map" && (
          <div className="map-dimension">
            <button
              className={`command-button ${base === "streets" ? "is-active" : ""}`}
              onClick={() => setBase("streets")}
              title="Street map tiles"
              type="button"
            >
              <MapIcon size={13} /> STREET
            </button>
            <button
              className={`command-button ${base === "satellite" ? "is-active" : ""}`}
              onClick={() => setBase("satellite")}
              title="High-resolution satellite imagery"
              type="button"
            >
              <Satellite size={13} /> SAT
            </button>
          </div>
        )}
        {!floating && (
          <button
            className="command-button"
            onClick={() => setFloating(true)}
            title="Pop the map out into a draggable, resizable window"
            type="button"
          >
            <Maximize2 size={14} />
          </button>
        )}
        {typeof onScanNet === "function" && (
          <button
            className={`command-button ${nearby ? "is-active" : ""}`}
            onClick={onScanNet}
            title="Scan the network this device is on for nearby hosts / cameras"
            type="button"
          >
            <Radar size={14} /> SCAN NET{cameraCount ? ` (${cameraCount} CAM)` : ""}
          </button>
        )}
        <button
          className={`command-button ${simulating ? "is-busy" : ""}`}
          onClick={reportLocation}
          disabled={simulating || !device?.identifier}
          type="button"
        >
          <Activity size={14} /> {simulating ? "REPORTING…" : "REPORT MY LOCATION"}
        </button>
      </div>
      {floating && <div className="map-resize-handle" onPointerDown={startResize} title="Resize map window" />}
      {simError && <div className="map-error">{simError}</div>}
      </div>
    </section>
  );
}
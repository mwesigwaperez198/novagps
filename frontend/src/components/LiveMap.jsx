import { useEffect, useRef, useState } from "react";
import { Activity } from "lucide-react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { api } from "../lib/api.js";
import { KAMPALA, getViewerLocation, relativeTime, simulateMotion, speedColor } from "../lib/live.js";

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

export default function LiveMap({ device }) {
  const containerRef = useRef(null);
  const mapRef = useRef(null);
  const dataLayerRef = useRef(null);
  const [routeHistory, setRouteHistory] = useState([]);
  const [geofences, setGeofences] = useState([]);
  const [simulating, setSimulating] = useState(false);
  const [simError, setSimError] = useState("");
  const [mapReady, setMapReady] = useState(false);

  const liveLocation = normalizeLocation(device?.latest_location);

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

    L.control.layers({ Streets: streets, Satellite: satellite }, {}, { collapsed: true }).addTo(map);
    L.control.scale({ imperial: false, metric: true }).addTo(map);

    const dataLayer = L.layerGroup().addTo(map);
    mapRef.current = map;
    dataLayerRef.current = dataLayer;
    setMapReady(true);
    return () => {
      map.remove();
      mapRef.current = null;
      dataLayerRef.current = null;
    };
  }, []);

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

  async function simulate() {
    if (!device?.identifier) return;
    setSimulating(true);
    setSimError("");
    try {
      const viewer = await getViewerLocation();
      await simulateMotion(device, api, viewer);
      const items = await api.locations(device.id, 160);
      setRouteHistory(items);
      dataLayerRef.current.options.resetAnchorDeviceId = undefined;
      if (mapRef.current && items.length) {
        const latestItem = items[0];
        mapRef.current.fitBounds([[latestItem.latitude, latestItem.longitude]], { maxZoom: 16 });
      }
    } catch (err) {
      setSimError(err.message || "Simulation failed (grant consent / location access)");
    } finally {
      setSimulating(false);
    }
  }

  return (
    <section className="panel live-map-panel">
      <div ref={containerRef} className="live-map" />
      <div className="map-topbar">
        <code className="map-coords">
          {liveLocation ? `${liveLocation.latitude.toFixed(6)}, ${liveLocation.longitude.toFixed(6)}`
            : "NO FIX — select a device"}
        </code>
        <button
          className={`command-button ${simulating ? "is-busy" : ""}`}
          onClick={simulate}
          disabled={simulating || !device?.identifier}
          type="button"
        >
          <Activity size={14} /> {simulating ? "SIMULATING…" : "SIMULATE SIGNAL"}
        </button>
      </div>
      {simError && <div className="map-error">{simError}</div>}
    </section>
  );
}
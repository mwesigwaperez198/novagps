import { useEffect, useMemo, useRef, useState } from "react";
import { Compass, Navigation, RefreshCw } from "lucide-react";
import * as THREE from "three";
import { api } from "../lib/api.js";

const DEFAULT_ORIGIN = { latitude: 37.7749, longitude: -122.4194 };
const METERS_PER_DEGREE_LATITUDE = 111_320;
const SCENE_UNIT_METERS = 14;
const CAMERA_MODES = ["follow", "orbit", "overview"];

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
    Math.abs(left.latitude - right.latitude) < 0.000001 &&
    Math.abs(left.longitude - right.longitude) < 0.000001 &&
    left.recorded_at === right.recorded_at
  );
}

function formatMetric(value, suffix = "") {
  if (value === null || value === undefined) return "--";
  return `${Math.round(value)}${suffix}`;
}

function chooseOrigin(points) {
  const latest = points[points.length - 1];
  return latest ? { latitude: latest.latitude, longitude: latest.longitude } : DEFAULT_ORIGIN;
}

function projectLocation(location, origin) {
  const latitudeScale = METERS_PER_DEGREE_LATITUDE;
  const longitudeScale = METERS_PER_DEGREE_LATITUDE * Math.cos((origin.latitude * Math.PI) / 180);
  const x = ((location.longitude - origin.longitude) * longitudeScale) / SCENE_UNIT_METERS;
  const z = -((location.latitude - origin.latitude) * latitudeScale) / SCENE_UNIT_METERS;
  const altitude = location.altitude ?? 0;
  const speedLift = location.speed ? Math.min(location.speed / 8, 5) : 0;
  const y = 4 + Math.max(0, altitude) / 18 + speedLift;
  return { ...location, x, y, z };
}

function disposeMaterial(material) {
  if (Array.isArray(material)) {
    material.forEach(disposeMaterial);
    return;
  }
  material?.dispose?.();
}

function disposeObject(object) {
  object.traverse((child) => {
    child.geometry?.dispose?.();
    disposeMaterial(child.material);
  });
}

function clearGroup(group) {
  while (group.children.length) {
    const child = group.children[0];
    group.remove(child);
    disposeObject(child);
  }
}

function buildRing(radius, color, opacity) {
  const geometry = new THREE.RingGeometry(radius * 0.84, radius, 96);
  const material = new THREE.MeshBasicMaterial({
    color,
    transparent: true,
    opacity,
    side: THREE.DoubleSide,
    depthWrite: false,
  });
  const ring = new THREE.Mesh(geometry, material);
  ring.rotation.x = -Math.PI / 2;
  return ring;
}

function speedToColor(speed) {
  if (speed === null || speed === undefined) return 0x40d7ff;
  if (speed < 20) return 0x29e06b;
  if (speed < 50) return 0xf2d96b;
  if (speed < 80) return 0xf2896b;
  return 0xe04040;
}

function buildDeviceBeacon(point, deviceType) {
  const marker = new THREE.Group();
  marker.position.set(point.x, point.y, point.z);

  const bodyColor = deviceType === "vehicle" || deviceType === "motorcycle" ? 0x29e06b : 0x40d7ff;
  const bodyGeometry = new THREE.ConeGeometry(4.8, 14, 5);
  const bodyMaterial = new THREE.MeshStandardMaterial({
    color: bodyColor,
    emissive: bodyColor,
    emissiveIntensity: 0.34,
    metalness: 0.45,
    roughness: 0.2,
  });
  const body = new THREE.Mesh(bodyGeometry, bodyMaterial);
  body.position.y = 8;
  marker.add(body);

  const coreGeometry = new THREE.SphereGeometry(2.4, 24, 18);
  const coreMaterial = new THREE.MeshBasicMaterial({
    color: 0xf7ff9c,
    transparent: true,
    opacity: 0.92,
  });
  const core = new THREE.Mesh(coreGeometry, coreMaterial);
  core.position.y = 1.8;
  marker.add(core);

  const heading = point.heading ?? 0;
  const arrow = new THREE.Group();
  arrow.rotation.y = (-heading * Math.PI) / 180;

  const shaftGeometry = new THREE.CylinderGeometry(0.45, 0.45, 15, 10);
  const shaftMaterial = new THREE.MeshBasicMaterial({ color: 0xf2d96b, transparent: true, opacity: 0.9 });
  const shaft = new THREE.Mesh(shaftGeometry, shaftMaterial);
  shaft.rotation.x = Math.PI / 2;
  shaft.position.z = -9;
  shaft.position.y = 5.8;
  arrow.add(shaft);

  const noseGeometry = new THREE.ConeGeometry(2.2, 5, 3);
  const noseMaterial = new THREE.MeshBasicMaterial({ color: 0xfff1a6 });
  const nose = new THREE.Mesh(noseGeometry, noseMaterial);
  nose.rotation.x = -Math.PI / 2;
  nose.position.z = -18.2;
  nose.position.y = 5.8;
  arrow.add(nose);
  marker.add(arrow);

  const orbitA = buildRing(10, 0x40d7ff, 0.22);
  orbitA.position.y = 1.2;
  orbitA.name = "pulse-ring";
  marker.add(orbitA);

  const orbitB = buildRing(15, 0x29e06b, 0.14);
  orbitB.position.y = 1.4;
  orbitB.name = "pulse-ring";
  marker.add(orbitB);

  const light = new THREE.PointLight(bodyColor, 2.2, 180);
  light.position.y = 18;
  marker.add(light);

  return marker;
}

function buildCameraMarker(projected, origin) {
  const group = new THREE.Group();
  group.position.set(projected.x, 3, projected.z);

  const poleGeo = new THREE.CylinderGeometry(0.4, 0.5, 12, 8);
  const poleMat = new THREE.MeshStandardMaterial({ color: 0x666666, metalness: 0.6, roughness: 0.3 });
  const pole = new THREE.Mesh(poleGeo, poleMat);
  pole.position.y = 6;
  group.add(pole);

  const headGeo = new THREE.BoxGeometry(3.2, 2.4, 2.4);
  const headMat = new THREE.MeshStandardMaterial({ color: 0xcc2222, metalness: 0.4, roughness: 0.4, emissive: 0xcc2222, emissiveIntensity: 0.2 });
  const head = new THREE.Mesh(headGeo, headMat);
  head.position.y = 13;
  group.add(head);

  const lensGeo = new THREE.CylinderGeometry(0.7, 1.0, 3.6, 12);
  const lensMat = new THREE.MeshStandardMaterial({ color: 0x111111, metalness: 0.8, roughness: 0.15 });
  const lens = new THREE.Mesh(lensGeo, lensMat);
  lens.rotation.x = Math.PI / 2;
  lens.position.set(0, 13, -2.4);
  group.add(lens);

  const lightGeo = new THREE.SphereGeometry(0.6, 12, 8);
  const lightMat = new THREE.MeshBasicMaterial({ color: 0xff3333, transparent: true, opacity: 0.9 });
  const light = new THREE.Mesh(lightGeo, lightMat);
  light.position.set(1.2, 14.6, 0);
  light.name = "camera-recording";
  group.add(light);

  const coverageGeo = new THREE.ConeGeometry(14, 30, 16, 1, true);
  const coverageMat = new THREE.MeshBasicMaterial({
    color: 0xff4444,
    transparent: true,
    opacity: 0.06,
    side: THREE.DoubleSide,
    depthWrite: false,
  });
  const coverage = new THREE.Mesh(coverageGeo, coverageMat);
  coverage.rotation.x = Math.PI / 2;
  coverage.position.set(0, 13, -18);
  group.add(coverage);

  return group;
}

function buildGeofencePolygon(coords, origin, color, opacity) {
  if (!coords || coords.length < 3) return null;

  const latitudeScale = METERS_PER_DEGREE_LATITUDE;
  const longitudeScale = METERS_PER_DEGREE_LATITUDE * Math.cos((origin.latitude * Math.PI) / 180);

  const points3d = coords.map((c) => {
    const x = ((c.longitude - origin.longitude) * longitudeScale) / SCENE_UNIT_METERS;
    const z = -((c.latitude - origin.latitude) * latitudeScale) / SCENE_UNIT_METERS;
    return new THREE.Vector3(x, 0.3, z);
  });

  const group = new THREE.Group();

  const shapePoints = points3d.map((p) => new THREE.Vector2(p.x, p.z));
  const shape = new THREE.Shape(shapePoints);
  const fillGeo = new THREE.ShapeGeometry(shape);
  const fillMat = new THREE.MeshBasicMaterial({
    color,
    transparent: true,
    opacity: opacity * 0.35,
    side: THREE.DoubleSide,
    depthWrite: false,
  });
  const fill = new THREE.Mesh(fillGeo, fillMat);
  fill.rotation.x = -Math.PI / 2;
  fill.position.y = 0.2;
  group.add(fill);

  const linePoints = [...points3d, points3d[0].clone()];
  const lineGeo = new THREE.BufferGeometry().setFromPoints(linePoints);
  const lineMat = new THREE.LineBasicMaterial({
    color,
    transparent: true,
    opacity,
    linewidth: 2,
  });
  const line = new THREE.Line(lineGeo, lineMat);
  group.add(line);

  points3d.forEach((p) => {
    const markerGeo = new THREE.SphereGeometry(1.0, 8, 6);
    const markerMat = new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.8 });
    const marker = new THREE.Mesh(markerGeo, markerMat);
    marker.position.copy(p);
    marker.position.y = 0.8;
    group.add(marker);
  });

  return group;
}

function cameraTarget(points, geofenceGroups) {
  if (!points.length && !geofenceGroups.length) return { x: 0, y: 8, z: 0, radius: 120 };

  let minX = Infinity, maxX = -Infinity, minZ = Infinity, maxZ = -Infinity, maxY = 0;

  points.forEach((point) => {
    minX = Math.min(minX, point.x);
    maxX = Math.max(maxX, point.x);
    minZ = Math.min(minZ, point.z);
    maxZ = Math.max(maxZ, point.z);
    maxY = Math.max(maxY, point.y);
  });

  geofenceGroups.forEach((group) => {
    group.traverse((child) => {
      if (child.isMesh && child.geometry) {
        const pos = child.position;
        minX = Math.min(minX, pos.x);
        maxX = Math.max(maxX, pos.x);
        minZ = Math.min(minZ, pos.z);
        maxZ = Math.max(maxZ, pos.z);
      }
    });
  });

  if (minX === Infinity) return { x: 0, y: 8, z: 0, radius: 120 };

  const width = maxX - minX;
  const depth = maxZ - minZ;
  return {
    x: (minX + maxX) / 2,
    y: maxY + 8,
    z: (minZ + maxZ) / 2,
    radius: Math.max(95, Math.min(420, Math.max(width, depth) * 1.45 + 100)),
  };
}

function positionCamera(camera, mode, focus, latest) {
  const target = new THREE.Vector3(focus.x, focus.y, focus.z);
  if (mode === "overview") {
    camera.position.set(focus.x + focus.radius * 0.72, focus.y + focus.radius * 0.82, focus.z + focus.radius * 0.82);
  } else if (mode === "follow" && latest) {
    const heading = ((latest.heading ?? 45) * Math.PI) / 180;
    camera.position.set(
      latest.x - Math.sin(heading) * 76,
      latest.y + 58,
      latest.z + Math.cos(heading) * 76,
    );
    target.set(latest.x, latest.y + 8, latest.z);
  } else {
    camera.position.set(focus.x + focus.radius, focus.y + focus.radius * 0.58, focus.z + focus.radius);
  }
  camera.lookAt(target);
}

export default function MapPanel({ device }) {
  const mountRef = useRef(null);
  const sceneRef = useRef(null);
  const modeRef = useRef("follow");
  const focusRef = useRef({ x: 0, y: 8, z: 0, radius: 120 });
  const latestRef = useRef(null);
  const animationRef = useRef(null);
  const [routeHistory, setRouteHistory] = useState([]);
  const [cameraMode, setCameraMode] = useState("follow");
  const [geofences, setGeofences] = useState([]);
  const [cameras, setCameras] = useState([]);

  const sourceLocation = device?.latest_location;
  const liveLocation = useMemo(
    () => normalizeLocation(sourceLocation),
    [
      sourceLocation?.latitude,
      sourceLocation?.longitude,
      sourceLocation?.altitude,
      sourceLocation?.speed,
      sourceLocation?.heading,
      sourceLocation?.accuracy,
      sourceLocation?.source,
      sourceLocation?.recorded_at,
    ],
  );
  const path = useMemo(() => {
    const normalized = routeHistory.map(normalizeLocation).filter(Boolean).reverse();
    if (liveLocation && !samePoint(normalized[normalized.length - 1], liveLocation)) {
      normalized.push(liveLocation);
    }
    return normalized.slice(-160);
  }, [routeHistory, liveLocation]);

  const latest = path[path.length - 1] || liveLocation;

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
    api.geofences()
      .then((data) => setGeofences(data.geofences || []))
      .catch(() => {});
  }, []);

  useEffect(() => {
    modeRef.current = cameraMode;
    const sceneState = sceneRef.current;
    if (sceneState) {
      positionCamera(sceneState.camera, cameraMode, focusRef.current, latestRef.current);
    }
  }, [cameraMode]);

  useEffect(() => {
    if (!mountRef.current || sceneRef.current) return;

    const mount = mountRef.current;
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x010302);
    scene.fog = new THREE.FogExp2(0x010302, 0.0038);

    const camera = new THREE.PerspectiveCamera(45, 1, 0.1, 2200);
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    renderer.shadowMap.enabled = true;
    renderer.domElement.className = "mission-webgl";
    mount.appendChild(renderer.domElement);

    const ambient = new THREE.AmbientLight(0x9cffbd, 0.42);
    const key = new THREE.DirectionalLight(0xdffff3, 2.1);
    key.position.set(-140, 220, 80);
    key.castShadow = true;
    const cyan = new THREE.PointLight(0x40d7ff, 1.5, 520);
    cyan.position.set(160, 80, 160);
    const amber = new THREE.PointLight(0xf2d96b, 0.9, 360);
    amber.position.set(-170, 48, -130);
    scene.add(ambient, key, cyan, amber);

    const planeGeometry = new THREE.PlaneGeometry(1100, 1100);
    const planeMaterial = new THREE.MeshStandardMaterial({
      color: 0x02110a,
      metalness: 0.16,
      roughness: 0.72,
      transparent: true,
      opacity: 0.78,
    });
    const plane = new THREE.Mesh(planeGeometry, planeMaterial);
    plane.rotation.x = -Math.PI / 2;
    plane.receiveShadow = true;
    scene.add(plane);

    const grid = new THREE.GridHelper(1100, 44, 0x29e06b, 0x0c4f33);
    grid.position.y = 0.08;
    scene.add(grid);

    const fineGrid = new THREE.GridHelper(320, 32, 0x40d7ff, 0x0b2e34);
    fineGrid.position.y = 0.12;
    scene.add(fineGrid);

    const starGeometry = new THREE.BufferGeometry();
    const starPositions = [];
    for (let index = 0; index < 260; index += 1) {
      starPositions.push(
        (Math.random() - 0.5) * 960,
        Math.random() * 150 + 22,
        (Math.random() - 0.5) * 960,
      );
    }
    starGeometry.setAttribute("position", new THREE.Float32BufferAttribute(starPositions, 3));
    const starMaterial = new THREE.PointsMaterial({
      color: 0x6fffb1,
      size: 1.1,
      transparent: true,
      opacity: 0.34,
      depthWrite: false,
    });
    const stars = new THREE.Points(starGeometry, starMaterial);
    scene.add(stars);

    const routeGroup = new THREE.Group();
    const markerGroup = new THREE.Group();
    const telemetryGroup = new THREE.Group();
    const geofenceGroup = new THREE.Group();
    const cameraMarkerGroup = new THREE.Group();
    scene.add(routeGroup, markerGroup, telemetryGroup, geofenceGroup, cameraMarkerGroup);

    function resize() {
      const width = Math.max(1, mount.clientWidth);
      const height = Math.max(1, mount.clientHeight);
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      renderer.setSize(width, height, false);
    }

    function animate(time) {
      stars.rotation.y += 0.00045;
      markerGroup.children.forEach((marker) => {
        marker.children.forEach((child) => {
          if (child.name === "pulse-ring") {
            child.rotation.z += 0.008;
            const pulse = 1 + Math.sin(time * 0.003) * 0.055;
            child.scale.set(pulse, pulse, pulse);
          }
        });
      });
      cameraMarkerGroup.children.forEach((cam) => {
        cam.children.forEach((child) => {
          if (child.name === "camera-recording") {
            const blink = Math.sin(time * 0.005) > 0 ? 1.0 : 0.2;
            child.material.opacity = blink;
          }
        });
      });
      if (modeRef.current === "orbit") {
        const focus = focusRef.current;
        const orbit = time * 0.00024;
        const radius = focus.radius;
        camera.position.set(
          focus.x + Math.cos(orbit) * radius,
          focus.y + radius * 0.55,
          focus.z + Math.sin(orbit) * radius,
        );
        camera.lookAt(focus.x, focus.y, focus.z);
      }
      renderer.render(scene, camera);
      animationRef.current = requestAnimationFrame(animate);
    }

    resize();
    window.addEventListener("resize", resize);
    sceneRef.current = { scene, camera, renderer, routeGroup, markerGroup, telemetryGroup, geofenceGroup, cameraMarkerGroup, resize };
    positionCamera(camera, "follow", focusRef.current, null);
    animationRef.current = requestAnimationFrame(animate);

    return () => {
      window.removeEventListener("resize", resize);
      cancelAnimationFrame(animationRef.current);
      sceneRef.current = null;
      clearGroup(routeGroup);
      clearGroup(markerGroup);
      clearGroup(telemetryGroup);
      clearGroup(geofenceGroup);
      clearGroup(cameraMarkerGroup);
      disposeObject(plane);
      grid.geometry.dispose();
      disposeMaterial(grid.material);
      fineGrid.geometry.dispose();
      disposeMaterial(fineGrid.material);
      starGeometry.dispose();
      starMaterial.dispose();
      renderer.dispose();
      renderer.domElement.remove();
    };
  }, []);

  useEffect(() => {
    const sceneState = sceneRef.current;
    if (!sceneState) return;

    const { routeGroup, markerGroup, telemetryGroup, geofenceGroup, cameraMarkerGroup, camera } = sceneState;
    clearGroup(routeGroup);
    clearGroup(markerGroup);
    clearGroup(telemetryGroup);

    const origin = chooseOrigin(path);
    const projected = path.map((location) => projectLocation(location, origin));
    const projectedLatest = projected[projected.length - 1] || null;

    clearGroup(geofenceGroup);
    geofences.forEach((fence) => {
      if (fence.coords && fence.coords.length >= 3) {
        const colors = [0x40d7ff, 0x29e06b, 0xf2d96b, 0xe04040, 0x9b59b6];
        const idx = geofences.indexOf(fence) % colors.length;
        const poly = buildGeofencePolygon(fence.coords, origin, colors[idx], 0.7);
        if (poly) {
          geofenceGroup.add(poly);
        }
      }
    });

    clearGroup(cameraMarkerGroup);
    cameras.forEach((cam) => {
      const camLat = cam.latitude || cam.lat;
      const camLng = cam.longitude || cam.lng || cam.lon;
      if (camLat && camLng) {
        const projectedCam = projectLocation({ latitude: camLat, longitude: camLng, altitude: 0, speed: 0, heading: 0 }, origin);
        const marker = buildCameraMarker(projectedCam, origin);
        cameraMarkerGroup.add(marker);
      }
    });

    const focus = cameraTarget(projected, [geofenceGroup]);
    focusRef.current = focus;
    latestRef.current = projectedLatest;

    if (projected.length >= 2) {
      for (let i = 1; i < projected.length; i++) {
        const p0 = projected[i - 1];
        const p1 = projected[i];
        const segColor = speedToColor(p1.speed);
        const segPoints = [
          new THREE.Vector3(p0.x, p0.y + 0.6, p0.z),
          new THREE.Vector3(p1.x, p1.y + 0.6, p1.z),
        ];
        const segGeo = new THREE.BufferGeometry().setFromPoints(segPoints);
        const segMat = new THREE.LineBasicMaterial({ color: segColor, transparent: true, opacity: 0.88 });
        routeGroup.add(new THREE.Line(segGeo, segMat));

        const glowMat = new THREE.LineBasicMaterial({ color: segColor, transparent: true, opacity: 0.22 });
        const glowGeo = new THREE.BufferGeometry().setFromPoints(segPoints);
        const glow = new THREE.Line(glowGeo, glowMat);
        glow.scale.set(1.006, 1.006, 1.006);
        routeGroup.add(glow);
      }
    }

    projected.slice(-34).forEach((point, index, items) => {
      const intensity = (index + 1) / items.length;
      const breadcrumbColor = speedToColor(point.speed);
      const breadcrumbGeometry = new THREE.SphereGeometry(1.2 + intensity * 0.8, 14, 10);
      const breadcrumbMaterial = new THREE.MeshBasicMaterial({
        color: index === items.length - 1 ? 0xf2d96b : breadcrumbColor,
        transparent: true,
        opacity: 0.2 + intensity * 0.56,
      });
      const breadcrumb = new THREE.Mesh(breadcrumbGeometry, breadcrumbMaterial);
      breadcrumb.position.set(point.x, point.y + 0.8, point.z);
      routeGroup.add(breadcrumb);

      if (point.y > 5.5) {
        const columnHeight = point.y;
        const columnGeometry = new THREE.CylinderGeometry(0.28, 0.55, columnHeight, 8);
        const columnMaterial = new THREE.MeshBasicMaterial({
          color: breadcrumbColor,
          transparent: true,
          opacity: 0.08 + intensity * 0.2,
        });
        const column = new THREE.Mesh(columnGeometry, columnMaterial);
        column.position.set(point.x, columnHeight / 2, point.z);
        telemetryGroup.add(column);
      }
    });

    if (projectedLatest) {
      const accuracyRadius = Math.max(9, Math.min(80, (projectedLatest.accuracy ?? 35) / SCENE_UNIT_METERS + 12));
      const accuracyRing = buildRing(accuracyRadius, 0xf2d96b, 0.18);
      accuracyRing.position.set(projectedLatest.x, 0.42, projectedLatest.z);
      telemetryGroup.add(accuracyRing);

      const beacon = buildDeviceBeacon(projectedLatest, device?.device_type);
      markerGroup.add(beacon);
    }

    positionCamera(camera, modeRef.current, focus, projectedLatest);
  }, [device?.device_type, path, geofences, cameras]);

  const modeIcons = {
    follow: Navigation,
    orbit: RefreshCw,
    overview: Compass,
  };

  const coordinateLabel = latest ? `${latest.latitude.toFixed(5)},${latest.longitude.toFixed(5)}` : "WAITING_FOR_SIGNAL";
  const trailPoints = path.length;

  return (
    <section className="panel map-panel mission-panel">
      <div className="panel-title mission-title">
        <span>3D_MISSION_VIEW</span>
        <code>{coordinateLabel}</code>
        <div className="mission-controls">
          {CAMERA_MODES.map((mode) => {
            const Icon = modeIcons[mode];
            return (
              <button
                key={mode}
                className={`icon-button ${cameraMode === mode ? "is-active" : ""}`}
                onClick={() => setCameraMode(mode)}
                title={`Camera ${mode}`}
                type="button"
              >
                <Icon size={15} />
              </button>
            );
          })}
        </div>
      </div>
      <div className="mission-stage">
        <div ref={mountRef} className="mission-canvas" />
        {!latest && <div className="mission-empty">WAITING_FOR_SIGNAL</div>}
        <div className="mission-hud">
          <div>
            <span>SPD</span>
            <strong>{formatMetric(latest?.speed, " km/h")}</strong>
          </div>
          <div>
            <span>HDG</span>
            <strong>{formatMetric(latest?.heading, " deg")}</strong>
          </div>
          <div>
            <span>ALT</span>
            <strong>{formatMetric(latest?.altitude, " m")}</strong>
          </div>
          <div>
            <span>ACC</span>
            <strong>{formatMetric(latest?.accuracy, " m")}</strong>
          </div>
          <div>
            <span>SRC</span>
            <strong>{latest?.source || "--"}</strong>
          </div>
          <div>
            <span>TRAIL</span>
            <strong>{trailPoints.toString().padStart(3, "0")}</strong>
          </div>
          <div>
            <span>FENCE</span>
            <strong>{geofences.length}</strong>
          </div>
          <div>
            <span>CAM</span>
            <strong>{cameras.length}</strong>
          </div>
        </div>
        {geofences.length > 0 && (
          <div className="mission-legend">
            {geofences.map((f, i) => (
              <div key={f.geofence_id} className="legend-item">
                <span className="legend-color" style={{ background: ["#40d7ff", "#29e06b", "#f2d96b", "#e04040", "#9b59b6"][i % 5] }} />
                {f.name}
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}

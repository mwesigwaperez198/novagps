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

function cameraTarget(points) {
  if (!points.length) return { x: 0, y: 8, z: 0, radius: 120 };
  let minX = points[0].x;
  let maxX = points[0].x;
  let minZ = points[0].z;
  let maxZ = points[0].z;
  let maxY = points[0].y;
  points.forEach((point) => {
    minX = Math.min(minX, point.x);
    maxX = Math.max(maxX, point.x);
    minZ = Math.min(minZ, point.z);
    maxZ = Math.max(maxZ, point.z);
    maxY = Math.max(maxY, point.y);
  });
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
    if (!device?.id) return () => {
      active = false;
    };
    api.locations(device.id, 160)
      .then((items) => {
        if (active) setRouteHistory(items);
      })
      .catch(() => {
        if (active) setRouteHistory([]);
      });
    return () => {
      active = false;
    };
  }, [device?.id]);

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
    scene.add(routeGroup, markerGroup, telemetryGroup);

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
    sceneRef.current = { scene, camera, renderer, routeGroup, markerGroup, telemetryGroup, resize };
    positionCamera(camera, "follow", focusRef.current, null);
    animationRef.current = requestAnimationFrame(animate);

    return () => {
      window.removeEventListener("resize", resize);
      cancelAnimationFrame(animationRef.current);
      sceneRef.current = null;
      clearGroup(routeGroup);
      clearGroup(markerGroup);
      clearGroup(telemetryGroup);
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

    const { routeGroup, markerGroup, telemetryGroup, camera } = sceneState;
    clearGroup(routeGroup);
    clearGroup(markerGroup);
    clearGroup(telemetryGroup);

    const origin = chooseOrigin(path);
    const projected = path.map((location) => projectLocation(location, origin));
    const projectedLatest = projected[projected.length - 1] || null;
    const focus = cameraTarget(projected);
    focusRef.current = focus;
    latestRef.current = projectedLatest;

    if (projected.length >= 2) {
      const routePoints = projected.map((point) => new THREE.Vector3(point.x, point.y + 0.6, point.z));
      const routeGeometry = new THREE.BufferGeometry().setFromPoints(routePoints);
      const routeMaterial = new THREE.LineBasicMaterial({
        color: 0x40d7ff,
        transparent: true,
        opacity: 0.88,
      });
      routeGroup.add(new THREE.Line(routeGeometry, routeMaterial));

      const glowGeometry = new THREE.BufferGeometry().setFromPoints(routePoints);
      const glowMaterial = new THREE.LineBasicMaterial({
        color: 0x29e06b,
        transparent: true,
        opacity: 0.28,
      });
      const glow = new THREE.Line(glowGeometry, glowMaterial);
      glow.scale.set(1.006, 1.006, 1.006);
      routeGroup.add(glow);
    }

    projected.slice(-34).forEach((point, index, items) => {
      const intensity = (index + 1) / items.length;
      const breadcrumbGeometry = new THREE.SphereGeometry(1.2 + intensity * 0.8, 14, 10);
      const breadcrumbMaterial = new THREE.MeshBasicMaterial({
        color: index === items.length - 1 ? 0xf2d96b : 0x6fffb1,
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
          color: 0x40d7ff,
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
  }, [device?.device_type, path]);

  const modeIcons = {
    follow: Navigation,
    orbit: RefreshCw,
    overview: Compass,
  };

  const coordinateLabel = latest ? `${latest.latitude.toFixed(5)},${latest.longitude.toFixed(5)}` : "WAITING_FOR_SIGNAL";

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
            <strong>{path.length.toString().padStart(3, "0")}</strong>
          </div>
        </div>
      </div>
    </section>
  );
}

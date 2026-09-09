import { useEffect, useRef } from "react";

const DEG = Math.PI / 180;
const GRID_LON_STEP = 20;
const GRID_LAT_STEP = 20;
const TEXTURE_URL = "https://unpkg.com/three-globe/example/img/earth-blue-marble.jpg";

let earthTexture = null;
let earthTexturePromise = null;

function loadEarthTexture() {
  if (earthTexturePromise) return earthTexturePromise;
  earthTexturePromise = new Promise((resolve) => {
    const image = new Image();
    image.crossOrigin = "anonymous";
    image.src = TEXTURE_URL;
    image.onload = () => {
      earthTexture = image;
      resolve(image);
    };
    image.onerror = () => resolve(null);
  });
  return earthTexturePromise;
}

function asNumber(value) {
  const next = Number(value);
  return Number.isFinite(next) ? next : null;
}

function project(latDeg, lonDeg, azDeg, altDeg, radius) {
  const lat = latDeg * DEG;
  const lon = lonDeg * DEG;
  const az = azDeg * DEG;
  const alt = altDeg * DEG;
  const L = lon - az;
  const cosAlt = Math.cos(alt);
  const u = Math.cos(lat) * Math.sin(L);
  const v = cosAlt * Math.sin(lat) - Math.sin(alt) * Math.cos(lat) * Math.cos(L);
  const w = Math.sin(alt) * Math.sin(lat) + cosAlt * Math.cos(lat) * Math.cos(L);
  return { u: u * radius, v: v * radius, w };
}

function traceLine(ctx, points, projectFn, close = false, style) {
  let penDown = false;
  if (close) {
    points.push(points[0]);
  }
  for (let index = 0; index < points.length; index += 1) {
    const p = projectFn(points[index].lat, points[index].lon);
    const visible = p.w > 0.02;
    if (visible) {
      const screenX = ctx.width_cx + p.u;
      const screenY = ctx.height_cy - p.v;
      if (!penDown) {
        ctx.beginPath();
        ctx.moveTo(screenX, screenY);
        penDown = true;
      } else {
        ctx.lineTo(screenX, screenY);
      }
    } else {
      if (penDown) {
        ctx.strokeStyle = style;
        ctx.stroke();
        penDown = false;
      }
    }
  }
  if (penDown) {
    ctx.strokeStyle = style;
    ctx.stroke();
  }
}

function drawTexturedSphere(ctx, tex, cx, cy, R, az) {
  const texW = tex.naturalWidth || tex.width;
  const texH = tex.naturalHeight || tex.height;
  if (!texW || !texH) return false;
  const srcW = texW / 2;
  const frontLeftDeg = az - 90;
  let sx = ((frontLeftDeg + 180) / 360) * texW;
  const wrap = sx + srcW > texW;
  const sx2 = sx + srcW - texW;

  ctx.save();
  ctx.beginPath();
  ctx.arc(cx, cy, R, 0, Math.PI * 2);
  ctx.clip();

  const rows = Math.max(24, Math.round(R * 2));
  for (let index = 0; index <= rows; index += 1) {
    const y0 = -R + (index / rows) * R * 2;
    const lat = Math.asin(y0 / R);
    const cosLat = Math.max(0.0015, Math.cos(lat));
    const dstW = Math.max(1, R * 2 * cosLat);
    const dstX = cx - dstW / 2;
    const dstY = cy + y0;
    const latY = Math.max(0, Math.min(texH - 1, (0.5 + lat / 180) * texH));
    if (!wrap) {
      ctx.drawImage(tex, sx, latY, srcW, 1, dstX, dstY, dstW, 1);
    } else {
      const head = texW - sx;
      ctx.drawImage(tex, sx, latY, head, 1, dstX, dstY, (dstW * head) / srcW, 1);
      ctx.drawImage(tex, 0, latY, sx2, 1, dstX + (dstW * head) / srcW, dstY, (dstW * sx2) / srcW, 1);
    }
  }

  const light = ctx.createRadialGradient(cx - R * 0.5, cy - R * 0.45, R * 0.1, cx, cy, R);
  light.addColorStop(0, "rgba(255,255,255,0.16)");
  light.addColorStop(0.55, "rgba(0,0,0,0)");
  light.addColorStop(1, "rgba(2,12,8,0.62)");
  ctx.fillStyle = light;
  ctx.fillRect(cx - R, cy - R, R * 2, R * 2);
  ctx.restore();
  return true;
}

export default function GlobeView({ device, markers = [] }) {
  const canvasRef = useRef(null);
  const stateRef = useRef({
    az: -35,
    alt: 18,
    radius: 0,
    targetRadius: 0,
    spinning: true,
    dragging: false,
    lastX: 0,
    lastY: 0,
  });

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return undefined;
    const ctx = canvas.getContext("2d");
    const state = stateRef.current;
    const texBridge = { texture: null };
    loadEarthTexture().then((texture) => {
      texBridge.texture = texture;
    });
    let raf = 0;
    let width = 0;
    let height = 0;

    function resize() {
      const rect = canvas.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      width = rect.width;
      height = rect.height;
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      state.targetRadius = Math.min(width, height) * 0.36;
    }

    resize();
    const observer = new ResizeObserver(resize);
    observer.observe(canvas);

    const background = ctx.createRadialGradient(0, 0, 0, 0, 0, 640);

    function draw() {
      state.radius += (state.targetRadius - state.radius) * 0.08;
      if (state.spinning && !state.dragging) {
        state.az += 0.1;
      }
      const radius = state.radius;
      const az = state.az;
      const alt = state.alt;

      ctx.clearRect(0, 0, width, height);
      ctx.fillStyle = background;
      ctx.fillRect(0, 0, width, height);

      const cx = width / 2;
      const cy = height / 2;
      ctx.width_cx = cx;
      ctx.height_cy = cy;
      const R = radius;

      const projectFn = (lat, lon) => project(lat, lon, az, alt, R);
      const glow = ctx.createRadialGradient(cx, cy, R * 0.85, cx, cy, R * 1.08);
      glow.addColorStop(0, "rgba(64,215,255,0.0)");
      glow.addColorStop(1, "rgba(64,215,255,0.12)");
      ctx.beginPath();
      ctx.arc(cx, cy, R * 1.06, 0, Math.PI * 2);
      ctx.fillStyle = glow;
      ctx.fill();

      const textured = texBridge.texture
        ? drawTexturedSphere(ctx, texBridge.texture, cx, cy, R, az)
        : false;

      if (!textured) {
        const ocean = ctx.createRadialGradient(cx - R * 0.3, cy - R * 0.35, R * 0.2, cx, cy, R);
        ocean.addColorStop(0, "#123a2a");
        ocean.addColorStop(0.65, "#0a1f16");
        ocean.addColorStop(1, "#04120c");
        ctx.beginPath();
        ctx.arc(cx, cy, R, 0, Math.PI * 2);
        ctx.fillStyle = ocean;
        ctx.fill();

        for (let lon = -180; lon < 180; lon += GRID_LON_STEP) {
          const line = [];
          for (let lat = -90; lat <= 90; lat += 5) line.push({ lat, lon });
          traceLine(ctx, line, projectFn, false, "rgba(64, 215, 255, 0.16)");
        }
        for (let lat = -90; lat <= 90; lat += GRID_LAT_STEP) {
          if (lat === 0 || Math.abs(lat) === 90) continue;
          const line = [];
          const segments = 72;
          for (let i = 0; i <= segments; i += 1) {
            line.push({ lat, lon: -180 + (360 * i) / segments });
          }
          traceLine(ctx, line, projectFn, false, "rgba(64, 215, 255, 0.16)");
        }
        const equator = [];
        for (let i = 0; i <= 72; i += 1) equator.push({ lat: 0, lon: -180 + (360 * i) / 72 });
        traceLine(ctx, equator, projectFn, false, "rgba(41, 224, 107, 0.28)");
      } else {
        const equator = [];
        for (let i = 0; i <= 72; i += 1) equator.push({ lat: 0, lon: -180 + (360 * i) / 72 });
        traceLine(ctx, equator, projectFn, false, "rgba(41, 224, 107, 0.14)");
      }

      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, Math.PI * 2);
      ctx.strokeStyle = "rgba(64, 215, 255, 0.5)";
      ctx.stroke();

      const live = (device && asNumber(device.latest_location?.latitude) !== null
        && asNumber(device.latest_location?.longitude) !== null)
        ? device.latest_location : null;

      if (live) {
        const lat = asNumber(live.latitude);
        const lon = asNumber(live.longitude);
        const p = projectFn(lat, lon);
        if (p.w > 0) {
          const x = cx + p.u;
          const y = cy - p.v;
          const color = live.speed ? "#29e06b" : "#40d7ff";
          const pulse = 0.75 + Math.sin(Date.now() / 420) * 0.18;
          ctx.beginPath();
          ctx.arc(x, y, 7 * pulse, 0, Math.PI * 2);
          ctx.fillStyle = `${color}55`;
          ctx.fill();
          ctx.beginPath();
          ctx.arc(x, y, 4, 0, Math.PI * 2);
          ctx.fillStyle = color;
          ctx.fill();
          ctx.shadowColor = color;
          ctx.shadowBlur = 12;
          ctx.fill();
          ctx.shadowBlur = 0;
          const label = device.name || device.identifier || "device";
          ctx.fillStyle = "#d7ffe0";
          ctx.font = "10px 'JetBrains Mono', monospace";
          ctx.fillText(label, x + 8, y + 3);
        }
      }

      markers
        .filter((marker) => asNumber(marker.latitude) !== null && asNumber(marker.longitude) !== null)
        .forEach((marker) => {
          const p = projectFn(asNumber(marker.latitude), asNumber(marker.longitude));
          if (p.w <= 0) return;
          const x = cx + p.u;
          const y = cy - p.v;
          ctx.save();
          ctx.translate(x, y);
          ctx.rotate(Date.now() / 900);
          ctx.fillStyle = "#e6d36c";
          ctx.fillRect(-3, -3, 6, 6);
          ctx.restore();
          ctx.fillStyle = "rgba(230, 211, 108, 0.8)";
          ctx.font = "9px 'JetBrains Mono', monospace";
          ctx.fillText(marker.label || marker.ip || "", x + 6, y - 4);
        });

      raf = requestAnimationFrame(draw);
    }

    function pointerDown(event) {
      state.dragging = true;
      state.spinning = false;
      state.lastX = event.clientX;
      state.lastY = event.clientY;
      canvas.setPointerCapture(event.pointerId);
    }

    function pointerMove(event) {
      if (!state.dragging) return;
      const dx = event.clientX - state.lastX;
      const dy = event.clientY - state.lastY;
      state.az -= dx * 0.35;
      state.alt = Math.max(-80, Math.min(80, state.alt + dy * 0.35));
      state.lastX = event.clientX;
      state.lastY = event.clientY;
    }

    function pointerUp(event) {
      state.dragging = false;
      if (canvas.hasPointerCapture(event.pointerId)) {
        canvas.releasePointerCapture(event.pointerId);
      }
    }

    function wheel(event) {
      event.preventDefault();
      state.targetRadius = Math.max(
        40,
        Math.min(Math.min(width, height) * 0.55, state.targetRadius * (event.deltaY > 0 ? 0.92 : 1.08)),
      );
    }

    canvas.addEventListener("pointerdown", pointerDown);
    canvas.addEventListener("pointermove", pointerMove);
    canvas.addEventListener("pointerup", pointerUp);
    canvas.addEventListener("pointercancel", pointerUp);
    canvas.addEventListener("wheel", wheel, { passive: false });
    raf = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(raf);
      observer.disconnect();
      canvas.removeEventListener("pointerdown", pointerDown);
      canvas.removeEventListener("pointermove", pointerMove);
      canvas.removeEventListener("pointerup", pointerUp);
      canvas.removeEventListener("pointercancel", pointerUp);
      canvas.removeEventListener("wheel", wheel);
    };
  }, [device, markers]);

  return <canvas ref={canvasRef} className="globe-canvas" />;
}
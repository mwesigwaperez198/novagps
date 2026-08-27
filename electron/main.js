const { app, BrowserWindow, shell, Tray, Menu, nativeImage } = require("electron");
const path = require("path");
const { spawn } = require("child_process");
const http = require("http");

const isDev = process.env.NOVA_DEV === "1";
const BACKEND_PORT = 8000;
const FRONTEND_PORT = 5173;
let mainWindow = null;
let tray = null;
let backendProcess = null;
let backendReady = false;

function getBackendBinary() {
  const platform = process.platform;
  const resourcesPath = app.isPackaged
    ? path.join(process.resourcesPath, "backend")
    : path.join(__dirname, "backend-bin");

  if (platform === "win32") {
    return path.join(resourcesPath, "nova-backend.exe");
  }
  return path.join(resourcesPath, "nova-backend");
}

function getFrontendURL() {
  if (isDev) {
    return `http://localhost:${FRONTEND_PORT}`;
  }
  if (app.isPackaged) {
    return `http://127.0.0.1:${BACKEND_PORT}`;
  }
  return `http://127.0.0.1:${BACKEND_PORT}`;
}

function startBackend() {
  const bin = getBackendBinary();
  const fs = require("fs");

  if (!fs.existsSync(bin)) {
    console.error(`[NOVA] Backend binary not found: ${bin}`);
    console.error("[NOVA] Run: python3 build_backend.py");
    return;
  }

  const dataDir = path.join(app.getPath("userData"), "data");
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }

  const env = {
    ...process.env,
    NOVA_MODE: "portable",
    ENVIRONMENT: "production",
    DATA_DIR: dataDir,
    DATABASE_URL: `sqlite:///${path.join(dataDir, "nova.sqlite3")}`,
    NOVA_AUTH_SECRET: require("crypto").randomBytes(32).toString("hex"),
    PORT: String(BACKEND_PORT),
  };

  console.log(`[NOVA] Starting backend: ${bin}`);
  backendProcess = spawn(bin, [], {
    env,
    stdio: ["ignore", "pipe", "pipe"],
    detached: false,
  });

  backendProcess.stdout?.on("data", (d) => {
    const msg = d.toString().trim();
    if (msg) console.log(`[backend] ${msg}`);
    if (msg.includes("Application startup complete")) {
      backendReady = true;
      loadFrontend();
    }
  });

  backendProcess.stderr?.on("data", (d) => {
    const msg = d.toString().trim();
    if (msg) console.error(`[backend] ${msg}`);
  });

  backendProcess.on("error", (err) => {
    console.error(`[NOVA] Backend failed to start: ${err.message}`);
  });

  backendProcess.on("exit", (code) => {
    console.log(`[NOVA] Backend exited with code ${code}`);
    backendProcess = null;
    backendReady = false;
  });
}

function waitForBackend(callback, attempts = 0) {
  if (attempts > 30) {
    console.error("[NOVA] Backend did not start in 30s, loading UI anyway");
    loadFrontend();
    return;
  }

  http
    .get(`http://127.0.0.1:${BACKEND_PORT}/health`, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        backendReady = true;
        callback();
      });
    })
    .on("error", () => {
      setTimeout(() => waitForBackend(callback, attempts + 1), 1000);
    });
}

function loadFrontend() {
  if (!mainWindow) return;
  const url = getFrontendURL();
  console.log(`[NOVA] Loading frontend: ${url}`);
  mainWindow.loadURL(url);
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1024,
    minHeight: 700,
    title: "NOVA GPS",
    icon: path.join(__dirname, "icon.png"),
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      nodeIntegration: false,
      contextIsolation: true,
    },
    show: false,
    backgroundColor: "#0a0a0f",
  });

  mainWindow.once("ready-to-show", () => {
    mainWindow.show();
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
  });

  mainWindow.on("close", (e) => {
    if (backendProcess) {
      e.preventDefault();
      mainWindow.hide();
    }
  });

  mainWindow.on("closed", () => {
    mainWindow = null;
  });

  if (isDev) {
    mainWindow.loadURL(`http://localhost:${FRONTEND_PORT}`);
  } else {
    mainWindow.loadURL("data:text/html," + encodeURIComponent(getSplashHTML()));
    startBackend();
    waitForBackend(loadFrontend);
  }
}

function createTray() {
  const iconPath = path.join(__dirname, "icon.png");
  let icon;
  try {
    icon = nativeImage.createFromPath(iconPath);
    if (icon.isEmpty()) throw new Error("empty");
  } catch {
    icon = nativeImage.createEmpty();
  }

  tray = new Tray(icon);
  tray.setToolTip("NOVA GPS");

  const contextMenu = Menu.buildFromTemplate([
    {
      label: "Open NOVA GPS",
      click: () => {
        if (mainWindow) {
          mainWindow.show();
          mainWindow.focus();
        }
      },
    },
    { type: "separator" },
    {
      label: "Restart Backend",
      click: () => {
        if (backendProcess) {
          backendProcess.kill();
          backendProcess = null;
          backendReady = false;
        }
        startBackend();
        waitForBackend(loadFrontend);
      },
    },
    { type: "separator" },
    {
      label: "Quit",
      click: () => {
        if (backendProcess) backendProcess.kill();
        app.quit();
      },
    },
  ]);

  tray.setContextMenu(contextMenu);
  tray.on("click", () => {
    if (mainWindow) {
      mainWindow.show();
      mainWindow.focus();
    }
  });
}

function getSplashHTML() {
  return `<!DOCTYPE html>
<html>
<head>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:#0a0a0f; color:#e0e0e0; font-family:'Segoe UI',system-ui,sans-serif;
         display:flex; align-items:center; justify-content:center; height:100vh; }
  .center { text-align:center; }
  .logo { font-size:48px; font-weight:800; letter-spacing:8px;
           background:linear-gradient(135deg,#00ff88,#00aaff); -webkit-background-clip:text;
           -webkit-text-fill-color:transparent; margin-bottom:20px; }
  .sub { font-size:14px; color:#666; letter-spacing:4px; text-transform:uppercase; margin-bottom:40px; }
  .spinner { width:40px; height:40px; border:3px solid #1a1a2e; border-top:3px solid #00ff88;
             border-radius:50%; animation:spin 1s linear infinite; margin:0 auto; }
  @keyframes spin { to { transform:rotate(360deg); } }
  .status { margin-top:20px; font-size:12px; color:#444; letter-spacing:2px; }
</style>
</head>
<body>
<div class="center">
  <div class="logo">NOVA GPS</div>
  <div class="sub">System Starting</div>
  <div class="spinner"></div>
  <div class="status">Initializing backend services...</div>
</div>
</body>
</html>`;
}

app.whenReady().then(() => {
  createWindow();
  createTray();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    if (backendProcess) backendProcess.kill();
    app.quit();
  }
});

app.on("before-quit", () => {
  if (backendProcess) {
    backendProcess.kill();
    backendProcess = null;
  }
});

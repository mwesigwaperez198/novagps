const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("novaDesktop", {
  platform: process.platform,
  isElectron: true,
  getVersion: () => ipcRenderer.invoke("get-version"),
  minimize: () => ipcRenderer.send("window-minimize"),
  maximize: () => ipcRenderer.send("window-maximize"),
  close: () => ipcRenderer.send("window-close"),
  restartBackend: () => ipcRenderer.send("restart-backend"),
  openExternal: (url) => ipcRenderer.send("open-external", url),
});

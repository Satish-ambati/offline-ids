import path from 'node:path';
import { BrowserWindow, app, dialog, session } from 'electron';
import { EngineConfig, startEngine, stopEngine } from './engine';
import { registerIpc } from './ipc/handlers';

let win: BrowserWindow | null = null;
const dev = !app.isPackaged && process.env.NODE_ENV === 'development';

if (!app.requestSingleInstanceLock()) app.quit();
app.on('second-instance', () => { if (win) { if (win.isMinimized()) win.restore(); win.focus(); } });

function createWindow(cfg: EngineConfig): void {
  win = new BrowserWindow({
    width: 1440, height: 900, minWidth: 1100, minHeight: 700, backgroundColor: '#060b18', title: 'Endpoint Security Center', show: false,
    autoHideMenuBar: true,
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  win.once('ready-to-show', () => win?.show());
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', (e, url) => { if (!url.startsWith('http://localhost:5173') && !url.startsWith('file://')) e.preventDefault(); });
  if (dev) win.loadURL('http://localhost:5173');
  else win.loadFile(path.join(__dirname, '..', 'dist', 'renderer', 'index.html'));
  win.on('closed', () => { win = null; });
  registerIpc(() => win, cfg);
}

app.whenReady().then(async () => {
  if (app.isPackaged) {   // strict CSP in production: only local scripts and the loopback engine
    session.defaultSession.webRequest.onHeadersReceived((d, cb) => cb({
      responseHeaders: { ...d.responseHeaders, 'Content-Security-Policy': [
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; "
        + "connect-src 'self' http://127.0.0.1:* ws://127.0.0.1:*; object-src 'none'; base-uri 'none'"] },
    }));
  }
  try {
    createWindow(await startEngine());
  } catch (err) {
    dialog.showErrorBox('Security engine failed to start',
      `${(err as Error).message}\n\nCheck that Python dependencies are installed (see README, "Python environment").`);
    app.quit();
  }
});

app.on('window-all-closed', () => app.quit());
app.on('before-quit', () => stopEngine());

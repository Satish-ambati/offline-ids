import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { BrowserWindow, Notification, app, dialog, ipcMain, shell } from 'electron';
import type { EngineConfig } from '../engine';

const SEVERITY_TITLE: Record<string, string> = {
  LOW: 'Informational Event', MEDIUM: 'Suspicious Activity', HIGH: 'High-Risk Activity', CRITICAL: 'Critical Security Incident',
};

export function registerIpc(getWindow: () => BrowserWindow | null, cfg: EngineConfig): void {
  ipcMain.handle('ids:get-config', () => cfg);

  ipcMain.on('ids:notify', (_e, p: { severity: string; body: string }) => {
    if (!Notification.isSupported()) return;
    const sev = String(p.severity || 'LOW').toUpperCase();
    const n = new Notification({ title: `${SEVERITY_TITLE[sev] ?? 'Security event'} — Endpoint Security Center`, body: String(p.body).slice(0, 240), silent: true });
    n.on('click', () => { const w = getWindow(); if (w) { if (w.isMinimized()) w.restore(); w.focus(); } });
    n.show();
  });

  ipcMain.handle('ids:pick-folder', async () => {
    const w = getWindow();
    const r = await (w ? dialog.showOpenDialog(w, { properties: ['openDirectory'] }) : dialog.showOpenDialog({ properties: ['openDirectory'] }));
    return r.canceled ? null : r.filePaths[0];
  });

  ipcMain.handle('ids:open-report', async (_e, name: string) => {
    const safe = path.basename(String(name));
    const res = await fetch(`${cfg.baseUrl}/api/reports/${encodeURIComponent(safe)}`, { headers: { 'X-Engine-Token': cfg.token } });
    if (!res.ok) throw new Error(`Report download failed (${res.status})`);
    const target = path.join(os.tmpdir(), safe);
    writeFileSync(target, Buffer.from(await res.arrayBuffer()));
    const err = await shell.openPath(target);
    if (err) throw new Error(err);
    return target;
  });

  // Elevation is optional and user-initiated: needed only for full packet capture and the Windows Security log.
  ipcMain.handle('ids:relaunch-admin', async () => {
    if (process.platform !== 'win32') return { ok: false, reason: 'Administrator relaunch is only available on Windows.' };
    const w = getWindow();
    const choice = await (w ? dialog.showMessageBox(w, msgOpts()) : dialog.showMessageBox(msgOpts()));
    if (choice.response !== 0) return { ok: false, reason: 'cancelled' };
    const exe = process.execPath.replace(/'/g, "''");
    const args = (app.isPackaged ? [] : [app.getAppPath()]).map((a) => `"${a}"`).join(' ').replace(/'/g, "''");
    const ps = args ? `Start-Process -FilePath '${exe}' -ArgumentList '${args}' -Verb RunAs` : `Start-Process -FilePath '${exe}' -Verb RunAs`;
    spawn('powershell', ['-NoProfile', '-Command', ps], { detached: true, windowsHide: true, stdio: 'ignore' }).unref();
    setTimeout(() => app.quit(), 400);
    return { ok: true };
  });
}

function msgOpts(): Electron.MessageBoxOptions {
  return {
    type: 'question', buttons: ['Restart as administrator', 'Cancel'], defaultId: 1, cancelId: 1, title: 'Administrator access',
    message: 'Restart with administrator rights?',
    detail: 'Administrator rights are needed only for two things: capturing packets through Npcap and reading the Windows Security event log '
      + '(logins and authentication failures). Without them the app keeps working with reduced visibility. '
      + 'The app never disables antivirus or the firewall, never bypasses Windows protections and never collects passwords.',
  };
}

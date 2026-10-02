import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('ids', {
  getConfig: () => ipcRenderer.invoke('ids:get-config'),
  notify: (severity: string, body: string) => ipcRenderer.send('ids:notify', { severity, body }),
  pickFolder: (): Promise<string | null> => ipcRenderer.invoke('ids:pick-folder'),
  openReport: (name: string) => ipcRenderer.invoke('ids:open-report', name),
  relaunchAdmin: (): Promise<{ ok: boolean; reason?: string }> => ipcRenderer.invoke('ids:relaunch-admin'),
});

import type { EngineConfig } from '../types';

let cfg: EngineConfig | null = null;

export async function loadConfig(): Promise<EngineConfig> {
  if (cfg) return cfg;
  if (window.ids) cfg = await window.ids.getConfig();
  else {   // plain-browser development: run `python main.py --port 8765` without IDS_TOKEN
    const port = new URLSearchParams(location.search).get('port') || '8765';
    cfg = { baseUrl: `http://127.0.0.1:${port}`, wsUrl: `ws://127.0.0.1:${port}/ws`, token: '', dev: true };
  }
  return cfg;
}

export async function api<T = unknown>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<T> {
  const c = await loadConfig();
  const headers: Record<string, string> = { 'X-Engine-Token': c.token, ...(init.headers as Record<string, string>) };
  let body = init.body;
  if (init.json !== undefined) { body = JSON.stringify(init.json); headers['Content-Type'] = 'application/json'; }
  const res = await fetch(`${c.baseUrl}${path}`, { ...init, headers, body });
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).detail ?? msg; } catch { /* ignore */ }
    throw new Error(String(msg));
  }
  return res.json() as Promise<T>;
}

export const qs = (o: Record<string, string | number | undefined | null>) => {
  const p = new URLSearchParams();
  Object.entries(o).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '') p.set(k, String(v)); });
  const s = p.toString();
  return s ? `?${s}` : '';
};

export async function openSocket(onMessage: (m: any) => void, onState: (up: boolean) => void): Promise<() => void> {
  const c = await loadConfig();
  let ws: WebSocket | null = null, closed = false, timer: number | undefined;
  const connect = () => {
    ws = new WebSocket(`${c.wsUrl}?token=${encodeURIComponent(c.token)}`);
    ws.onopen = () => onState(true);
    ws.onmessage = (e) => { try { onMessage(JSON.parse(e.data)); } catch { /* ignore malformed */ } };
    ws.onclose = () => { onState(false); if (!closed) timer = window.setTimeout(connect, 1500); };
  };
  connect();
  return () => { closed = true; window.clearTimeout(timer); ws?.close(); };
}

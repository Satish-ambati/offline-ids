import { createContext, useCallback, useContext, useEffect, useMemo, useReducer, useRef, type ReactNode } from 'react';
import { useEffectiveMotion, type Motion } from '../animations/motion';
import type { Alert, Incident, Metric, RiskState, Row, Settings, Stats, Status } from '../types';
import { api, openSocket, qs, resetConfig } from './api';
import { sevRank } from './format';
import { beep } from './sound';

export type Tables = 'process_events' | 'host_events' | 'file_events' | 'network_events' | 'service_events';
const TABLES: Tables[] = ['process_events', 'host_events', 'file_events', 'network_events', 'service_events'];
const MAX_ALERTS = 500, MAX_ROWS = 300;

/** Newest first, deduplicated: a live frame and its stored row differ only by the database id. */
function mergeAlerts(live: Alert[], stored: Alert[]): Alert[] {
  const seen = new Set<number>();
  const out: Alert[] = [];
  for (const a of [...live, ...stored]) {
    if (seen.has(a.id)) continue;
    seen.add(a.id);
    out.push(a);
  }
  return out.slice(0, MAX_ALERTS);
}

function mergeRows(live: Row[], stored: Row[]): Row[] {
  const seen = new Set<string>();
  const out: Row[] = [];
  for (const r of [...live, ...stored]) {
    const { id: _dbId, ...rest } = r;
    const k = JSON.stringify(rest);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(r);
  }
  return out.slice(0, MAX_ROWS);
}

export interface Toast { id: number; severity: Alert['severity']; title: string; body: string; }
interface State {
  up: boolean; status?: Status; stats?: Stats; settings?: Settings; risk: RiskState; alerts: Alert[];
  incidents: Record<string, Incident>; metrics: Metric[]; events: Record<Tables, Row[]>; toasts: Toast[];
}
type Action =
  | { t: 'up'; up: boolean } | { t: 'init'; p: Partial<State> } | { t: 'status'; status: Status; risk?: RiskState }
  | { t: 'stats'; stats: Stats }
  | { t: 'settings'; settings: Settings } | { t: 'alert'; alert: Alert } | { t: 'alerts'; alerts: Alert[] }
  | { t: 'ack'; id: number }
  | { t: 'alerts-clear' }
  | { t: 'incident'; incident: Incident } | { t: 'incidents'; incidents: Incident[] }
  | { t: 'risk'; risk: RiskState; metric: Metric; system: Status['system'] } | { t: 'event'; table: Tables; rows: Row[] }
  | { t: 'toast'; toast: Toast } | { t: 'untoast'; id: number };

const empty: Record<Tables, Row[]> = { process_events: [], host_events: [], file_events: [], network_events: [], service_events: [] };
const init: State = { up: false, risk: { score: 0, level: 'LOW', components: {} }, alerts: [], incidents: {}, metrics: [], events: empty, toasts: [] };

function reducer(s: State, a: Action): State {
  switch (a.t) {
    case 'up': return { ...s, up: a.up };
    // the snapshot is merged, never assigned: rows that arrived over the socket while it was loading are newer
    case 'init': return {
      ...s, ...a.p,
      alerts: a.p.alerts ? mergeAlerts(s.alerts, a.p.alerts) : s.alerts,
      events: a.p.events ? Object.fromEntries(TABLES.map((t) => [t, mergeRows(s.events[t], a.p.events![t] ?? [])])) as Record<Tables, Row[]> : s.events,
      incidents: a.p.incidents ? { ...a.p.incidents, ...s.incidents } : s.incidents,
    };
    case 'status': return { ...s, status: a.status, risk: a.risk ?? a.status.risk ?? s.risk };
    case 'stats': return { ...s, stats: a.stats };
    case 'settings': return { ...s, settings: a.settings };
    case 'alert': return { ...s, alerts: mergeAlerts([a.alert], s.alerts) };
    case 'alerts': return { ...s, alerts: mergeAlerts(s.alerts, a.alerts) };
    case 'ack': return { ...s, alerts: s.alerts.map((x) => (x.id === a.id ? { ...x, acknowledged: 1 } : x)) };
    case 'alerts-clear': return { ...s, alerts: [] };
    case 'incident': return { ...s, incidents: { ...s.incidents, [a.incident.id]: a.incident } };
    case 'incidents': return { ...s, incidents: { ...Object.fromEntries(a.incidents.map((i) => [i.id, i])), ...s.incidents } };
    case 'risk': return {
      ...s, risk: a.risk, metrics: [...s.metrics, a.metric].slice(-120),
      status: s.status ? { ...s.status, system: a.system, last_scan: a.metric.ts, risk: a.risk } : s.status,
    };
    case 'event': return { ...s, events: { ...s.events, [a.table]: [...a.rows, ...s.events[a.table]].slice(0, MAX_ROWS) } };
    case 'toast': return { ...s, toasts: [a.toast, ...s.toasts].slice(0, 4) };
    case 'untoast': return { ...s, toasts: s.toasts.filter((x) => x.id !== a.id) };
  }
}

interface Ctx extends State {
  motion: Motion; toggleProtection(): Promise<void>; saveSettings(patch: Partial<Settings> | Record<string, unknown>): Promise<void>;
  ack(id: number): Promise<void>; dismiss(id: number): void; refresh(): Promise<void>; toggleDemo(): Promise<void>; error?: string;
  clearAlerts(): Promise<number>;
}
const C = createContext<Ctx>(null as unknown as Ctx);
export const useStore = () => useContext(C);

let toastId = 1;

export function StoreProvider({ children }: { children: ReactNode }) {
  const [s, d] = useReducer(reducer, init);
  const settingsRef = useRef<Settings | undefined>();
  settingsRef.current = s.settings;
  const [error, setError] = useReducer((_: string | undefined, e: string | undefined) => e, undefined);

  const refresh = useCallback(async () => {
    try {
      const [status, st, settings, alerts, incs] = await Promise.all([
        api<Status>('/api/status'), api<{ stats: Stats }>('/api/stats'), api<Settings>('/api/settings'),
        api<Alert[]>(`/api/events/alerts${qs({ limit: 300 })}`), api<Incident[]>(`/api/events/incidents${qs({ limit: 200 })}`),
      ]);
      const ev = await Promise.all(TABLES.map((t) => api<Row[]>(`/api/events/${t}${qs({ limit: 150 })}`)));
      const events = Object.fromEntries(TABLES.map((t, i) => [t, ev[i]])) as Record<Tables, Row[]>;
      d({ t: 'init', p: { status, stats: st.stats, settings, alerts, events, incidents: Object.fromEntries(incs.map((i) => [i.id, i])) } });
      setError(undefined);
    } catch (e) { setError((e as Error).message); }
  }, []);

  useEffect(() => {
    let close: (() => void) | undefined, dead = false, retry: number | undefined;
    refresh();
    const connect = () => {
      openSocket((m) => {
        switch (m.type) {
          // hello repeats the alert backlog so anything raised while the socket was down is not lost
          case 'hello': d({ t: 'status', status: m.status, risk: m.risk }); d({ t: 'stats', stats: m.stats });
            d({ t: 'alerts', alerts: m.alerts }); d({ t: 'incidents', incidents: m.incidents }); break;
          case 'status': d({ t: 'status', status: m.status }); break;
          case 'stats': d({ t: 'stats', stats: m.stats }); break;
          case 'risk': d({ t: 'risk', risk: m.risk, metric: m.metrics, system: m.system }); break;
          case 'incident': d({ t: 'incident', incident: m.incident }); break;
          case 'event': if (TABLES.includes(m.table as Tables)) d({ t: 'event', table: m.table as Tables, rows: [m.row] }); break;
          case 'flows': d({ t: 'event', table: 'network_events', rows: m.flows }); break;
          case 'alert': {
            const a = m.alert;
            d({ t: 'alert', alert: a });
            const cfg = settingsRef.current;
            const id = toastId++;
            d({ t: 'toast', toast: { id, severity: a.severity, title: a.category, body: a.description } });
            window.setTimeout(() => d({ t: 'untoast', id }), a.severity === 'CRITICAL' ? 12000 : 6000);
            if (cfg?.notifications !== false && sevRank(a.severity) >= 1) window.ids?.notify(a.severity, `${a.category}: ${a.description}`);
            if (cfg?.sound && sevRank(a.severity) >= 1) beep(a.severity);
            break;
          }
        }
      }, (up) => d({ t: 'up', up }))
        .then((c) => { if (dead) c(); else close = c; })
        // a failed getConfig must not leave a permanently dead UI: clear the cache and try again
        .catch((e) => { setError((e as Error).message); resetConfig(); if (!dead) retry = window.setTimeout(connect, 3000); });
    };
    connect();
    return () => { dead = true; window.clearTimeout(retry); close?.(); };
  }, [refresh]);

  const motion = useEffectiveMotion(s.settings?.animations ?? 'full');
  useEffect(() => { document.documentElement.dataset.motion = motion; }, [motion]);

  const value = useMemo<Ctx>(() => ({
    ...s, motion, error,
    async toggleProtection() {
      const st = await api<Status>(s.status?.running ? '/api/protection/stop' : '/api/protection/start', { method: 'POST' });
      d({ t: 'status', status: st });
    },
    async saveSettings(patch) {
      d({ t: 'settings', settings: await api<Settings>('/api/settings', { method: 'PUT', json: patch }) });
    },
    async ack(id) { await api(`/api/alerts/${id}/ack`, { method: 'POST' }); d({ t: 'ack', id }); await refresh(); },
    async clearAlerts() {
      const r = await api<{ removed: number }>('/api/alerts/clear', { method: 'POST' });
      d({ t: 'alerts-clear' });
      await refresh();
      return r.removed;
    },
    dismiss: (id) => d({ t: 'untoast', id }),
    refresh,
    async toggleDemo() {
      await api(s.status?.demo ? '/api/demo/stop' : '/api/demo/start', { method: 'POST' });
      d({ t: 'status', status: await api<Status>('/api/status') });
      await refresh();
    },
  }), [s, motion, error, refresh]);

  return <C.Provider value={value}>{children}</C.Provider>;
}

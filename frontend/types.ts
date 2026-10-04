export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export const SEVERITIES: Severity[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

export interface Alert {
  id: number; ts: number; severity: Severity; category: string; source: string | null; description: string;
  risk_score: number; incident_id: string | null; acknowledged: number; details: unknown; is_demo: number;
}
export interface TimelineEntry { ts: number; kind: string; severity: string; message: string; association: string; }
export interface Incident {
  id: string; opened_ts: number; updated_ts: number; severity: Severity; category: string; title: string; risk_score: number;
  status: string; reason: string; is_demo: number; key?: string;
  summary: { pid?: number; process?: string; exe?: string; user?: string; source?: string; destination?: string; files?: string[] } | string | null;
  timeline: TimelineEntry[] | string | null; components?: Record<string, number>;
}
export interface ModuleState { state: 'running' | 'stopped' | 'unavailable' | 'limited'; detail: string; }
export interface Status {
  running: boolean; started_at: number | null; last_scan: number | null; admin: boolean; platform: string;
  modules: Record<string, ModuleState>; demo: boolean; risk: RiskState; ml: Record<string, unknown>;
  fim: { state: string; files: number }; system: { cpu: number; mem: number; latency_ms: number }; notice: string;
}
export interface RiskState { score: number; level: Severity; components: Record<string, number>; }
export interface Stats {
  total_events: number; suspicious_events: number; active_threats: number; critical_alerts: number;
  network_connections: number; running_processes: number;
}
export interface Metric { ts: number; pps: number; bps: number; cps: number; }
export interface Settings {
  animations: 'full' | 'reduced' | 'off'; sound: boolean; notifications: boolean; interface: string; tick_seconds: number;
  autostart_protection: boolean; retention_days: number; fim_excluded_ext: string[]; fim_max_file_mb: number;
  thresholds: Record<string, number>;
  risk: { weights: Record<string, number>; correlation_bonus: number; levels: Record<string, number>; correlation_window: number; incident_min_kinds: number; incident_ttl: number };
  ml: { enabled: boolean; min_train_windows: number; persist_windows: number; rf_threshold: number };
}
export interface EngineConfig { baseUrl: string; wsUrl: string; token: string; dev: boolean; }

/** Every frame the engine pushes. Keeps store.tsx's switch exhaustive so a contract break fails typecheck. */
export type SocketMessage =
  | { type: 'hello'; status: Status; stats: Stats; risk: RiskState; alerts: Alert[]; incidents: Incident[] }
  | { type: 'status'; status: Status }
  | { type: 'stats'; stats: Stats }
  | { type: 'risk'; risk: RiskState; metrics: Metric; system: Status['system'] }
  | { type: 'incident'; incident: Incident }
  | { type: 'event'; table: string; row: Row }
  | { type: 'flows'; flows: Row[] }
  | { type: 'alert'; alert: Alert };

export type Row = Record<string, any>;

const SOCKET_TYPES = ['hello', 'status', 'stats', 'risk', 'incident', 'event', 'flows', 'alert'] as const;

/** Narrows an untrusted parsed frame; an unknown or malformed frame is dropped rather than reaching the store. */
export function isSocketMessage(m: unknown): m is SocketMessage {
  if (typeof m !== 'object' || m === null) return false;
  const t = (m as { type?: unknown }).type;
  return typeof t === 'string' && (SOCKET_TYPES as readonly string[]).includes(t);
}

declare global {
  interface Window {
    ids?: {
      getConfig(): Promise<EngineConfig>; notify(sev: string, body: string): void; pickFolder(): Promise<string | null>;
      openReport(name: string): Promise<string>; relaunchAdmin(): Promise<{ ok: boolean; reason?: string }>;
    };
  }
}

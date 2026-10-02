import type { MapNode } from '../charts/AttackMap';
import type { Alert, Incident, Severity, Status } from '../types';
import { fmtTime, parse, sevRank } from './format';
import type { Tables } from './store';

type Row = Record<string, any>;
const maxSev = (a?: Severity, b?: Severity): Severity | undefined => (!a ? b : !b ? a : sevRank(a) >= sevRank(b) ? a : b);

/** Builds the attack-map nodes purely from data the engine has reported. Nothing is invented. */
export function buildNodes(status: Status | undefined, alerts: Alert[], events: Record<Tables, Row[]>, incidents: Record<string, Incident>): MapNode[] {
  const now = Date.now() / 1000, recent = (t: number) => now - t < 1800;
  const nodes = new Map<string, MapNode>();
  const add = (n: MapNode) => { const p = nodes.get(n.id); if (p) { p.severity = maxSev(p.severity, n.severity); Object.assign(p.detail, n.detail); } else nodes.set(n.id, n); };

  add({ id: 'internet', kind: 'internet', label: 'Internet / LAN', detail: { Role: 'External network reachable from this PC' } });
  const m = status?.modules ?? {};
  add({ id: 'mon-net', kind: 'monitor', label: 'Network Monitor', state: m.network?.state, detail: { State: m.network?.state ?? 'stopped', Info: m.network?.detail || 'Npcap + Scapy packet capture' } });
  add({ id: 'mon-host', kind: 'monitor', label: 'Host Monitor', state: m.eventlog?.state, detail: { State: m.eventlog?.state ?? 'stopped', Info: m.eventlog?.detail || 'Windows event log + services' } });
  add({ id: 'mon-proc', kind: 'monitor', label: 'Process Monitor', state: m.process?.state, detail: { State: m.process?.state ?? 'stopped', Info: m.process?.detail || 'Process creation and parent-child tracking' } });

  for (const a of alerts.filter((x) => recent(x.ts)).slice(0, 80)) {
    if (a.source && /^[0-9a-f:.]+$/i.test(a.source) && a.source !== 'local') add({ id: `src-${a.source}`, kind: 'source', label: a.source, severity: a.severity, detail: { Address: a.source, Latest: a.category, When: fmtTime(a.ts) } });
  }
  const seenIp = new Set<string>();
  for (const f of events.network_events.filter((x) => x.direction === 'in').slice(0, 60)) {
    const ip = f.src_ip; if (!ip || ip === 'local' || seenIp.has(ip) || seenIp.size >= 4) continue; seenIp.add(ip);
    add({ id: `src-${ip}`, kind: 'source', label: ip, severity: 'LOW', detail: { Address: ip, Protocol: f.protocol, 'Local port': String(f.dst_port) } });
  }
  for (const p of events.process_events.filter((x) => x.action === 'created' && recent(x.ts)).slice(0, 60)) {
    const reasons = parse<string[]>(p.reasons, []);
    if (reasons.length) add({ id: `proc-${p.pid}`, kind: 'process', label: `${p.name} (${p.pid})`, severity: 'MEDIUM', detail: { Process: p.name, PID: String(p.pid), Path: p.exe, User: p.username, Why: reasons.join(' | ') } });
  }
  for (const i of Object.values(incidents).filter((x) => x.status === 'open')) {
    const s = parse<any>(i.summary, {});
    if (s?.pid) add({ id: `proc-${s.pid}`, kind: 'process', label: `${s.process ?? 'process'} (${s.pid})`, severity: i.severity, detail: { Incident: i.id, Risk: `${i.risk_score}/100` } });
  }
  events.file_events.filter((f) => recent(f.ts)).slice(0, 12).forEach((f, idx) => {
    if (idx < 4 || f.risk !== 'LOW') add({ id: `file-${f.path}`, kind: 'file', label: String(f.path).split(/[\\/]/).pop() ?? f.path, severity: f.risk, detail: { Path: f.path, Action: f.action, 'Hash status': f.hash_status, Risk: f.risk } });
  });
  events.service_events.filter((s) => recent(s.ts) && ['created', 'binary_changed'].includes(s.action)).slice(0, 3)
    .forEach((s) => add({ id: `svc-${s.name}`, kind: 'service', label: s.name, severity: 'MEDIUM', detail: { Service: s.display_name, Action: s.action, Binary: s.binary_path } }));
  const fails: Record<string, number> = {};
  events.host_events.filter((h) => h.event_type === 'logon_failure' && recent(h.ts)).forEach((h) => { fails[h.user || 'unknown'] = (fails[h.user || 'unknown'] ?? 0) + 1; });
  Object.entries(fails).slice(0, 3).forEach(([u, n]) => add({ id: `login-${u}`, kind: 'login', label: `${u} · ${n} failed`, severity: n >= 5 ? 'HIGH' : n >= 3 ? 'MEDIUM' : 'LOW', detail: { Account: u, 'Failed logons (30 min)': String(n) } }));
  return [...nodes.values()];
}

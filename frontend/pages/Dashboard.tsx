import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { AttackMap, type MapNode } from '../charts/AttackMap';
import { RiskGauge } from '../charts/RiskGauge';
import { TrafficChart } from '../charts/TrafficChart';
import { Shield3D } from '../components/Shield3D';
import { DemoBadge, Empty, Notice, Panel, SeverityBadge } from '../components/ui';
import { fmtTime, sevColor } from '../services/format';
import { buildNodes } from '../services/mapNodes';
import { useStore } from '../services/store';
import type { Stats } from '../types';

const CARDS: [keyof Stats, string, string][] = [
  ['total_events', 'Total events', '#56d4f5'], ['suspicious_events', 'Suspicious events', '#f2b441'], ['active_threats', 'Active threats', '#ff8a4c'],
  ['critical_alerts', 'Critical alerts', '#ff5468'], ['network_connections', 'Network connections', '#9c8cff'], ['running_processes', 'Running processes', '#4ade9a'],
];

export default function Dashboard() {
  const s = useStore();
  const [sel, setSel] = useState<MapNode | null>(null);
  const nodes = useMemo(() => buildNodes(s.status, s.alerts, s.events, s.incidents), [s.status, s.alerts, s.events, s.incidents]);
  const running = !!s.status?.running;
  const pps = s.metrics.at(-1)?.pps ?? 0;
  const levels = s.settings?.risk.levels ?? { medium: 30, high: 60, critical: 80 };
  const unavailable = Object.entries(s.status?.modules ?? {}).filter(([, m]) => m.state === 'unavailable' || m.state === 'limited');

  return (
    <div className="space-y-5">
      {s.status?.demo && <Notice>Demo mode is on. Events marked <DemoBadge /> are simulated and do not come from this PC. Turn it off in Settings.</Notice>}
      {running && unavailable.length > 0 && <Notice tone="warn">Reduced visibility: {unavailable.map(([n, m]) => `${n} — ${m.detail || m.state}`).join(' · ')}. See Settings to restart as administrator.</Notice>}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        {CARDS.map(([k, label, c]) => (
          <div key={k} className="panel relative overflow-hidden px-4 py-3">
            <span className="absolute inset-y-0 left-0 w-0.5" style={{ background: c }} />
            <div className="text-xs text-mute">{label}</div>
            <div className="font-display text-2xl font-bold" style={{ color: k === 'critical_alerts' && (s.stats?.[k] ?? 0) > 0 ? '#ff5468' : undefined }}>{s.stats ? s.stats[k].toLocaleString() : '—'}</div>
          </div>))}
      </div>

      <div className="grid gap-5 xl:grid-cols-[1fr_320px]">
        <Panel title="Live security map" right={<span className="text-[11px] text-mute">Packets are sampled from the measured traffic rate ({pps.toFixed(0)} pkt/s)</span>}>
          <div className="relative h-[470px]">
            <AttackMap nodes={nodes} pps={pps} live={running || !!s.status?.demo} level={s.risk.level} motion={s.motion} onSelect={setSel} selectedId={sel?.id} />
            {!running && !s.status?.demo && <div className="pointer-events-none absolute inset-x-0 bottom-3 text-center text-xs text-mute">Protection is stopped. Start protection to see live activity.</div>}
            {sel && (
              <div className="absolute right-3 top-3 w-64 rounded-md border border-line bg-panel/95 p-3 text-xs shadow-xl">
                <div className="mb-1 flex items-center justify-between"><b className="text-[13px]">{sel.label}</b><button onClick={() => setSel(null)} aria-label="Close details" className="text-mute hover:text-text">×</button></div>
                {sel.severity && sel.kind !== 'monitor' && <div className="mb-2"><SeverityBadge sev={sel.severity} /></div>}
                <dl className="space-y-1">{Object.entries(sel.detail).map(([k, v]) => <div key={k}><dt className="text-mute">{k}</dt><dd className="break-all">{v}</dd></div>)}</dl>
              </div>)}
          </div>
          <div className="flex flex-wrap gap-4 border-t border-line px-4 py-2 text-[11px] text-mute">
            <span><i className="mr-1 inline-block h-2 w-2 rounded-full bg-signal" />normal traffic</span>
            <span><i className="mr-1 inline-block h-2 w-2 rounded-full bg-alarm" />suspicious source</span>
            <span>◆ process · ▪ file · ● network / service / login</span><span>Click a node to inspect it</span>
          </div>
        </Panel>

        <div className="space-y-5">
          <Panel title="Risk level">
            <div className="flex flex-col items-center px-4 pb-4">
              <Shield3D level={s.risk.level} running={running} />
              <RiskGauge score={s.risk.score} level={s.risk.level} levels={levels} />
            </div>
          </Panel>
          <Panel title="Monitors">
            <ul className="px-4 pb-3 text-[13px]">
              {Object.entries(s.status?.modules ?? {}).map(([n, m]) => (
                <li key={n} className="flex items-center justify-between border-b border-line/40 py-1.5 last:border-0" title={m.detail}>
                  <span className="capitalize">{n}</span>
                  <span className="flex items-center gap-2 text-xs" style={{ color: m.state === 'running' ? '#4ade9a' : m.state === 'stopped' ? '#7f92b3' : '#f2b441' }}>
                    <i className="h-1.5 w-1.5 rounded-full" style={{ background: 'currentColor' }} />{m.state}</span>
                </li>))}
            </ul>
          </Panel>
        </div>
      </div>

      <div className="grid gap-5 xl:grid-cols-2">
        <Panel title="Network activity" right={<span className="text-[11px] text-mute"><i className="mr-1 inline-block h-0.5 w-3 bg-signal align-middle" />packets/s <i className="ml-3 mr-1 inline-block h-0.5 w-3 bg-violet align-middle" />new connections/s</span>}>
          <div className="px-2 pb-3">{s.metrics.length ? <TrafficChart data={s.metrics} animate={s.motion === 'full'} /> : <Empty>Traffic appears here once protection is running.</Empty>}</div>
        </Panel>
        <Panel title="Latest alerts" right={<Link className="text-xs text-signal hover:underline" to="/alerts">View all</Link>}>
          {s.alerts.length === 0 ? <Empty>No alerts. That only means nothing matched the rules yet; it is not proof that the PC is clean.</Empty> : (
            <ul>{s.alerts.slice(0, 7).map((a) => (
              <li key={a.id} className="row-in flex items-start gap-3 border-t border-line/50 px-4 py-2">
                <span className="mt-1 h-2 w-2 shrink-0 rounded-full" style={{ background: sevColor[a.severity] }} />
                <div className="min-w-0 flex-1"><div className="flex items-center gap-2 text-[13px] font-medium">{a.category}{a.is_demo ? <DemoBadge /> : null}</div>
                  <div className="truncate text-xs text-mute">{a.description}</div></div>
                <span className="font-mono text-[11px] text-mute">{fmtTime(a.ts)}</span>
              </li>))}</ul>)}
        </Panel>
      </div>
    </div>
  );
}

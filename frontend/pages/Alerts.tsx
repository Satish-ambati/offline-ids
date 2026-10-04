import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { FilterBar, noFilters, toQuery, type Filters } from '../components/FilterBar';
import { DemoBadge, Panel, SeverityBadge, Table } from '../components/ui';
import { api, qs } from '../services/api';
import { fmtDateTime, sevLabel } from '../services/format';
import { useStore } from '../services/store';
import type { Alert } from '../types';

export default function Alerts() {
  const s = useStore();
  const [f, setF] = useState<Filters>(noFilters);
  const [rows, setRows] = useState<Alert[]>([]);
  const [armed, setArmed] = useState(false);
  const [busy, setBusy] = useState(false);
  useEffect(() => { api<Alert[]>(`/api/events/alerts${qs({ ...toQuery(f), limit: 500 })}`).then(setRows).catch(() => undefined); }, [f, s.alerts.length, s.alerts[0]?.acknowledged]);
  // the first click only arms the button; it disarms itself so a stray later click cannot delete anything
  useEffect(() => { if (!armed) return; const t = window.setTimeout(() => setArmed(false), 5000); return () => window.clearTimeout(t); }, [armed]);
  const clear = async () => {
    if (!armed) { setArmed(true); return; }
    setBusy(true);
    try { await s.clearAlerts(); } finally { setArmed(false); setBusy(false); }
  };
  return (
    <Panel title="Alerts" right={
      <button className={armed ? 'btn btn-danger' : 'btn'} disabled={busy || !s.alerts.length} onClick={clear}
        title="Delete every stored alert. Incidents and the other event history are kept.">
        {busy ? 'Clearing…' : armed ? 'Click again to confirm' : `Clear all${s.alerts.length ? ` (${s.alerts.length})` : ''}`}
      </button>
    }>
      <FilterBar f={f} set={setF} show={['q', 'severity', 'category', 'source', 'since']} />
      <Table rows={rows} empty="No alerts match these filters." rowKey={(a) => a.id}
        cols={[{ h: 'Time', r: (a) => <span className="font-mono text-xs">{fmtDateTime(a.ts)}</span>, w: '160px' },
          { h: 'Severity', r: (a) => <div><SeverityBadge sev={a.severity} /><div className="mt-0.5 text-[10px] text-mute">{sevLabel[a.severity]}</div></div> },
          { h: 'Category', r: (a) => <span>{a.category} {a.is_demo ? <DemoBadge /> : null}</span> }, { h: 'Source', r: (a) => a.source ?? '—', cls: 'font-mono text-xs' },
          { h: 'Description', r: (a) => a.description, cls: 'max-w-[460px]' }, { h: 'Score', r: (a) => a.risk_score },
          { h: 'Incident', r: (a) => (a.incident_id ? <Link className="text-signal hover:underline" to={`/incidents/${a.incident_id}`}>{a.incident_id}</Link> : '—') },
          { h: '', r: (a) => (a.acknowledged ? <span className="text-xs text-mute">acknowledged</span> : <button className="btn" onClick={() => s.ack(a.id)}>Acknowledge</button>) }]} />
    </Panel>
  );
}

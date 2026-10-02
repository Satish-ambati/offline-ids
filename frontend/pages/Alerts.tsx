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
  useEffect(() => { api<Alert[]>(`/api/events/alerts${qs({ ...toQuery(f), limit: 500 })}`).then(setRows).catch(() => undefined); }, [f, s.alerts.length, s.alerts[0]?.acknowledged]);
  return (
    <Panel title="Alerts">
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

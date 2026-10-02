import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Timeline, tlFromIncident } from '../components/Timeline';
import { DemoBadge, Empty, Panel, SeverityBadge } from '../components/ui';
import { api } from '../services/api';
import { fmtDateTime, kindLabel, parse } from '../services/format';
import { useStore } from '../services/store';
import type { Incident } from '../types';

export default function IncidentTimeline() {
  const { id } = useParams();
  const nav = useNavigate();
  const s = useStore();
  const list = Object.values(s.incidents).sort((a, b) => b.updated_ts - a.updated_ts);
  const selId = id ?? list[0]?.id;
  const [detail, setDetail] = useState<(Incident & { related_alerts?: any[] }) | null>(null);
  useEffect(() => { if (selId) api<Incident>(`/api/incidents/${selId}`).then(setDetail).catch(() => setDetail(null)); else setDetail(null); }, [selId, s.incidents[selId ?? '']?.updated_ts]);
  const sum = parse<any>(detail?.summary, {});
  const tl = parse<any[]>(detail?.timeline, []);
  const row = (k: string, v?: string | number | null) => <div><dt className="text-xs text-mute">{k}</dt><dd className="break-all text-[13px]">{v ?? '—'}</dd></div>;
  return (
    <div className="grid gap-5 xl:grid-cols-[320px_1fr]">
      <Panel title="Incidents"><ul className="max-h-[70vh] overflow-auto">
        {list.length === 0 && <Empty>No correlated incidents. An incident opens when several independent signals (for example an unusual process, an external connection and file changes) line up.</Empty>}
        {list.map((i) => (
          <li key={i.id}><button onClick={() => nav(`/incidents/${i.id}`)} className={`w-full border-t border-line/50 px-4 py-3 text-left hover:bg-raise ${i.id === selId ? 'bg-raise' : ''}`}>
            <div className="mb-1 flex items-center justify-between"><span className="font-mono text-[11px] text-mute">{i.id}</span><SeverityBadge sev={i.severity} /></div>
            <div className="text-[13px] font-medium">{i.title}</div><div className="text-[11px] text-mute">{fmtDateTime(i.updated_ts)} · {i.status}</div></button></li>))}</ul></Panel>
      <Panel title="Investigation">
        {!detail ? <Empty>Select an incident to see how it developed.</Empty> : (
          <div className="space-y-5 px-4 pb-5">
            <div className="flex flex-wrap items-center gap-3"><h3 className="font-display text-lg font-semibold">{detail.title}</h3><SeverityBadge sev={detail.severity} />{detail.is_demo ? <DemoBadge /> : null}
              <span className="ml-auto text-sm">Risk score <b className="font-display text-xl">{detail.risk_score}</b>/100</span></div>
            <dl className="grid gap-3 md:grid-cols-3">
              {row('Incident ID', detail.id)}{row('Detection category', detail.category)}{row('Opened', fmtDateTime(detail.opened_ts))}
              {row('Source', sum.source)}{row('Destination', sum.destination)}{row('Process', sum.process ? `${sum.process} (PID ${sum.pid})` : null)}
              {row('User', sum.user)}{row('Executable', sum.exe)}{row('Status', detail.status)}
            </dl>
            <div><h4 className="mb-1 text-xs text-mute">Related files</h4>{sum.files?.length ? <ul className="font-mono text-xs">{sum.files.map((f: string) => <li key={f} className="break-all">{f}</li>)}</ul> : <p className="text-sm text-mute">None recorded.</p>}</div>
            <div><h4 className="mb-1 text-xs text-mute">Detection reason</h4><p className="text-[13px]">{detail.reason}</p>
              {detail.components && <p className="mt-1 text-xs text-mute">Score components: {Object.entries(detail.components).map(([k, v]) => `${kindLabel(k)} ${v}`).join(' · ')}</p>}
              <p className="mt-1 text-xs text-mute">"Time-linked" entries were associated by timing only; they may be unrelated to the process.</p></div>
            <div><h4 className="mb-2 text-xs text-mute">Timeline</h4><Timeline key={`${detail.id}-${tl.length}`} items={tlFromIncident(tl)} /></div>
            <div><h4 className="mb-1 text-xs text-mute">Related alerts</h4><ul className="space-y-1 text-[13px]">{(detail.related_alerts ?? []).map((a) => <li key={a.id}><SeverityBadge sev={a.severity} /> <span className="ml-2">{a.description}</span></li>)}
              {!(detail.related_alerts ?? []).length && <li className="text-mute">—</li>}</ul></div>
          </div>)}
      </Panel>
    </div>
  );
}

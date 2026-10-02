import { useEffect, useState } from 'react';
import { Panel, Table } from '../components/ui';
import { api } from '../services/api';
import { fmtTime, parse } from '../services/format';
import { useStore } from '../services/store';

interface P { pid: number; ppid: number; name: string; exe: string; user: string; parent_name: string; memory_mb: number; reasons: string[]; }

export default function ProcessMonitor() {
  const s = useStore();
  const [procs, setProcs] = useState<P[]>([]);
  const [q, setQ] = useState('');
  useEffect(() => {
    let alive = true;
    const load = () => api<P[]>('/api/live/processes').then((d) => alive && setProcs(d)).catch(() => undefined);
    load(); const t = setInterval(load, 5000);
    return () => { alive = false; clearInterval(t); };
  }, []);
  const f = procs.filter((p) => `${p.name} ${p.exe} ${p.user} ${p.pid}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <div className="space-y-5">
      <Panel title="Running processes" right={<input className="input" placeholder="Filter by name, path, user or PID" aria-label="Filter processes" value={q} onChange={(e) => setQ(e.target.value)} />}>
        <p className="px-4 pb-2 text-xs text-mute">A process is flagged only for behaviour (unusual location, unusual parent/child chain) — never because of its file name alone. Flagged rows are listed first.</p>
        <div className="max-h-[440px] overflow-auto"><Table rows={f.slice(0, 400)} rowKey={(p) => p.pid}
          cols={[{ h: 'PID', r: (p) => p.pid, cls: 'font-mono' }, { h: 'Name', r: (p) => p.name }, { h: 'Parent', r: (p) => `${p.parent_name || '—'} (${p.ppid})` }, { h: 'User', r: (p) => p.user || '—' },
            { h: 'MB', r: (p) => p.memory_mb }, { h: 'Path', r: (p) => p.exe || '—', cls: 'break-all text-xs font-mono' },
            { h: 'Behaviour', r: (p) => (p.reasons.length ? <span className="text-amber">{p.reasons.join(' | ')}</span> : <span className="text-mute">—</span>) }]} /></div>
      </Panel>
      <Panel title="Process creation & termination (live)">
        <div className="max-h-[360px] overflow-auto"><Table rows={s.events.process_events.slice(0, 120)} empty="Events appear once protection is running."
          cols={[{ h: 'Time', r: (e) => <span className="font-mono text-xs">{fmtTime(e.ts)}</span> }, { h: 'Event', r: (e) => e.action }, { h: 'Process', r: (e) => `${e.name} (${e.pid})` },
            { h: 'Parent', r: (e) => e.parent_name || `PID ${e.ppid}` }, { h: 'Path', r: (e) => e.exe || '—', cls: 'break-all text-xs font-mono' },
            { h: 'Flags', r: (e) => { const r = parse<string[]>(e.reasons, []); return r.length ? <span className="text-amber">{r.join(' | ')}</span> : '—'; } }]} /></div>
      </Panel>
    </div>
  );
}

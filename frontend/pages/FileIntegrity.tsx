import { useEffect, useState } from 'react';
import { FilterBar, noFilters, toQuery, type Filters } from '../components/FilterBar';
import { Notice, Panel, SeverityBadge } from '../components/ui';
import { api, qs } from '../services/api';
import { fmtTime } from '../services/format';
import { useStore } from '../services/store';

export default function FileIntegrity() {
  const s = useStore();
  const [folders, setFolders] = useState<string[]>([]);
  const [progress, setProgress] = useState<{ state: string; files: number }>();
  const [path, setPath] = useState('');
  const [err, setErr] = useState('');
  const [f, setF] = useState<Filters>(noFilters);
  const [rows, setRows] = useState<any[]>([]);
  const load = () => api<{ folders: string[]; progress: typeof progress }>('/api/fim/folders').then((d) => { setFolders(d.folders); setProgress(d.progress); });
  useEffect(() => { load(); const t = setInterval(load, 3000); return () => clearInterval(t); }, []);
  useEffect(() => { api<any[]>(`/api/events/file_events${qs({ ...toQuery(f), limit: 200 })}`).then(setRows).catch(() => undefined); }, [f, s.events.file_events.length]);
  const add = async (p: string) => { try { setErr(''); await api('/api/fim/folders', { method: 'POST', json: { path: p } }); setPath(''); load(); } catch (e) { setErr((e as Error).message); } };
  const pick = async () => { const p = await window.ids?.pickFolder(); if (p) add(p); };
  return (
    <div className="space-y-5">
      <Panel title="Protected folders" right={<button className="btn" onClick={() => api('/api/fim/rebuild', { method: 'POST' })}>Rebuild baselines</button>}>
        <div className="space-y-3 px-4 pb-4">
          <p className="text-xs text-mute">Pick the folders that matter. A SHA-256 baseline is built for each file; later changes are compared against it. Ordinary edits are low risk — only changes to executables and scripts are raised.</p>
          <div className="flex flex-wrap gap-2">
            {window.ids && <button className="btn btn-primary" onClick={pick}>Choose folder…</button>}
            <input className="input min-w-[280px] flex-1" placeholder={String.raw`Folder path, e.g. C:\Users\me\Documents`} aria-label="Folder path" value={path} onChange={(e) => setPath(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && path && add(path)} />
            <button className="btn" disabled={!path} onClick={() => add(path)}>Add folder</button>
          </div>
          {err && <Notice tone="warn">{err}</Notice>}
          {progress && progress.state === 'scanning' && <Notice>Building baseline… {progress.files} files hashed.</Notice>}
          {progress && progress.state === 'ready' && <div className="text-xs text-mute">Baseline ready · {progress.files} files hashed in last scan.</div>}
          <ul className="divide-y divide-line/50 text-sm">{folders.length === 0 && <li className="py-3 text-mute">No folders selected yet.</li>}
            {folders.map((d) => <li key={d} className="flex items-center justify-between py-1.5"><span className="break-all font-mono text-xs">{d}</span>
              <button className="btn" onClick={() => api(`/api/fim/folders${qs({ path: d })}`, { method: 'DELETE' }).then(load)}>Remove</button></li>)}</ul>
        </div>
      </Panel>
      <Panel title="File integrity events">
        <FilterBar f={f} set={setF} show={['q', 'severity', 'event_type', 'since']} />
        <div className="grid gap-3 px-4 pb-4 md:grid-cols-2">
          {rows.length === 0 && <p className="col-span-2 py-8 text-center text-sm text-mute">No integrity events match. Changes to files inside protected folders appear here while protection is running.</p>}
          {rows.slice(0, 60).map((e) => (
            <article key={e.id} className="row-in rounded-md border border-line bg-ink/50 p-3 font-mono text-xs leading-relaxed">
              <div className="mb-1 flex items-center justify-between font-sans"><b className="text-[11px] text-mute">FILE INTEGRITY EVENT</b><span className="flex gap-2">{e.is_demo ? <span className="text-violet">DEMO</span> : null}<SeverityBadge sev={e.risk} /></span></div>
              <div className="break-all"><span className="text-mute">File: </span>{String(e.path).split(/[\\/]/).pop()}</div>
              <div><span className="text-mute">Action: </span>{e.action}</div>
              <div><span className="text-mute">Hash Status: </span>{e.hash_status}</div>
              <div><span className="text-mute">Time: </span>{fmtTime(e.ts)}</div>
              <div className="break-all text-mute" title={e.path}>{e.path}</div>
              {e.new_hash && <div className="truncate text-mute" title={e.new_hash}>sha256 {e.new_hash}</div>}
            </article>))}
        </div>
      </Panel>
    </div>
  );
}

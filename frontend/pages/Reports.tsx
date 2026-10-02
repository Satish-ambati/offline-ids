import { useEffect, useState } from 'react';
import { Notice, Panel, Table, Toggle } from '../components/ui';
import { api } from '../services/api';
import { fmtDateTime } from '../services/format';

export default function Reports() {
  const [list, setList] = useState<{ name: string; size: number; ts: number }[]>([]);
  const [hours, setHours] = useState(24);
  const [demo, setDemo] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const load = () => api<typeof list>('/api/reports').then(setList);
  useEffect(() => { load(); }, []);
  const make = async () => { setBusy(true); setMsg(''); try { const r = await api<{ name: string }>('/api/reports', { method: 'POST', json: { hours, include_demo: demo } }); await load(); open(r.name); } catch (e) { setMsg((e as Error).message); } finally { setBusy(false); } };
  const open = async (name: string) => { try { await window.ids?.openReport(name); if (!window.ids) setMsg('Reports open from the desktop app. They are stored in the data folder shown in Settings.'); } catch (e) { setMsg((e as Error).message); } };
  return (
    <div className="space-y-5">
      <Panel title="Generate a PDF report">
        <div className="flex flex-wrap items-end gap-4 px-4 pb-4">
          <label className="text-xs text-mute">Period<select className="input ml-2" value={hours} onChange={(e) => setHours(Number(e.target.value))}><option value={1}>Last hour</option><option value={24}>Last 24 hours</option><option value={168}>Last 7 days</option><option value={720}>Last 30 days</option></select></label>
          <Toggle checked={demo} onChange={setDemo} label="Include DEMO/SIMULATION data" />
          <button className="btn btn-primary" disabled={busy} onClick={make}>{busy ? 'Generating…' : 'Generate report'}</button>
        </div>
        {msg && <div className="px-4 pb-4"><Notice tone="warn">{msg}</Notice></div>}
      </Panel>
      <Panel title="Saved reports"><Table rows={list} empty="No reports yet." cols={[{ h: 'File', r: (r) => r.name, cls: 'font-mono text-xs' }, { h: 'Created', r: (r) => fmtDateTime(r.ts) }, { h: 'Size', r: (r) => `${(r.size / 1024).toFixed(0)} KB` }, { h: '', r: (r) => <button className="btn" onClick={() => open(r.name)}>Open</button> }]} /></Panel>
    </div>
  );
}

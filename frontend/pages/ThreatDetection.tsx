import { useMemo, useState } from 'react';
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Field, Notice, Panel, Toggle } from '../components/ui';
import { api } from '../services/api';
import { kindLabel, sevColor } from '../services/format';
import { useStore } from '../services/store';
import { SEVERITIES } from '../types';

const RULES = [
  ['Port scan', 'Many distinct destination ports probed by one peer inside a short window (connection attempts only).'],
  ['Brute-force-like authentication', 'Repeated failed logons grouped by source and account; also success after many failures.'],
  ['SYN-flood-like activity', 'High inbound SYN volume with few completing ACKs.'],
  ['Abnormal traffic / DoS-like', 'Packets, bytes and connections per second vs a learned baseline. Escalated only when CPU, memory or responsiveness also degrade.'],
  ['Suspicious process', 'Unusual location or parent/child chain, then correlated with connections and file changes. Names alone are never enough.'],
  ['File integrity', 'SHA-256 changes; executables/scripts weigh more than documents.'],
];

export default function ThreatDetection() {
  const s = useStore();
  const [draft, setDraft] = useState<Record<string, number>>({});
  const [csv, setCsv] = useState('');
  const [msg, setMsg] = useState('');
  const st = s.settings;
  const bySev = useMemo(() => SEVERITIES.map((k) => ({ k, n: s.alerts.filter((a) => a.severity === k).length })), [s.alerts]);
  if (!st) return null;
  const val = (key: string, base: number) => draft[key] ?? base;
  const save = async () => {
    const th: Record<string, number> = {}, w: Record<string, number> = {};
    Object.entries(draft).forEach(([k, v]) => (k.startsWith('w:') ? (w[k.slice(2)] = v) : (th[k] = v)));
    await s.saveSettings({ thresholds: th, risk: { weights: w } }); setDraft({}); setMsg('Saved. New thresholds apply immediately.');
  };
  const num = (key: string, base: number) => <input type="number" step="any" className="input w-28" value={val(key, base)} onChange={(e) => setDraft({ ...draft, [key]: Number(e.target.value) })} />;
  return (
    <div className="space-y-5">
      <Notice>Detections describe observable behaviour. This app cannot detect every cyberattack, and ML output is a supporting signal, never proof.</Notice>
      <div className="grid gap-5 xl:grid-cols-[1.2fr_1fr]">
        <Panel title="Detection rules"><ul className="divide-y divide-line/50 px-4 pb-3">{RULES.map(([n, d]) => <li key={n} className="py-2.5"><div className="text-sm font-medium">{n}</div><div className="text-xs text-mute">{d}</div></li>)}</ul></Panel>
        <Panel title="Alerts by severity"><div className="h-[250px] px-2 pb-3"><ResponsiveContainer><BarChart data={bySev}><XAxis dataKey="k" stroke="#7f92b3" fontSize={11} /><YAxis stroke="#7f92b3" fontSize={11} allowDecimals={false} width={30} />
          <Tooltip contentStyle={{ background: '#0c1427', border: '1px solid #1b2a47', fontSize: 12 }} /><Bar dataKey="n" isAnimationActive={s.motion === 'full'} radius={[4, 4, 0, 0]}>{bySev.map((b) => <Cell key={b.k} fill={sevColor[b.k]} />)}</Bar></BarChart></ResponsiveContainer></div></Panel>
      </div>
      <Panel title="Thresholds and risk weights" right={<div className="flex items-center gap-3">{msg && <span className="text-xs text-mint">{msg}</span>}<button className="btn btn-primary" disabled={!Object.keys(draft).length} onClick={save}>Save changes</button></div>}>
        <div className="grid gap-6 px-4 pb-4 lg:grid-cols-2">
          <div><h3 className="mb-2 text-xs text-mute">Rule thresholds</h3><div className="grid grid-cols-2 gap-3">{Object.entries(st.thresholds).map(([k, v]) => <Field key={k} label={kindLabel(k)}>{num(k, v)}</Field>)}</div></div>
          <div><h3 className="mb-2 text-xs text-mute">Signal weights (application-defined; levels: LOW 0–{st.risk.levels.medium - 1}, MEDIUM {st.risk.levels.medium}–{st.risk.levels.high - 1}, HIGH {st.risk.levels.high}–{st.risk.levels.critical - 1}, CRITICAL {st.risk.levels.critical}–100)</h3>
            <div className="grid grid-cols-2 gap-3">{Object.entries(st.risk.weights).map(([k, v]) => <Field key={k} label={kindLabel(k)}>{num(`w:${k}`, v)}</Field>)}</div></div>
        </div>
      </Panel>
      <Panel title="Machine learning (local, scikit-learn)">
        <div className="space-y-4 px-4 pb-4 text-sm">
          <Toggle checked={st.ml.enabled} onChange={(v) => s.saveSettings({ ml: { enabled: v } })} label="Enable ML anomaly signal" />
          <dl className="grid gap-2 text-[13px] md:grid-cols-2">
            <div><dt className="text-xs text-mute">Isolation Forest (unsupervised)</dt><dd>{String(s.status?.ml?.isolation_forest ?? '—')}</dd></div>
            <div><dt className="text-xs text-mute">Random Forest (supervised)</dt><dd>{String(s.status?.ml?.random_forest ?? '—')}</dd></div></dl>
          <p className="text-xs text-mute">The Isolation Forest learns this PC's normal behaviour from its first {st.ml.min_train_windows} measurement windows, so start protection while the machine is behaving normally. Re-learn if the baseline was polluted.</p>
          <div className="flex flex-wrap items-center gap-2">
            <button className="btn" onClick={async () => { await api('/api/ml/relearn', { method: 'POST' }); setMsg('Baseline reset; learning restarted.'); s.refresh(); }}>Re-learn baseline</button>
            <input className="input min-w-[260px] flex-1" placeholder="Path to labelled CSV (feature columns + label 0/1)" aria-label="Labelled CSV path" value={csv} onChange={(e) => setCsv(e.target.value)} />
            <button className="btn" disabled={!csv} onClick={async () => { try { const r: any = await api('/api/ml/train', { method: 'POST', json: { csv_path: csv } }); setMsg(`Random Forest trained on ${r.rows} rows.`); s.refresh(); } catch (e) { setMsg((e as Error).message); } }}>Train Random Forest</button>
          </div>
        </div>
      </Panel>
    </div>
  );
}

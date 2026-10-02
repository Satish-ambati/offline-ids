import { SEVERITIES } from '../types';

export interface Filters { q: string; severity: string; category: string; source: string; process: string; event_type: string; since: string; }
export const noFilters: Filters = { q: '', severity: '', category: '', source: '', process: '', event_type: '', since: '' };

export function toQuery(f: Filters) {
  return { ...f, since: f.since ? new Date(f.since).getTime() / 1000 : undefined };
}

export function FilterBar({ f, set, show }: { f: Filters; set: (f: Filters) => void; show: (keyof Filters)[] }) {
  const u = (k: keyof Filters) => (e: { target: { value: string } }) => set({ ...f, [k]: e.target.value });
  return (
    <div className="flex flex-wrap items-end gap-2 px-4 pb-3">
      {show.includes('q') && <input className="input w-56" placeholder="Search text" aria-label="Search text" value={f.q} onChange={u('q')} />}
      {show.includes('severity') && <select className="input" aria-label="Severity" value={f.severity} onChange={u('severity')}><option value="">All severities</option>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}</select>}
      {show.includes('category') && <input className="input w-40" placeholder="Category" aria-label="Category" value={f.category} onChange={u('category')} />}
      {show.includes('source') && <input className="input w-36" placeholder="Source" aria-label="Source" value={f.source} onChange={u('source')} />}
      {show.includes('process') && <input className="input w-36" placeholder="Process" aria-label="Process" value={f.process} onChange={u('process')} />}
      {show.includes('event_type') && <input className="input w-36" placeholder="Event type" aria-label="Event type" value={f.event_type} onChange={u('event_type')} />}
      {show.includes('since') && <label className="text-xs text-mute">Since <input type="datetime-local" className="input ml-1" value={f.since} onChange={u('since')} /></label>}
      <button className="btn" onClick={() => set(noFilters)}>Clear</button>
    </div>
  );
}

import type { ReactNode } from 'react';
import type { Severity } from '../types';
import { sevColor } from '../services/format';

export const SeverityBadge = ({ sev }: { sev: string }) => {
  const c = sevColor[sev as Severity] ?? '#7f92b3';
  return <span className="inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 text-[11px] font-semibold" style={{ color: c, background: `${c}1f`, border: `1px solid ${c}55` }}>
    <svg width="8" height="8" viewBox="0 0 8 8"><circle cx="4" cy="4" r="4" fill={c} /></svg>{sev}</span>;
};

export const DemoBadge = () => <span className="rounded border border-violet/60 bg-violet/15 px-1.5 py-0.5 text-[10px] font-semibold text-violet">DEMO / SIMULATION</span>;

export const Panel = ({ title, right, children, className = '' }: { title?: ReactNode; right?: ReactNode; children: ReactNode; className?: string }) => (
  <section className={`panel ${className}`}>
    {(title || right) && <header className="flex items-center justify-between px-4 pt-3 pb-2"><h2 className="panel-title">{title}</h2>{right}</header>}
    {children}
  </section>
);

export const Empty = ({ children }: { children: ReactNode }) => <div className="px-4 py-8 text-center text-sm text-mute">{children}</div>;

export function Table<T>({ cols, rows, empty, onRow, rowKey }: {
  cols: { h: string; r: (row: T) => ReactNode; w?: string; cls?: string }[]; rows: T[]; empty?: string; onRow?: (r: T) => void; rowKey?: (r: T, i: number) => string | number;
}) {
  if (!rows.length) return <Empty>{empty ?? 'Nothing to show yet.'}</Empty>;
  return (
    <div className="overflow-auto">
      <table className="w-full border-collapse">
        <thead><tr>{cols.map((c) => <th key={c.h} className="th" style={{ width: c.w }}>{c.h}</th>)}</tr></thead>
        <tbody>{rows.map((r, i) => (
          <tr key={rowKey ? rowKey(r, i) : i} className={`row-in ${onRow ? 'cursor-pointer hover:bg-raise' : ''}`} onClick={() => onRow?.(r)}>
            {cols.map((c) => <td key={c.h} className={`td ${c.cls ?? ''}`}>{c.r(r)}</td>)}
          </tr>))}
        </tbody>
      </table>
    </div>
  );
}

export const Notice = ({ tone = 'info', children }: { tone?: 'info' | 'warn'; children: ReactNode }) => (
  <div className={`rounded-md border px-3 py-2 text-[13px] ${tone === 'warn' ? 'border-amber/50 bg-amber/10 text-amber' : 'border-signal/40 bg-signal/10 text-signal'}`}>{children}</div>
);

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return <label className="block"><span className="mb-1 block text-xs text-mute">{label}</span>{children}{hint && <span className="mt-1 block text-[11px] text-mute/80">{hint}</span>}</label>;
}

export function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button role="switch" aria-checked={checked} onClick={() => onChange(!checked)} className="flex items-center gap-3 text-sm">
      <span className={`relative h-5 w-9 rounded-full border transition-colors ${checked ? 'border-signal bg-signal/30' : 'border-line bg-ink'}`}>
        <span className={`absolute top-0.5 h-3.5 w-3.5 rounded-full transition-all ${checked ? 'left-[18px] bg-signal' : 'left-0.5 bg-mute'}`} />
      </span>{label}
    </button>
  );
}

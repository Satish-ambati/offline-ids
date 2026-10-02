import { fmtTime, kindLabel, sevColor } from '../services/format';
import type { Severity } from '../types';

export interface TLItem { ts: number; title: string; message: string; severity: string; tag?: string; }

export function Timeline({ items }: { items: TLItem[] }) {
  return (
    <ol className="relative ml-2 list-none pl-6">
      <span className="absolute left-[3px] top-1 bottom-1 w-px origin-top bg-line" style={{ animation: 'tl-grow .8s var(--ease) both' }} />
      {items.map((it, i) => {
        const c = sevColor[it.severity as Severity] ?? '#56d4f5';
        return (
          <li key={i} className="relative pb-4" style={{ animation: `tl-pop .35s var(--ease) both`, animationDelay: `${Math.min(i, 12) * 90}ms` }}>
            <span className="absolute -left-[27px] top-1 h-2.5 w-2.5 rounded-full" style={{ background: c, boxShadow: `0 0 10px ${c}` }} />
            <div className="flex items-baseline gap-3"><span className="font-mono text-xs text-mute">{fmtTime(it.ts)}</span>
              <span className="text-sm font-medium">{it.title}</span>
              {it.tag === 'temporal' && <span className="rounded border border-line px-1 text-[10px] text-mute" title="Linked by timing, not by a confirmed process ID">time-linked</span>}
            </div>
            <p className="mt-0.5 text-[13px] text-mute">{it.message}</p>
          </li>
        );
      })}
    </ol>
  );
}
export const tlFromIncident = (t: { ts: number; kind: string; severity: string; message: string; association: string }[]): TLItem[] =>
  t.map((x) => ({ ts: x.ts, title: kindLabel(x.kind), message: x.message, severity: x.severity, tag: x.association }));

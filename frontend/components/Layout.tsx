import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { fmtTime } from '../services/format';
import { useStore } from '../services/store';
import { DemoBadge } from './ui';
import { sevColor, sevLabel } from '../services/format';

const I: Record<string, string> = {
  dash: 'M3 3h7v9H3zM14 3h7v5h-7zM14 12h7v9h-7zM3 16h7v5H3z',
  net: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18',
  host: 'M4 5h16v11H4zM8 20h8M12 16v4',
  proc: 'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM17 14v6M14 17h6',
  file: 'M6 3h9l4 4v14H6zM14 3v5h5M9 13h7M9 17h7',
  threat: 'M12 3l9 16H3zM12 10v4M12 17v.5',
  inc: 'M4 6h16M4 12h10M4 18h6M18 12l3 3-3 3',
  alert: 'M6 17V11a6 6 0 1 1 12 0v6l2 2H4zM10 21h4',
  report: 'M5 3h14v18H5zM9 8h6M9 12h6M9 16h4',
  set: 'M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6zM19 12l2-1-1-3-2 .5-1.5-1.5.5-2-3-1-1 2h-2l-1-2-3 1 .5 2L6 8.5 4 8l-1 3 2 1v2l-2 1 1 3 2-.5L7.5 19l-.5 2 3 1 1-2h2l1 2 3-1-.5-2 1.5-1.5 2 .5 1-3-2-1z',
};
const NAV = [
  ['/', 'Dashboard', 'dash'], ['/network', 'Network Monitor', 'net'], ['/host', 'Host Monitor', 'host'], ['/process', 'Process Monitor', 'proc'],
  ['/files', 'File Integrity', 'file'], ['/threats', 'Threat Detection', 'threat'], ['/incidents', 'Incident Timeline', 'inc'],
  ['/alerts', 'Alerts', 'alert'], ['/reports', 'Security Reports', 'report'], ['/settings', 'Settings', 'set'],
] as const;

export const Icon = ({ n, size = 18 }: { n: string; size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d={I[n]} /></svg>
);

function Logo() {
  return (
    <svg width="30" height="34" viewBox="0 0 100 120" aria-hidden>
      <path d="M50 4 L92 20 V58 C92 88 72 108 50 116 C28 108 8 88 8 58 V20 Z" fill="#56d4f522" stroke="#56d4f5" strokeWidth="6" />
      <path d="M32 60 l13 13 25 -28" fill="none" stroke="#56d4f5" strokeWidth="9" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function Layout() {
  const s = useStore();
  const loc = useLocation();
  const running = !!s.status?.running;
  const sys = s.status?.system;
  const alertCount = s.alerts.filter((a) => !a.acknowledged && a.severity !== 'LOW').length;
  return (
    <div className="flex h-full">
      <aside className="flex w-56 shrink-0 flex-col border-r border-line bg-panel/80 py-4" aria-label="Primary">
        <div className="flex items-center gap-2.5 px-4 pb-5"><Logo /><div className="font-display text-[13px] font-bold leading-tight">Endpoint<br />Security Center</div></div>
        <nav className="flex-1 space-y-0.5 px-2">
          {NAV.map(([to, label, icon]) => (
            <NavLink key={to} to={to} end={to === '/'} className={({ isActive }) => `flex items-center gap-3 rounded-md px-3 py-2 text-[13px] transition-colors ${isActive ? 'bg-signal/12 text-signal' : 'text-mute hover:bg-raise hover:text-text'}`}>
              <Icon n={icon} /><span className="flex-1">{label}</span>
              {to === '/alerts' && alertCount > 0 && <span className="rounded-full bg-alarm/20 px-1.5 text-[10px] font-semibold text-alarm">{alertCount > 99 ? '99+' : alertCount}</span>}
            </NavLink>))}
        </nav>
        <p className="px-4 pt-3 text-[11px] leading-snug text-mute">All analysis and storage happen on this PC. No cloud services are used.</p>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex flex-wrap items-center gap-x-6 gap-y-2 border-b border-line bg-panel/60 px-6 py-3">
          <div className="flex items-center gap-3">
            <span className={`h-2.5 w-2.5 rounded-full ${running ? 'pulse bg-mint' : 'bg-mute'}`} style={{ ['--sev' as string]: '#4ade9a' }} />
            <div><div className="font-display text-sm font-semibold">{running ? 'Protection active' : s.up ? 'Protection stopped' : 'Engine not connected'}</div>
              <div className="text-[11px] text-mute">{running ? 'Monitoring this PC' : 'Start protection to begin monitoring'}</div></div>
          </div>
          <button className={`btn ${running ? 'btn-danger' : 'btn-primary'}`} onClick={s.toggleProtection} disabled={!s.up}>{running ? 'Stop protection' : 'Start protection'}</button>
          <div className="flex gap-5 text-xs text-mute">
            <span>System <b className="font-medium text-text">CPU {sys?.cpu?.toFixed(0) ?? '—'}% · RAM {sys?.mem?.toFixed(0) ?? '—'}%</b></span>
            <span>Last scan <b className="font-medium text-text">{fmtTime(s.status?.last_scan)}</b></span>
          </div>
          <div className="ml-auto flex items-center gap-3">
            {s.status?.demo && <DemoBadge />}
            {!s.status?.admin && s.status && <span className="text-[11px] text-amber" title="Packet capture and the Windows Security log need administrator rights. See Settings.">Limited visibility (not administrator)</span>}
          </div>
        </header>
        {s.error && <div className="border-b border-alarm/40 bg-alarm/10 px-6 py-2 text-[13px] text-alarm">Cannot reach the security engine: {s.error}</div>}
        <main className="min-h-0 flex-1 overflow-auto p-6"><div key={loc.pathname} className="page-in mx-auto max-w-[1500px]"><Outlet /></div></main>
      </div>
      <ToastHost />
    </div>
  );
}

function ToastHost() {
  const { toasts, dismiss } = useStore();
  return (
    <div className="pointer-events-none fixed right-4 top-4 z-50 flex w-80 flex-col gap-2" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} className="toast-in pointer-events-auto rounded-md border bg-panel p-3 shadow-xl" style={{ borderColor: `${sevColor[t.severity]}88`, boxShadow: `0 0 24px ${sevColor[t.severity]}33` }}>
          <div className="flex items-center justify-between"><span className="text-xs font-semibold" style={{ color: sevColor[t.severity] }}>{sevLabel[t.severity]}</span>
            <button className="text-mute hover:text-text" onClick={() => dismiss(t.id)} aria-label="Dismiss">×</button></div>
          <div className="mt-1 text-[13px] font-medium">{t.title}</div>
          <div className="mt-0.5 line-clamp-3 text-xs text-mute">{t.body}</div>
        </div>))}
    </div>
  );
}

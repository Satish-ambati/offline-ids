import { useEffect, useState } from 'react';
import { Notice, Panel, Table } from '../components/ui';
import { Timeline } from '../components/Timeline';
import { api } from '../services/api';
import { fmtTime } from '../services/format';
import { useStore } from '../services/store';

const SEV: Record<string, string> = { logon_failure: 'MEDIUM', audit_log_cleared: 'HIGH', service_installed: 'MEDIUM', account_created: 'MEDIUM', group_member_added: 'MEDIUM' };

export default function HostMonitor() {
  const s = useStore();
  const [svc, setSvc] = useState<{ name: string; display_name: string; status: string; start_type: string; binpath: string }[]>([]);
  const [q, setQ] = useState('');
  useEffect(() => { api<typeof svc>('/api/live/services').then(setSvc).catch(() => undefined); }, []);
  const m = s.status?.modules.eventlog;
  return (
    <div className="space-y-5">
      {m?.state === 'unavailable' && <Notice tone="warn">{m.detail}</Notice>}
      {s.status?.running && !s.status.admin && <Notice tone="warn">Login and authentication events come from the Windows Security log, which requires administrator rights. Enable it in Settings.</Notice>}
      <div className="grid gap-5 xl:grid-cols-2">
        <Panel title="Live host timeline">
          <div className="max-h-[520px] overflow-auto px-4 pb-3 pt-1">
            {s.events.host_events.length === 0 ? <p className="py-8 text-center text-sm text-mute">No logon, service or audit events recorded yet.</p> :
              <Timeline items={s.events.host_events.slice(0, 40).map((e) => ({ ts: e.ts, title: String(e.event_type).replace(/_/g, ' '), message: e.message, severity: SEV[e.event_type] ?? 'LOW' }))} />}
          </div>
        </Panel>
        <Panel title="Service changes"><div className="max-h-[520px] overflow-auto"><Table rows={s.events.service_events.slice(0, 80)} empty="No service changes observed since protection started."
          cols={[{ h: 'Time', r: (r) => <span className="font-mono text-xs">{fmtTime(r.ts)}</span> }, { h: 'Service', r: (r) => r.name }, { h: 'Change', r: (r) => String(r.action).replace(/_/g, ' ') }, { h: 'Detail', r: (r) => `${r.old_state || '∅'} → ${r.new_state || '∅'}`, cls: 'break-all text-xs' }]} /></div></Panel>
      </div>
      <Panel title="Installed Windows services" right={<input className="input" placeholder="Filter" aria-label="Filter services" value={q} onChange={(e) => setQ(e.target.value)} />}>
        <div className="max-h-[360px] overflow-auto"><Table rows={svc.filter((x) => `${x.name} ${x.display_name} ${x.binpath}`.toLowerCase().includes(q.toLowerCase())).slice(0, 300)} empty="Service list is only available on Windows."
          cols={[{ h: 'Name', r: (x) => x.name }, { h: 'Display name', r: (x) => x.display_name }, { h: 'State', r: (x) => x.status }, { h: 'Start', r: (x) => x.start_type }, { h: 'Binary', r: (x) => x.binpath, cls: 'break-all text-xs font-mono' }]} /></div>
      </Panel>
    </div>
  );
}

import { useEffect, useState } from 'react';
import { TrafficChart } from '../charts/TrafficChart';
import { Notice, Panel, Table } from '../components/ui';
import { api } from '../services/api';
import { fmtBytes, fmtTime } from '../services/format';
import { useStore } from '../services/store';

interface Conn { pid: number | null; process: string; local: string; remote: string; status: string; proto: string; external: boolean; }

export default function NetworkMonitor() {
  const s = useStore();
  const [conns, setConns] = useState<{ connections: Conn[]; listening: { pid: number; process: string; port: number; address: string }[]; error: string | null }>();
  const [onlyExt, setOnlyExt] = useState(false);
  useEffect(() => {
    let alive = true;
    const load = () => api<typeof conns>('/api/live/connections').then((d) => alive && setConns(d)).catch(() => undefined);
    load(); const t = setInterval(load, 3000);
    return () => { alive = false; clearInterval(t); };
  }, []);
  const net = s.status?.modules.network;
  const list = (conns?.connections ?? []).filter((c) => (onlyExt ? c.external : c.remote || c.status === 'LISTEN'));
  return (
    <div className="space-y-5">
      {net?.state === 'unavailable' && <Notice tone="warn">Packet capture is unavailable: {net.detail} Install Npcap (WinPcap API-compatible mode) and restart the app as administrator from Settings. Connection tracking below still works.</Notice>}
      <Panel title="Traffic involving this PC" right={<span className="text-[11px] text-mute">Only packets sent to or from this computer are captured.</span>}>
        <div className="px-2 pb-3">{s.metrics.length ? <TrafficChart data={s.metrics} animate={s.motion === 'full'} height={220} /> : <div className="px-4 py-8 text-center text-sm text-mute">Start protection to see live traffic.</div>}</div>
      </Panel>
      <Panel title="Recent flows" right={<span className="text-[11px] text-mute">Aggregated per flow; payloads are never stored.</span>}>
        <Table rows={s.events.network_events.slice(0, 80)} empty="No flows captured yet."
          cols={[{ h: 'Time', r: (r) => <span className="font-mono text-xs">{fmtTime(r.ts)}</span> }, { h: 'Dir', r: (r) => (r.direction === 'in' ? '← in' : '→ out') },
            { h: 'Source', r: (r) => `${r.src_ip}${r.src_port ? `:${r.src_port}` : ''}`, cls: 'font-mono' }, { h: 'Destination', r: (r) => `${r.dst_ip}${r.dst_port ? `:${r.dst_port}` : ''}`, cls: 'font-mono' },
            { h: 'Proto', r: (r) => r.protocol }, { h: 'TCP flags', r: (r) => r.flags || '—', cls: 'font-mono' }, { h: 'Packets', r: (r) => r.packets }, { h: 'Size', r: (r) => fmtBytes(r.bytes ?? 0) }, { h: 'Process', r: (r) => r.process || '—' }]} />
      </Panel>
      <div className="grid gap-5 xl:grid-cols-[2fr_1fr]">
        <Panel title="Connections by process" right={<label className="flex items-center gap-2 text-xs text-mute"><input type="checkbox" checked={onlyExt} onChange={(e) => setOnlyExt(e.target.checked)} />External only</label>}>
          {conns?.error && <div className="px-4 pb-2"><Notice tone="warn">{conns.error}</Notice></div>}
          <div className="max-h-[420px] overflow-auto"><Table rows={list.slice(0, 300)} empty="No connections."
            cols={[{ h: 'Process', r: (c) => `${c.process || '—'}${c.pid ? ` (${c.pid})` : ''}` }, { h: 'Local', r: (c) => c.local, cls: 'font-mono' }, { h: 'Remote', r: (c) => c.remote || '—', cls: 'font-mono' },
              { h: 'State', r: (c) => c.status }, { h: 'Scope', r: (c) => (c.external ? <span className="text-amber">external</span> : 'local/LAN') }]} /></div>
        </Panel>
        <Panel title="Open (listening) ports"><div className="max-h-[420px] overflow-auto"><Table rows={conns?.listening ?? []} empty="None found."
          cols={[{ h: 'Port', r: (p) => p.port, cls: 'font-mono' }, { h: 'Address', r: (p) => p.address, cls: 'font-mono' }, { h: 'Process', r: (p) => p.process || '—' }]} /></div></Panel>
      </div>
    </div>
  );
}

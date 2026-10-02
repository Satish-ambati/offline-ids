import { useState } from 'react';
import { Field, Notice, Panel, Toggle } from '../components/ui';
import { useStore } from '../services/store';

export default function Settings() {
  const s = useStore();
  const st = s.settings;
  const [msg, setMsg] = useState('');
  if (!st) return null;
  const set = (p: Record<string, unknown>) => s.saveSettings(p);
  const admin = async () => { const r = await window.ids?.relaunchAdmin(); if (r && !r.ok && r.reason !== 'cancelled') setMsg(r.reason ?? 'Could not restart.'); };
  return (
    <div className="grid gap-5 xl:grid-cols-2">
      <Panel title="Appearance and alerts"><div className="space-y-4 px-4 pb-4">
        <Field label="Animations" hint="Heavy animations (3D shield, packet particles) can be reduced or turned off. The operating system's reduced-motion setting is always respected.">
          <select className="input" value={st.animations} onChange={(e) => set({ animations: e.target.value })}><option value="full">Full</option><option value="reduced">Reduced (static shield, fewer particles)</option><option value="off">Off</option></select></Field>
        {s.motion !== st.animations && <p className="text-xs text-amber">Currently reduced by the operating system's reduced-motion preference.</p>}
        <Toggle checked={st.notifications} onChange={(v) => set({ notifications: v })} label="Desktop notifications (medium severity and above)" />
        <Toggle checked={st.sound} onChange={(v) => set({ sound: v })} label="Alert sound" />
        <Toggle checked={st.autostart_protection} onChange={(v) => set({ autostart_protection: v })} label="Start protection when the app opens" />
      </div></Panel>
      <Panel title="Monitoring"><div className="space-y-4 px-4 pb-4">
        <Field label="Capture interface (blank = automatic)"><input className="input w-full" value={st.interface} onChange={(e) => set({ interface: e.target.value })} placeholder="e.g. Wi-Fi" /></Field>
        <Field label="Analysis interval (seconds)"><input type="number" min={2} max={60} className="input w-28" value={st.tick_seconds} onChange={(e) => set({ tick_seconds: Number(e.target.value) })} /></Field>
        <Field label="Keep data for (days)"><input type="number" min={1} max={365} className="input w-28" value={st.retention_days} onChange={(e) => set({ retention_days: Number(e.target.value) })} /></Field>
        <Field label="Ignore file extensions in integrity monitoring (comma separated)"><input className="input w-full" defaultValue={st.fim_excluded_ext.join(', ')} onBlur={(e) => set({ fim_excluded_ext: e.target.value.split(',').map((x) => x.trim()).filter(Boolean) })} /></Field>
      </div></Panel>
      <Panel title="Administrator access"><div className="space-y-3 px-4 pb-4 text-sm">
        <p>Status: <b>{s.status?.admin ? 'running as administrator' : 'standard user'}</b></p>
        <p className="text-xs text-mute">Administrator rights are needed only to capture packets through Npcap and to read the Windows Security log (logins and authentication failures). Everything else works without them. This app never disables antivirus or the firewall, never bypasses Windows security and never collects passwords.</p>
        {!s.status?.admin && window.ids && <button className="btn btn-primary" onClick={admin}>Restart as administrator…</button>}
        {msg && <Notice tone="warn">{msg}</Notice>}
      </div></Panel>
      <Panel title="Demo mode"><div className="space-y-3 px-4 pb-4 text-sm">
        <p className="text-xs text-mute">Runs a scripted scenario (port scan → suspicious process → external connection → file change → login failures) so the interface can be demonstrated safely. Every simulated item is labelled DEMO / SIMULATION and is removed when demo mode stops. It never touches real files, processes or the network.</p>
        <button className={`btn ${s.status?.demo ? 'btn-danger' : 'btn-primary'}`} onClick={s.toggleDemo}>{s.status?.demo ? 'Stop demo and remove simulated data' : 'Start demo simulation'}</button>
      </div></Panel>
      <Panel title="Privacy" className="xl:col-span-2"><ul className="list-disc space-y-1 px-8 pb-4 text-[13px] text-mute">
        <li>All detection, machine learning and storage run locally. No cloud service is contacted.</li><li>Packet payloads, passwords and process command lines are never stored.</li>
        <li>The engine listens only on 127.0.0.1 and requires a random per-launch token.</li><li>Use this tool only on your own PC, isolated virtual machines, or systems you are explicitly authorised to test.</li></ul></Panel>
    </div>
  );
}

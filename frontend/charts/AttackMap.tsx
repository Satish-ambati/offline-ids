import { useEffect, useRef } from 'react';
import type { Motion } from '../animations/motion';
import { sevColor } from '../services/format';
import type { Severity } from '../types';

export type NodeKind = 'internet' | 'source' | 'process' | 'file' | 'service' | 'login' | 'monitor';
export interface MapNode { id: string; kind: NodeKind; label: string; severity?: Severity; state?: string; detail: Record<string, string>; }

// Angular sectors (degrees) so each node type has a home around the protected PC
const SECTOR: Record<NodeKind, [number, number]> = {
  internet: [-90, -90], source: [-150, -30], process: [-15, 40], file: [55, 95], service: [105, 145], login: [160, 205], monitor: [60, 120],
};
interface Placed extends MapNode { x: number; y: number; s: number; r: number; }
interface Packet { n: Placed; t: number; speed: number; out: boolean; bad: boolean; }
interface Spark { x: number; y: number; vx: number; vy: number; life: number; c: string; }

export function AttackMap({ nodes, pps, live, level, motion, onSelect, selectedId }: {
  nodes: MapNode[]; pps: number; live: boolean; level: Severity; motion: Motion; onSelect: (n: MapNode | null) => void; selectedId?: string;
}) {
  const ref = useRef<HTMLCanvasElement>(null);
  const props = useRef({ nodes, pps, live, level, motion, selectedId });
  props.current = { nodes, pps, live, level, motion, selectedId };
  const placed = useRef<Placed[]>([]);
  const redraw = useRef<() => void>(() => undefined);

  useEffect(() => {
    const cv = ref.current!, ctx = cv.getContext('2d')!;
    let w = 0, h = 0, raf = 0, last = performance.now(), acc = 0, running = true;
    const packets: Packet[] = [], sparks: Spark[] = [], seen = new Set<string>();

    const layout = () => {
      const P = props.current, cx = w / 2, cy = h / 2 + 6;
      const rx = w * 0.4, ry = h * 0.34;
      const groups: Record<string, MapNode[]> = {};
      P.nodes.forEach((n) => (groups[n.kind] ||= []).push(n));
      const out: Placed[] = [];
      const drift = P.motion === 'full' ? Math.sin(performance.now() / 6000) * 4 : 0;
      for (const [kind, list] of Object.entries(groups)) {
        const [a0, a1] = SECTOR[kind as NodeKind];
        list.forEach((n, i) => {
          const f = list.length === 1 ? 0.5 : i / (list.length - 1);
          const ang = ((a0 + (a1 - a0) * f + drift) * Math.PI) / 180;
          const rad = kind === 'monitor' ? 0.5 : 1;
          const depth = 0.78 + 0.22 * ((1 + Math.sin(ang)) / 2);
          out.push({ ...n, x: cx + Math.cos(ang) * rx * rad, y: cy + Math.sin(ang) * ry * rad, s: depth, r: (kind === 'monitor' ? 9 : 7) * depth });
        });
      }
      placed.current = out;
    };

    const spawn = (dt: number) => {
      const P = props.current;
      const cap = P.motion === 'full' ? 42 : 14;
      const srcs = placed.current.filter((n) => n.kind === 'source' || n.kind === 'internet');
      const bad = placed.current.filter((n) => n.severity && n.severity !== 'LOW' && n.kind !== 'monitor');
      const rate = P.live ? Math.min(P.motion === 'full' ? 14 : 5, Math.log2(1 + P.pps) * 1.4) : 0;   // driven by real packets-per-second
      acc += rate * dt;
      while (acc >= 1 && packets.length < cap && srcs.length) {
        acc -= 1;
        packets.push({ n: srcs[(Math.random() * srcs.length) | 0], t: 0, speed: 0.35 + Math.random() * 0.35, out: Math.random() < 0.35, bad: false });
      }
      if (bad.length && packets.length < cap && Math.random() < dt * 2.2) {
        packets.push({ n: bad[(Math.random() * bad.length) | 0], t: 0, speed: 0.5, out: false, bad: true });
      }
    };

    const draw = (dt: number) => {
      const P = props.current, cx = w / 2, cy = h / 2 + 6, animated = P.motion !== 'off';
      ctx.clearRect(0, 0, w, h);
      layout();
      // ground grid for depth
      ctx.strokeStyle = 'rgba(86,212,245,.06)'; ctx.lineWidth = 1;
      for (let i = 1; i <= 4; i++) { ctx.beginPath(); ctx.ellipse(cx, cy, (w * 0.4 * i) / 4 * 1.08, (h * 0.34 * i) / 4 * 1.08, 0, 0, Math.PI * 2); ctx.stroke(); }
      // links
      for (const n of placed.current) {
        const c = n.severity && n.severity !== 'LOW' ? sevColor[n.severity] : '#56d4f5';
        const g = ctx.createLinearGradient(n.x, n.y, cx, cy);
        g.addColorStop(0, `${c}${n.severity && n.severity !== 'LOW' ? 'cc' : '55'}`); g.addColorStop(1, `${c}10`);
        ctx.strokeStyle = g; ctx.lineWidth = n.severity && n.severity !== 'LOW' ? 2 : 1;
        if (n.severity && n.severity !== 'LOW') { ctx.shadowColor = c; ctx.shadowBlur = 10; }
        ctx.beginPath(); ctx.moveTo(n.x, n.y); ctx.lineTo(cx, cy); ctx.stroke(); ctx.shadowBlur = 0;
        if (n.severity && n.severity !== 'LOW' && !seen.has(n.id)) {
          seen.add(n.id);
          if (P.motion === 'full') for (let i = 0; i < 16; i++) { const a = (i / 16) * Math.PI * 2; sparks.push({ x: n.x, y: n.y, vx: Math.cos(a) * (40 + Math.random() * 60), vy: Math.sin(a) * (40 + Math.random() * 60), life: 1, c }); }
        }
      }
      // packets
      if (animated) {
        spawn(dt);
        for (let i = packets.length - 1; i >= 0; i--) {
          const p = packets[i]; p.t += dt * p.speed;
          if (p.t >= 1) { packets.splice(i, 1); continue; }
          const f = p.out ? 1 - p.t : p.t;
          const c = p.bad ? sevColor[p.n.severity ?? 'HIGH'] : '#56d4f5';
          for (let k = 0; k < 4; k++) {
            const ff = Math.max(0, Math.min(1, f + (p.out ? 1 : -1) * k * 0.025));
            ctx.globalAlpha = 0.8 - k * 0.2; ctx.fillStyle = c;
            ctx.beginPath(); ctx.arc(p.n.x + (cx - p.n.x) * ff, p.n.y + (cy - p.n.y) * ff, (p.bad ? 3.2 : 2.2) - k * 0.4, 0, Math.PI * 2); ctx.fill();
          }
          ctx.globalAlpha = 1;
        }
        for (let i = sparks.length - 1; i >= 0; i--) {
          const s = sparks[i]; s.life -= dt * 1.3; s.x += s.vx * dt; s.y += s.vy * dt;
          if (s.life <= 0) { sparks.splice(i, 1); continue; }
          ctx.globalAlpha = s.life; ctx.fillStyle = s.c; ctx.fillRect(s.x, s.y, 2.5, 2.5);
        }
        ctx.globalAlpha = 1;
      }
      // nodes
      const t = performance.now() / 1000;
      for (const n of placed.current) {
        const threat = n.severity && n.severity !== 'LOW';
        const col = n.kind === 'monitor' ? (n.state === 'running' ? '#4ade9a' : n.state === 'unavailable' ? '#f2b441' : '#4b5a78')
          : threat ? sevColor[n.severity!] : n.kind === 'internet' ? '#9c8cff' : '#56d4f5';
        if (threat && animated) { const k = (t * 1.2) % 1; ctx.strokeStyle = col; ctx.globalAlpha = 1 - k; ctx.lineWidth = 2; ctx.beginPath(); ctx.arc(n.x, n.y, n.r + k * 16, 0, Math.PI * 2); ctx.stroke(); ctx.globalAlpha = 1; }
        ctx.fillStyle = '#0c1427'; ctx.strokeStyle = col; ctx.lineWidth = n.id === P.selectedId ? 3 : 1.6;
        ctx.shadowColor = col; ctx.shadowBlur = threat ? 14 : 6;
        ctx.beginPath();
        if (n.kind === 'file') ctx.rect(n.x - n.r, n.y - n.r, n.r * 2, n.r * 2);
        else if (n.kind === 'process') { ctx.moveTo(n.x, n.y - n.r * 1.2); ctx.lineTo(n.x + n.r * 1.1, n.y); ctx.lineTo(n.x, n.y + n.r * 1.2); ctx.lineTo(n.x - n.r * 1.1, n.y); ctx.closePath(); }
        else ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.fill(); ctx.stroke(); ctx.shadowBlur = 0;
        ctx.fillStyle = n.kind === 'monitor' ? '#dbe5f6' : '#9fb0cc'; ctx.font = `${Math.round(10.5 * n.s)}px "IBM Plex Sans", sans-serif`; ctx.textAlign = 'center';
        ctx.fillText(n.label.length > 22 ? `${n.label.slice(0, 21)}…` : n.label, n.x, n.y + n.r + 13 * n.s);
      }
      // protected PC (drawn shield)
      const c = props.current.live ? sevColor[P.level] : '#4b5a78';
      const pulse = animated ? 1 + Math.sin(t * 2) * 0.04 : 1;
      ctx.save(); ctx.translate(cx, cy); ctx.scale(pulse, pulse);
      ctx.shadowColor = c; ctx.shadowBlur = 24; ctx.fillStyle = '#0c1427'; ctx.strokeStyle = c; ctx.lineWidth = 2.5;
      ctx.beginPath(); ctx.moveTo(0, -34); ctx.lineTo(30, -23); ctx.lineTo(30, 4); ctx.bezierCurveTo(30, 24, 14, 36, 0, 42); ctx.bezierCurveTo(-14, 36, -30, 24, -30, 4); ctx.lineTo(-30, -23); ctx.closePath();
      ctx.fill(); ctx.stroke(); ctx.shadowBlur = 0; ctx.fillStyle = `${c}30`; ctx.fill();
      ctx.fillStyle = c; ctx.font = '600 9px Sora, sans-serif'; ctx.textAlign = 'center'; ctx.fillText('PROTECTED', 0, 0); ctx.fillText('PC', 0, 12);
      ctx.restore();
    };

    const resize = () => {
      const dpr = window.devicePixelRatio || 1, r = cv.getBoundingClientRect();
      w = r.width; h = r.height; cv.width = w * dpr; cv.height = h * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0); draw(0);
    };
    const ro = new ResizeObserver(resize); ro.observe(cv); resize();
    redraw.current = () => draw(0);

    const loop = (now: number) => {
      if (!running) return;
      const m = props.current.motion, dt = Math.min(0.05, (now - last) / 1000);
      if (m === 'off') { raf = requestAnimationFrame(loop); last = now; return; }
      if (m === 'reduced' && now - last < 41) { raf = requestAnimationFrame(loop); return; }   // ~24 fps
      last = now; draw(dt); raf = requestAnimationFrame(loop);
    };
    raf = requestAnimationFrame(loop);
    const vis = () => { running = !document.hidden; if (running) { last = performance.now(); raf = requestAnimationFrame(loop); } };
    document.addEventListener('visibilitychange', vis);
    return () => { running = false; cancelAnimationFrame(raf); ro.disconnect(); document.removeEventListener('visibilitychange', vis); };
  }, []);

  useEffect(() => { if (motion === 'off') redraw.current(); }, [nodes, motion, level, live, selectedId]);

  const click = (e: React.MouseEvent) => {
    const r = ref.current!.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top;
    const hit = placed.current.find((n) => Math.hypot(n.x - x, n.y - y) <= n.r + 8);
    onSelect(hit ?? null);
  };
  return <canvas ref={ref} onClick={click} className="h-full w-full cursor-crosshair" role="img"
    aria-label="Interactive attack map. Protected PC at the centre with network sources, processes, files, services and login sessions around it." />;
}

import type { Severity } from '../types';
import { sevColor } from '../services/format';

const R = 78, CX = 100, CY = 100, START = Math.PI, SPAN = Math.PI;
const pt = (v: number, r = R) => { const a = START + (v / 100) * SPAN; return [CX + r * Math.cos(a), CY + r * Math.sin(a)]; };
const arc = (a: number, b: number, r = R) => { const [x1, y1] = pt(a, r), [x2, y2] = pt(b, r); return `M${x1} ${y1} A${r} ${r} 0 0 1 ${x2} ${y2}`; };

export function RiskGauge({ score, level, levels }: { score: number; level: Severity; levels: Record<string, number> }) {
  const [nx, ny] = pt(score, R - 14);
  const bands: [number, number, Severity][] = [[0, levels.medium, 'LOW'], [levels.medium, levels.high, 'MEDIUM'], [levels.high, levels.critical, 'HIGH'], [levels.critical, 100, 'CRITICAL']];
  return (
    <figure className="m-0">
      <svg viewBox="0 0 200 122" className="w-full max-w-[260px]" role="img" aria-label={`Application-defined risk level ${level}, score ${score} of 100`}>
        {bands.map(([a, b, s]) => <path key={s} d={arc(a + 0.6, b - 0.6)} stroke={sevColor[s]} strokeOpacity={s === level ? 1 : 0.28} strokeWidth="10" fill="none" />)}
        <line x1={CX} y1={CY} x2={nx} y2={ny} stroke={sevColor[level]} strokeWidth="2.5" strokeLinecap="round" style={{ transition: 'all .8s cubic-bezier(.2,.7,.2,1)' }} />
        <circle cx={CX} cy={CY} r="5" fill={sevColor[level]} />
        <text x={CX} y={CY + 18} textAnchor="middle" fontSize="20" fontWeight="700" fill="#dbe5f6" fontFamily="Sora">{score}</text>
      </svg>
      <figcaption className="-mt-1 text-center text-xs text-mute">{level} · application-defined risk level, not an attack probability</figcaption>
    </figure>
  );
}

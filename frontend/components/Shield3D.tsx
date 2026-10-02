import type { Severity } from '../types';
import { sevColor } from '../services/format';

const PATH = 'M50 4 L92 20 V58 C92 88 72 108 50 116 C28 108 8 88 8 58 V20 Z';

/** CSS-3D shield: stacked SVG layers give thickness; two orbit rings; spins unless motion is reduced/off. */
export function Shield3D({ level, running }: { level: Severity; running: boolean }) {
  const color = running ? sevColor[level] : '#4b5a78';
  const layers = [-3, -2, -1, 0, 1, 2, 3];
  return (
    <div className="shield-scene heavy" style={{ ['--sev' as string]: color }} aria-label={`Protection ${running ? 'active' : 'stopped'}, ${level} risk level`} role="img">
      <div className="shield-rot heavy">
        <span className="ring3d r1 heavy" /><span className="ring3d r2 heavy" />
        {layers.map((z) => (
          <svg key={z} viewBox="0 0 100 120" style={{ transform: `translateZ(${z * 5}px)` }}>
            <path d={PATH} fill={z === 3 ? `${color}22` : `${color}${z < 0 ? '10' : '18'}`} stroke={color} strokeWidth={z === 3 || z === -3 ? 2 : 1} strokeOpacity={z === 3 ? 1 : 0.5} />
            {z === 3 && (
              <g fill="none" stroke={color} strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round">
                <rect x="36" y="52" width="28" height="22" rx="3" fill={`${color}33`} />
                <path d="M42 52 V45 a8 8 0 0 1 16 0 V52" />
                <circle cx="50" cy="63" r="2.5" fill={color} stroke="none" />
              </g>
            )}
          </svg>
        ))}
      </div>
    </div>
  );
}

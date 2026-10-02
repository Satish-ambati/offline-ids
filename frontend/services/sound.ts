let ctx: AudioContext | null = null;
const FREQ: Record<string, number[]> = { LOW: [520], MEDIUM: [660, 520], HIGH: [880, 660, 880], CRITICAL: [990, 740, 990, 740] };

export function beep(severity: string) {
  try {
    ctx = ctx ?? new AudioContext();
    let t = ctx.currentTime;
    for (const f of FREQ[severity] ?? FREQ.LOW) {
      const o = ctx.createOscillator(), g = ctx.createGain();
      o.frequency.value = f; o.type = 'sine';
      g.gain.setValueAtTime(0.0001, t); g.gain.exponentialRampToValueAtTime(0.08, t + 0.02); g.gain.exponentialRampToValueAtTime(0.0001, t + 0.16);
      o.connect(g).connect(ctx.destination); o.start(t); o.stop(t + 0.18); t += 0.18;
    }
  } catch { /* audio unavailable */ }
}

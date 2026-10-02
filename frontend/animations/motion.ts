import { useEffect, useState } from 'react';

export type Motion = 'full' | 'reduced' | 'off';

/** Effective motion level: the user's setting, downgraded when the OS asks for reduced motion. */
export function useEffectiveMotion(setting: Motion): Motion {
  const [prefers, setPrefers] = useState(() => window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    const h = () => setPrefers(mq.matches);
    mq.addEventListener('change', h);
    return () => mq.removeEventListener('change', h);
  }, []);
  return prefers ? 'off' : setting;
}

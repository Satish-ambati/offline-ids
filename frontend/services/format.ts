import type { Severity } from '../types';

export const fmtTime = (ts?: number | null) => (ts ? new Date(ts * 1000).toLocaleTimeString([], { hour12: false }) : '—');
export const fmtDateTime = (ts?: number | null) => (ts ? new Date(ts * 1000).toLocaleString([], { hour12: false }) : '—');
export const fmtBytes = (n: number) => {
  if (n < 1024) return `${n.toFixed(0)} B`;
  const u = ['KB', 'MB', 'GB', 'TB']; let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return `${n.toFixed(1)} ${u[i]}`;
};
export const sevColor: Record<Severity, string> = { LOW: '#56d4f5', MEDIUM: '#f2b441', HIGH: '#ff8a4c', CRITICAL: '#ff5468' };
export const sevLabel: Record<Severity, string> = {
  LOW: 'Informational Event', MEDIUM: 'Suspicious Activity', HIGH: 'High-Risk Activity', CRITICAL: 'Critical Security Incident',
};
export const sevRank = (s: string) => ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].indexOf(s);
export const parse = <T,>(v: unknown, fallback: T): T => {
  if (typeof v === 'string') { try { return JSON.parse(v) as T; } catch { return fallback; } }
  return (v as T) ?? fallback;
};
export const kindLabel = (k: string) => k.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase());

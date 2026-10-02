import { Area, AreaChart, CartesianGrid, Line, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { fmtTime } from '../services/format';
import type { Metric } from '../types';

export function TrafficChart({ data, animate, height = 200 }: { data: Metric[]; animate: boolean; height?: number }) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 8, right: 12, bottom: 0, left: -12 }}>
        <defs><linearGradient id="pps" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#56d4f5" stopOpacity={0.4} /><stop offset="1" stopColor="#56d4f5" stopOpacity={0} /></linearGradient></defs>
        <CartesianGrid stroke="#1b2a47" strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey="ts" tickFormatter={fmtTime} stroke="#7f92b3" fontSize={11} minTickGap={50} />
        <YAxis stroke="#7f92b3" fontSize={11} width={48} />
        <Tooltip contentStyle={{ background: '#0c1427', border: '1px solid #1b2a47', borderRadius: 6, fontSize: 12 }} labelFormatter={(v) => fmtTime(v as number)}
          formatter={(v: number, n) => [v.toFixed(1), n === 'pps' ? 'packets/s' : 'new connections/s']} />
        <Area type="monotone" dataKey="pps" stroke="#56d4f5" fill="url(#pps)" strokeWidth={1.8} isAnimationActive={animate} dot={false} />
        <Line type="monotone" dataKey="cps" stroke="#9c8cff" strokeWidth={1.5} dot={false} isAnimationActive={animate} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

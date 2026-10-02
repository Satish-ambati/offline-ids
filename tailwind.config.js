/** @type {import('tailwindcss').Config} */
export default {
  content: ['./frontend/index.html', './frontend/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: '#060b18', panel: '#0c1427', raise: '#111c34', line: '#1b2a47', mute: '#7f92b3', text: '#dbe5f6',
        signal: '#56d4f5', amber: '#f2b441', alarm: '#ff5468', violet: '#9c8cff', mint: '#4ade9a',
      },
      fontFamily: { display: ['Sora', 'Segoe UI', 'sans-serif'], sans: ['"IBM Plex Sans"', 'Segoe UI', 'sans-serif'], mono: ['"IBM Plex Mono"', 'Consolas', 'monospace'] },
    },
  },
  plugins: [],
};

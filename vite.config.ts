import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  root: 'frontend',
  base: './',
  plugins: [react()],
  server: { port: 5173, strictPort: true },
  build: { outDir: '../dist/renderer', emptyOutDir: true, sourcemap: false },
});

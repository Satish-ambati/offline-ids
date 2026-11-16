import { ChildProcess, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { app } from 'electron';

export interface EngineConfig { baseUrl: string; wsUrl: string; token: string; dev: boolean; }

// Loading numpy/scikit-learn/scapy from a cold disk can take well over 30 s on Windows
// (antivirus scanning, slow HDD), so allow a generous first-start window.
const STARTUP_TIMEOUT_MS = Number(process.env.IDS_ENGINE_TIMEOUT_MS) || 120_000;

let child: ChildProcess | null = null;
let config: EngineConfig | null = null;
let spawnError: Error | null = null;
export let engineLog = '';

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const port = (srv.address() as net.AddressInfo).port;
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

function resolveCommand(): { cmd: string; args: string[]; cwd: string } {
  if (app.isPackaged) {
    const exe = path.join(process.resourcesPath, 'engine', 'engine.exe');
    if (!existsSync(exe)) throw new Error(`Bundled engine not found at ${exe}. Build it with "npm run build:engine" before packaging.`);
    return { cmd: exe, args: [], cwd: path.dirname(exe) };
  }
  const root = path.resolve(__dirname, '..');
  const dir = path.join(root, 'security-engine');
  const venv = process.platform === 'win32' ? path.join(dir, '.venv', 'Scripts', 'python.exe') : path.join(dir, '.venv', 'bin', 'python');
  const py = process.env.IDS_PYTHON || (existsSync(venv) ? venv : process.platform === 'win32' ? 'python' : 'python3');
  return { cmd: py, args: ['main.py'], cwd: dir };
}

async function waitHealthy(baseUrl: string, timeoutMs = STARTUP_TIMEOUT_MS): Promise<void> {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    // a missing interpreter raises 'error' with no exit code, so without this the loop would spin until the timeout
    if (spawnError) throw new Error(`${spawnError.message}\nCheck that Python dependencies are installed (see README, "Python environment").`);
    try {
      const r = await fetch(`${baseUrl}/api/health`);
      if (r.ok) return;
    } catch { /* not up yet */ }
    if (child && child.exitCode !== null) throw new Error(`Security engine exited (code ${child.exitCode}).\n${engineLog.slice(-1500)}`);
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error(`Security engine did not become ready within ${Math.round(timeoutMs / 1000)}s.\n${engineLog.slice(-1500) || '(no output from the engine)'}`);
}

export async function startEngine(): Promise<EngineConfig> {
  if (config) return config;
  const port = await freePort();
  const token = randomBytes(24).toString('hex');
  const { cmd, args, cwd } = resolveCommand();
  spawnError = null;
  child = spawn(cmd, [...args, '--port', String(port)], {
    cwd, windowsHide: true, env: { ...process.env, IDS_TOKEN: token, PYTHONUNBUFFERED: '1' },
  });
  const collect = (b: Buffer) => { engineLog = (engineLog + b.toString()).slice(-8000); };
  child.stdout?.on('data', collect);
  child.stderr?.on('data', collect);
  child.on('error', (e) => { engineLog += `\nspawn error: ${e.message}`; spawnError = e; });
  const baseUrl = `http://127.0.0.1:${port}`;
  try {
    await waitHealthy(baseUrl);
  } catch (e) {
    stopEngine();
    const detail = `Interpreter: ${cmd}\nWorking directory: ${cwd}\nLog: %APPDATA%\\OfflineIDS\\logs\\engine.log`;
    throw new Error(`${(e as Error).message}\n\n${detail}`);
  }
  config = { baseUrl, wsUrl: `ws://127.0.0.1:${port}/ws`, token, dev: !app.isPackaged };
  return config;
}

export function stopEngine(): void {
  spawnError = null;
  if (child && child.exitCode === null) {
    if (process.platform === 'win32' && child.pid) spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { windowsHide: true });
    else child.kill('SIGTERM');
  }
  child = null;
  config = null;
}

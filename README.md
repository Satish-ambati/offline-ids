# Endpoint Security Center — Offline AI-Powered Host & Network IDS (single Windows PC)

A desktop intrusion-detection application for **one Windows PC**. It watches network traffic to/from the PC, sockets and open
ports, logons, processes, services and monitored folders; runs rule-based detection, event correlation, risk scoring and local
machine learning; and shows everything in a dark SOC-style dashboard. **Detection, ML and storage are all local — no cloud services.**

> **Honest scope.** The app detects *observable host and network behaviour*. It cannot detect every cyberattack, a quiet dashboard
> is not proof of a clean system, and it can only see traffic that reaches this PC's network card. Risk levels are
> **application-defined** (LOW 0–29, MEDIUM 30–59, HIGH 60–79, CRITICAL 80–100) and are **not attack probabilities**. ML output is a
> supporting signal, never proof.

## Architecture

```
Electron (main, preload, IPC)  ──spawns──►  Python engine (FastAPI on 127.0.0.1 + random per-launch token)
   │  React + TypeScript + Tailwind UI  ◄── REST + WebSocket ──►  monitors → detectors → correlation → risk → SQLite
```

| Folder | Contents |
|---|---|
| `electron/` | `main.ts` (window, CSP, engine lifecycle), `engine.ts` (spawn/health/kill), `preload.ts` (safe bridge), `ipc/handlers.ts` (notifications, folder picker, admin relaunch, report open) |
| `frontend/` | `pages/` (10 pages), `components/`, `charts/` (attack map canvas, risk gauge, traffic chart), `animations/`, `services/` (API, WebSocket store) |
| `security-engine/network` | Scapy/Npcap sniffer, flow aggregation, socket↔process tracker |
| `security-engine/host` | Windows Event Log (wevtutil), service monitor, system metrics |
| `security-engine/process` | Process create/terminate + parent-child (polling, optional WMI trace) |
| `security-engine/filesystem` | Watchdog + SHA-256 baselines (file integrity) |
| `security-engine/detection` | Port scan, SYN-flood-like, brute-force-like, DoS-like/abnormal traffic, process behaviour rules |
| `security-engine/correlation` | Links signals into incidents (process ↔ PID ↔ connection ↔ files ↔ logins) |
| `security-engine/risk` | Configurable weights + correlation bonus |
| `security-engine/ml` | Isolation Forest (unsupervised, learns this PC) + optional Random Forest (labelled CSV) |
| `security-engine/database` | SQLite schema: security_events, network_events, host_events, process_events, file_events, service_events, alerts, incidents, risk_scores (+ settings, fim tables) |
| `security-engine/reports` | ReportLab PDF generator |
| `security-engine/demo` | DEMO/SIMULATION scenario (all data flagged `is_demo`) |
| `tests/` | pytest suite (detectors, correlation, risk, FIM, ML, DB, API) |

## Windows setup

1. Install **Node.js 20+** (https://nodejs.org) and **Python 3.10–3.12** (https://python.org, tick "Add to PATH").
2. Install **Npcap** (https://npcap.com) — tick **"Install Npcap in WinPcap API-compatible Mode"**. Needed only for packet capture.
3. In PowerShell, from this folder:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
```

This creates `security-engine\.venv`, installs Python and npm dependencies and initialises the database. Manual equivalent:

```powershell
cd security-engine
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe main.py --init-db      # creates %APPDATA%\OfflineIDS\ids.sqlite3
cd ..
npm install
```

## Run

```powershell
npm run dev        # Vite + Electron (hot reload UI); Electron starts the Python engine automatically
npm start          # build once, then run the compiled app
```

For **full visibility** run the app as administrator (Settings → *Restart as administrator*, or launch the terminal as admin).
Elevation is optional and only needed for (a) packet capture through Npcap and (b) reading the Windows Security log
(logons/failures). Without it the app runs in limited mode and says so. The app never disables antivirus/firewall, never bypasses
Windows security and never stores passwords, packet payloads or process command lines.

Try it safely first: **Settings → Start demo simulation**. Every simulated event is labelled **DEMO / SIMULATION** and removed when
you stop the demo.

### Using it
1. **Start protection** (top bar). The ML baseline learns from the first ~60 windows (5 s each) — start while the PC is idle/normal.
2. **File Integrity** → choose folders → SHA-256 baselines are built; later changes are compared.
3. Investigate in **Alerts**, **Incident Timeline** (animated), **Network / Host / Process** monitors; export **Security Reports** (PDF).
4. Tune thresholds and risk weights in **Threat Detection**.

### Engine-only development (any OS)
```bash
cd security-engine && pip install -r requirements-dev.txt && python main.py --port 8765
# UI in a browser: npm run dev:renderer  → http://localhost:5173/?port=8765   (engine started without IDS_TOKEN)
```

## Testing
```powershell
cd security-engine
.\.venv\Scripts\python.exe -m pytest -q          # 19 tests
cd ..; npm run typecheck
```
Test attack-like behaviour **only on your own PC, an isolated VM, or systems you are explicitly authorised to test**. Examples
from a *second* machine you own: `nmap -sS -p 1-1000 <your-pc-ip>` (port scan rule); repeated wrong logons to a test account
(authentication rule); drop an `.exe` into a protected folder (file integrity).

## Production build
```powershell
npm run build:engine     # PyInstaller → build\engine\engine.exe  (bundles Python so the installer needs no Python)
npm run dist             # Electron Builder → release\Endpoint Security Center Setup x.y.z.exe
```
Npcap is a separate installer and is not bundled (its licence restricts redistribution); the app shows guidance when it is missing.

## Detection logic (summary)
* **Port scan** – ≥20 unique destination ports (connection attempts only) from one peer in 10 s.
* **Brute-force-like auth** – ≥5 failed logons in 5 min grouped by source and by account; success-after-failures escalates.
* **SYN-flood-like** – ≥150 inbound SYNs in 5 s with SYN:ACK ratio ≥3.
* **Abnormal traffic / DoS-like** – pps/bps/cps vs learned baseline; **MEDIUM** on its own, **HIGH** only if CPU, memory or loopback responsiveness also degrade.
* **Suspicious process** – behaviour only (unusual location, office→script-host chain, system-binary name outside System32). A process
  becomes an *incident* only when independent signals (e.g. unusual path + external connection + file change) correlate.
  File changes are linked to a process by **timing** (labelled "time-linked"); Windows file events carry no PID.
* **Risk** – sum of the strongest weight per signal type + 6 per extra signal type, capped at 100 (editable in the UI).

## Known limitations
* Process creation is polled every 1 s (plus WMI trace when running as admin with `wmi` installed); very short-lived processes can be missed without WMI.
* Windows Security-log logon events require administrator rights and the relevant audit policy enabled.
* Switched networks: only traffic to/from this PC is visible; no promiscuous capture of other hosts.
* The Isolation Forest assumes the learning period was benign.
* Verified in development: engine logic, API and UI build on Linux; Windows-only modules (Event Log, services, Npcap, WMI, packaging)
  follow documented Windows APIs but must be validated on your Windows machine.

## Troubleshooting
| Symptom | Fix |
|---|---|
| "Security engine failed to start" | Run `scripts\setup.ps1`; check `%APPDATA%\OfflineIDS\logs\engine.log` |
| Network module "unavailable" | Install Npcap (WinPcap-compatible mode) and restart as administrator |
| No login events | Restart as administrator; enable *Audit Logon* in local security policy |
| Heavy CPU from animations | Settings → Animations → Reduced/Off |

Logs: `%APPDATA%\OfflineIDS\logs\engine.log` (rotating). Data: `%APPDATA%\OfflineIDS\`.

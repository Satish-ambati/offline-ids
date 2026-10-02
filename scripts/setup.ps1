# One-time setup for Windows 10/11. Run from the project root in PowerShell:
#   powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
$ErrorActionPreference = "Stop"
Write-Host "== Checking prerequisites ==" -ForegroundColor Cyan
foreach ($t in @("node", "npm", "python")) {
  if (-not (Get-Command $t -ErrorAction SilentlyContinue)) { throw "$t was not found. Install Node.js 20+ and Python 3.10+ first (see README)." }
}
Write-Host "== Python virtual environment ==" -ForegroundColor Cyan
Push-Location security-engine
if (-not (Test-Path ".venv")) { python -m venv .venv }
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
Write-Host "== Initialising local database ==" -ForegroundColor Cyan
& .\.venv\Scripts\python.exe main.py --init-db
Pop-Location
Write-Host "== Node dependencies ==" -ForegroundColor Cyan
npm install
if (-not (Test-Path "$env:SystemRoot\System32\Npcap")) {
  Write-Host "Npcap not found. Install it from https://npcap.com (tick 'WinPcap API-compatible Mode') to enable packet capture." -ForegroundColor Yellow
}
Write-Host "Done. Start the app with:  npm run dev" -ForegroundColor Green

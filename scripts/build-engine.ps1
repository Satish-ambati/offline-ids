# Bundles the Python engine into build\engine\engine.exe (PyInstaller) so the installer needs no Python.
$ErrorActionPreference = "Stop"
Push-Location security-engine
& .\.venv\Scripts\python.exe -m PyInstaller --noconfirm --clean --onedir --name engine `
  --collect-submodules scapy --collect-submodules sklearn --hidden-import uvicorn.logging --hidden-import uvicorn.loops.auto `
  --hidden-import uvicorn.protocols.http.auto --hidden-import uvicorn.protocols.websockets.auto --hidden-import uvicorn.lifespan.on `
  --hidden-import win32timezone --distpath ..\build --workpath ..\build\pyi-work --specpath ..\build main.py
Pop-Location
Write-Host "Engine bundled in build\engine" -ForegroundColor Green

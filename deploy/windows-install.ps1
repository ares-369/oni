# =====================================================================
#  OniOps - Offensive Neural Intelligence - Windows installer
#  Requires Python 3.10+ (https://www.python.org). Run in PowerShell:
#      powershell -ExecutionPolicy Bypass -File deploy\windows-install.ps1
#  OniOps drives the Kali host over SSH (paramiko) and serves the UI with
#  waitress, so no WSL or OpenSSH binary is required.
# =====================================================================
$ErrorActionPreference = "Stop"

Write-Host "[OniOps] creating virtual environment..."
python -m venv venv
.\venv\Scripts\python.exe -m pip install --upgrade pip
.\venv\Scripts\pip.exe install -r requirements.txt

if (-not (Test-Path "config.yaml")) {
    Copy-Item "config.example.yaml" "config.yaml"
    Write-Host "[OniOps] created config.yaml - EDIT IT (scope + Kali host)."
}
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
}
New-Item -ItemType Directory -Force -Path "secrets","data" | Out-Null

Write-Host ""
Write-Host "[OniOps] Installed. Next steps:"
Write-Host "  1. Edit config.yaml (your network scope + Kali host)."
Write-Host "  2. Put the Kali SSH private key in .\secrets\ and point config.yaml at it."
Write-Host "  3. Start OniOps:   .\venv\Scripts\python.exe -m oniops"
Write-Host "  (To run as a Windows service, use NSSM: nssm install OniOps ...\python.exe -m oniops)"

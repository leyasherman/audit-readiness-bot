# One-time setup (Windows PowerShell):  powershell -ExecutionPolicy Bypass -File setup.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Test-Path .venv)) { py -m venv .venv }
.\.venv\Scripts\python -m pip install -q -r requirements.txt
.\.venv\Scripts\python demo\setup_demo.py
Write-Host ""
Write-Host "Ready. Try:  .\.venv\Scripts\python -m auditbot scan demo-target"

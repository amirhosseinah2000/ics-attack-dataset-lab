$ErrorActionPreference = "Stop"

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host "uv is not installed. Install uv first, then re-run this script."
    exit 1
}

uv venv
uv pip install -e ".[dev]"

Write-Host ""
Write-Host "Environment created."
Write-Host "Activate with: .\.venv\Scripts\Activate.ps1"
Write-Host "Then run: icslab doctor"

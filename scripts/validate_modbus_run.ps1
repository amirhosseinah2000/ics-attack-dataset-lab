param(
    [Parameter(Mandatory = $true)]
    [string]$RunDir
)

$ErrorActionPreference = "Stop"

$repoRoot = (Get-Location).Path
$validator = Join-Path $repoRoot "scripts\validate_modbus_run.py"

if (-not (Test-Path $validator)) {
    throw "Validator not found: $validator"
}

$resolvedRunDir = [System.IO.Path]::GetFullPath(
    (Join-Path $repoRoot $RunDir)
)

if (-not (Test-Path $resolvedRunDir)) {
    throw "Run directory not found: $resolvedRunDir"
}

Write-Host ""
Write-Host "====================================================="
Write-Host " ICS Attack Dataset Lab - Modbus Run Validation"
Write-Host "====================================================="
Write-Host "Run directory : $resolvedRunDir"
Write-Host ""

& python $validator --run-dir $resolvedRunDir

if ($LASTEXITCODE -ne 0) {
    throw "Validation failed. Check validation_report.json in the run directory."
}

Write-Host ""
Write-Host "Validation passed."

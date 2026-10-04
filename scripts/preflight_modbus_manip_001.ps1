param(
    [string]$ComposeFile = "external\aloha-water-treatment\docker-compose-example.yml"
)

$ErrorActionPreference = "Stop"
$repoRoot = (Get-Location).Path
$composePath = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $ComposeFile))

Write-Host ""
Write-Host "====================================================="
Write-Host " MODBUS-MANIP-001 - Preflight"
Write-Host "====================================================="

function Pass([string]$Text) { Write-Host "[PASS] $Text" }
function Fail([string]$Text) { Write-Host "[FAIL] $Text"; throw $Text }

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Fail "Docker CLI not found." }
Pass "Docker CLI found"

& docker version *> $null
if ($LASTEXITCODE -ne 0) { Fail "Docker Engine is not available." }
Pass "Docker Engine reachable"

& docker compose version *> $null
if ($LASTEXITCODE -ne 0) { Fail "Docker Compose is not available." }
Pass "Docker Compose available"

if (-not (Test-Path $composePath)) { Fail "Compose file not found: $composePath" }
Pass "Compose file found"

$required = @(
    "scripts\record_process_state.ps1",
    "scripts\extract_modbus.ps1",
    "scripts\label_modbus_packets.py",
    "scripts\validate_modbus_run.py",
    "scripts\modbus_manual_overflow_lab.py",
    "configs\scenarios\modbus\MODBUS-MANIP-001.yaml"
)
foreach ($rel in $required) {
    $p = Join-Path $repoRoot $rel
    if (-not (Test-Path $p)) { Fail "Required file missing: $rel" }
    Pass $rel
}

$plc = (& docker compose -f $composePath ps -q aloha-plc).Trim()
$hmi = (& docker compose -f $composePath ps -q aloha-hmi).Trim()
if ([string]::IsNullOrWhiteSpace($plc)) { Fail "aloha-plc is not running." }
if ([string]::IsNullOrWhiteSpace($hmi)) { Fail "aloha-hmi is not running." }
Pass "aloha-plc is running"
Pass "aloha-hmi is running"

$networkName = (& docker inspect $plc --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}').Trim()
if ([string]::IsNullOrWhiteSpace($networkName)) { Fail "Could not resolve Aloha Docker network." }
Pass "Docker network: $networkName"

$hmiImage = (& docker inspect $hmi --format '{{.Config.Image}}').Trim()
if ([string]::IsNullOrWhiteSpace($hmiImage)) { Fail "Could not resolve HMI image." }
Pass "HMI image: $hmiImage"

$probe = @'
from pymodbus.client import ModbusTcpClient
try:
    c = ModbusTcpClient("aloha-plc", port=5020, timeout=2)
    if not c.connect():
        raise SystemExit(2)
    try:
        r = c.read_holding_registers(address=0, count=10, device_id=1)
    except TypeError:
        r = c.read_holding_registers(address=0, count=10, slave=1)
    if r.isError():
        raise SystemExit(3)
    print("REGS=" + ",".join(str(x) for x in r.registers[:10]))
    c.close()
except Exception as exc:
    print(type(exc).__name__ + ":" + str(exc))
    raise
'@

$probeOut = $probe | & docker compose -f $composePath exec -T aloha-hmi python3 -
if ($LASTEXITCODE -ne 0) { Fail "Modbus read probe failed." }
Pass "Modbus read probe succeeded: $($probeOut -join ' ')"

Write-Host ""
Write-Host "Preflight passed. The lab is ready for a short smoke run."

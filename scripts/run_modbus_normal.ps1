param(
    [string]$ScenarioId = "MODBUS-NORMAL-001",

    [int]$DurationSeconds = 120,

    [double]$ProcessIntervalSeconds = 1.0,

    [string]$ComposeFile = "external\aloha-water-treatment\docker-compose-example.yml",

    [string]$Protocol = "modbus_tcp",

    [int]$ModbusPort = 5020,

    [string]$CaptureRoot = "captures\modbus\normal",

    [string]$NetshootImage = "nicolaka/netshoot"
)

$ErrorActionPreference = "Stop"

function Get-UtcIso {
    return (Get-Date).ToUniversalTime().ToString("o")
}

$repoRoot = (Get-Location).Path
$composePath = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $ComposeFile))

if (-not (Test-Path $composePath)) {
    throw "Compose file not found: $composePath"
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$runId = "${ScenarioId}_${timestamp}"

$runDir = [System.IO.Path]::GetFullPath(
    (Join-Path $repoRoot (Join-Path $CaptureRoot $runId))
)

New-Item -ItemType Directory -Force $runDir | Out-Null

$pcapPath = Join-Path $runDir "traffic.pcap"
$processPath = Join-Path $runDir "process_state.csv"
$modbusCsvPath = Join-Path $runDir "modbus_packets.csv"
$groundTruthPath = Join-Path $runDir "ground_truth.jsonl"
$manifestPath = Join-Path $runDir "manifest.yaml"

$captureContainer = ("icslab-capture-" + $runId.ToLower() -replace '[^a-z0-9_.-]', '-')

Write-Host ""
Write-Host "====================================================="
Write-Host " ICS Attack Dataset Lab - Normal Modbus Run"
Write-Host "====================================================="
Write-Host "Run ID      : $runId"
Write-Host "Scenario ID : $ScenarioId"
Write-Host "Duration    : $DurationSeconds sec"
Write-Host "Output      : $runDir"
Write-Host ""

# -------------------------------------------------------------------
# 1. Verify Aloha services
# -------------------------------------------------------------------
Write-Host "[1/6] Checking Aloha services..."

$services = & docker compose -f $composePath ps --status running --services
if ($LASTEXITCODE -ne 0) {
    throw "Could not query Docker Compose services."
}

if ($services -notcontains "aloha-plc") {
    throw "aloha-plc is not running."
}

if ($services -notcontains "aloha-hmi") {
    throw "aloha-hmi is not running."
}

$plcContainer = (
    & docker compose -f $composePath ps -q aloha-plc
).Trim()

if ([string]::IsNullOrWhiteSpace($plcContainer)) {
    throw "Could not resolve aloha-plc container ID."
}

Write-Host "      PLC container: $plcContainer"

# -------------------------------------------------------------------
# 2. Record provenance before capture
# -------------------------------------------------------------------
Write-Host "[2/6] Recording provenance..."

$alohaPath = Split-Path $composePath -Parent
$alohaCommit = (& git -C $alohaPath rev-parse HEAD).Trim()

try {
    $dockerVersion = (& docker version --format '{{.Server.Version}}').Trim()
}
catch {
    $dockerVersion = "unknown"
}

$startUtc = Get-UtcIso

# Initial Ground Truth event.
$startEvent = [ordered]@{
    timestamp_utc = $startUtc
    event          = "run_start"
    run_id         = $runId
    scenario_id    = $ScenarioId
    protocol       = $Protocol
    binary_label   = "normal"
    attack         = $false
}

$startEvent |
    ConvertTo-Json -Compress |
    Set-Content -Path $groundTruthPath -Encoding utf8

# -------------------------------------------------------------------
# 3. Start packet capture
# -------------------------------------------------------------------
Write-Host "[3/6] Starting Modbus PCAP capture..."

$captureId = & docker run --rm -d `
    --name $captureContainer `
    --network "container:$plcContainer" `
    -v "${runDir}:/captures" `
    $NetshootImage `
    tcpdump -i any -nn -s 0 -U `
    -w /captures/traffic.pcap `
    "tcp port $ModbusPort"

if ($LASTEXITCODE -ne 0) {
    throw "Failed to start packet capture."
}

Write-Host "      Capture container: $captureContainer"

# Give tcpdump a moment to initialize.
Start-Sleep -Seconds 2

# -------------------------------------------------------------------
# 4. Record process state while PCAP capture is running
# -------------------------------------------------------------------
Write-Host "[4/6] Recording process state..."

try {
    & (Join-Path $repoRoot "scripts\record_process_state.ps1") `
        -Output $processPath `
        -DurationSeconds $DurationSeconds `
        -IntervalSeconds $ProcessIntervalSeconds `
        -ComposeFile $composePath `
        -HmiService "aloha-hmi" `
        -PlcHost "aloha-plc" `
        -PlcPort $ModbusPort

    if ($LASTEXITCODE -ne 0) {
        throw "Process-state recorder failed."
    }
}
finally {
    Write-Host "      Stopping capture..."
    & docker stop $captureContainer | Out-Null
}

$endUtc = Get-UtcIso

$endEvent = [ordered]@{
    timestamp_utc = $endUtc
    event          = "run_end"
    run_id         = $runId
    scenario_id    = $ScenarioId
    protocol       = $Protocol
    binary_label   = "normal"
    attack         = $false
}

$endEvent |
    ConvertTo-Json -Compress |
    Add-Content -Path $groundTruthPath -Encoding utf8

# -------------------------------------------------------------------
# 5. Extract Modbus application-layer fields
# -------------------------------------------------------------------
Write-Host "[5/6] Extracting Modbus application-layer fields..."

& (Join-Path $repoRoot "scripts\extract_modbus.ps1") `
    -Pcap $pcapPath `
    -Output $modbusCsvPath `
    -ModbusPort $ModbusPort `
    -Image $NetshootImage

if ($LASTEXITCODE -ne 0) {
    throw "Modbus extraction failed."
}

# -------------------------------------------------------------------
# 6. Write run manifest
# -------------------------------------------------------------------
Write-Host "[6/6] Writing manifest..."

$processSamples = 0
if (Test-Path $processPath) {
    $processSamples = [Math]::Max(
        0,
        ((Get-Content $processPath | Measure-Object -Line).Lines - 1)
    )
}

$modbusRows = 0
if (Test-Path $modbusCsvPath) {
    $modbusRows = [Math]::Max(
        0,
        ((Get-Content $modbusCsvPath | Measure-Object -Line).Lines - 1)
    )
}

$pcapBytes = 0
if (Test-Path $pcapPath) {
    $pcapBytes = (Get-Item $pcapPath).Length
}

$manifest = @"
dataset_version: "0.1-dev"
run_id: "$runId"
scenario_id: "$ScenarioId"

class:
  binary_label: "normal"
  attack: false

protocol:
  name: "$Protocol"
  transport: "tcp"
  port: $ModbusPort

simulator:
  name: "MITRE Aloha Water Treatment"
  git_commit: "$alohaCommit"

environment:
  docker_server_version: "$dockerVersion"

timing:
  start_utc: "$startUtc"
  end_utc: "$endUtc"
  requested_duration_seconds: $DurationSeconds
  process_interval_seconds: $ProcessIntervalSeconds

fidelity_level: "cyber_physical_simulation"

artifacts:
  pcap: "traffic.pcap"
  modbus_packets: "modbus_packets.csv"
  process_state: "process_state.csv"
  ground_truth: "ground_truth.jsonl"

capture:
  filter: "tcp port $ModbusPort"
  pcap_bytes: $pcapBytes

statistics:
  process_samples: $processSamples
  modbus_rows: $modbusRows

ground_truth:
  attack: false
  label_source: "scenario_definition"
"@

$manifest | Set-Content -Path $manifestPath -Encoding utf8

Write-Host ""
Write-Host "====================================================="
Write-Host " RUN COMPLETE"
Write-Host "====================================================="
Write-Host "Run directory : $runDir"
Write-Host "PCAP bytes    : $pcapBytes"
Write-Host "Process rows  : $processSamples"
Write-Host "Modbus rows   : $modbusRows"
Write-Host ""
Write-Host "Artifacts:"
Write-Host "  traffic.pcap"
Write-Host "  process_state.csv"
Write-Host "  modbus_packets.csv"
Write-Host "  ground_truth.jsonl"
Write-Host "  manifest.yaml"
Write-Host ""

# Return the run directory so callers can reuse it.
Write-Output $runDir

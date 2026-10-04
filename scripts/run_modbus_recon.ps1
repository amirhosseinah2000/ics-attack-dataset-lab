param(
    [string]$RunIdOverride = "",
    [string]$RecorderContainer = "",

    [int]$WarmupSeconds = 30,
    [int]$AttackSeconds = 30,
    [int]$RecoverySeconds = 30,
    [double]$RequestsPerSecond = 5.0,

    [string]$ScenarioId = "MODBUS-RECON-001",
    [string]$ComposeFile = "external\aloha-water-treatment\docker-compose-example.yml",
    [string]$CaptureRoot = "captures\modbus\attack",
    [int]$ModbusPort = 5020,
    [string]$NetshootImage = "nicolaka/netshoot"
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "assert_local_lab.ps1")
Assert-LocalLabDocker

function Get-UtcIso {
    return (Get-Date).ToUniversalTime().ToString("o")
}

function Append-JsonLine {
    param(
        [string]$Path,
        [hashtable]$Object
    )
    $Object |
        ConvertTo-Json -Compress |
        Add-Content -Path $Path -Encoding utf8
}

$repoRoot = (Get-Location).Path
$composePath = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $ComposeFile))

if (-not (Test-Path $composePath)) {
    throw "Compose file not found: $composePath"
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$runId = "${ScenarioId}_${timestamp}"
if ($RunIdOverride) {
    if ($RunIdOverride -notmatch '^[A-Za-z0-9_-]+$') { throw "Invalid run ID" }
    $runId = $RunIdOverride
}

$runDir = [System.IO.Path]::GetFullPath(
    (Join-Path $repoRoot (Join-Path $CaptureRoot $runId))
)

if (Test-Path $runDir) { throw "Run directory already exists: $runDir" }
New-Item -ItemType Directory $runDir | Out-Null

$pcapPath = Join-Path $runDir "traffic.pcap"
$processPath = Join-Path $runDir "process_state.csv"
$modbusCsvPath = Join-Path $runDir "modbus_packets.csv"
$labeledCsvPath = Join-Path $runDir "modbus_packets_labeled.csv"
$groundTruthPath = Join-Path $runDir "ground_truth.jsonl"
$manifestPath = Join-Path $runDir "manifest.yaml"
$attackStatsPath = Join-Path $runDir "attack_stats.json"
$labelSummaryPath = Join-Path $runDir "label_summary.json"

$totalDuration = $WarmupSeconds + $AttackSeconds + $RecoverySeconds

Write-Host ""
Write-Host "====================================================="
Write-Host " ICS Attack Dataset Lab - Modbus Recon Run v2"
Write-Host "====================================================="
Write-Host "Run ID       : $runId"
Write-Host "Warmup       : $WarmupSeconds sec"
Write-Host "Attack       : $AttackSeconds sec"
Write-Host "Recovery     : $RecoverySeconds sec"
Write-Host "Attack rate  : $RequestsPerSecond cycles/sec"
Write-Host "Output       : $runDir"
Write-Host ""

# -------------------------------------------------------------------
# Resolve Aloha containers/network/image.
# -------------------------------------------------------------------
$plcContainer = (
    & docker compose -f $composePath ps -q aloha-plc
).Trim()

$hmiContainer = (
    & docker compose -f $composePath ps -q aloha-hmi
).Trim()

if ([string]::IsNullOrWhiteSpace($plcContainer)) {
    throw "aloha-plc is not running."
}
if ([string]::IsNullOrWhiteSpace($hmiContainer)) {
    throw "aloha-hmi is not running."
}

$hmiImage = (& docker inspect $hmiContainer --format '{{.Config.Image}}').Trim()

$networkName = (& docker inspect $plcContainer --format `
    '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}').Trim()

if ([string]::IsNullOrWhiteSpace($networkName)) {
    throw "Could not resolve the Aloha Docker network."
}

$alohaPath = Split-Path $composePath -Parent
$alohaCommit = (& git -C $alohaPath rev-parse HEAD).Trim()

# -------------------------------------------------------------------
# Start attacker as a persistent container so its identity is recorded.
# -------------------------------------------------------------------
$attackerContainer = (
    "icslab-attacker-" + $runId.ToLower() -replace '[^a-z0-9_.-]', '-'
)

Write-Host "[1/7] Creating persistent attacker container..."

& docker run -d `
    --name $attackerContainer `
    --network $networkName `
    --entrypoint sh `
    -v "${repoRoot}:/workspace" `
    $hmiImage `
    -c "while true; do sleep 3600; done" | Out-Null

if ($LASTEXITCODE -ne 0) {
    throw "Failed to start attacker container."
}

# Resolve attacker IP via JSON instead of Docker Go templates.
# This is robust when the Docker network name contains characters like '-'.
$attackerInspectRaw = & docker inspect $attackerContainer
if ($LASTEXITCODE -ne 0) {
    & docker rm -f $attackerContainer | Out-Null
    throw "Could not inspect attacker container."
}

$attackerInspect = $attackerInspectRaw | ConvertFrom-Json
$networkProperty = $attackerInspect[0].NetworkSettings.Networks.PSObject.Properties[$networkName]

if ($null -eq $networkProperty) {
    & docker rm -f $attackerContainer | Out-Null
    throw "Attacker container is not attached to expected network: $networkName"
}

$attackerIp = [string]$networkProperty.Value.IPAddress

if ([string]::IsNullOrWhiteSpace($attackerIp)) {
    & docker rm -f $attackerContainer | Out-Null
    throw "Could not determine attacker IP."
}

Write-Host "      Attacker IP: $attackerIp"

# -------------------------------------------------------------------
# Ground truth run start.
# -------------------------------------------------------------------
$startUtc = Get-UtcIso

@{
    timestamp_utc = $startUtc
    event = "run_start"
    run_id = $runId
    scenario_id = $ScenarioId
    protocol = "modbus_tcp"
    phase = "warmup"
    attack_active = $false
    attacker_ip = $attackerIp
} |
    ConvertTo-Json -Compress |
    Set-Content -Path $groundTruthPath -Encoding utf8

# -------------------------------------------------------------------
# Start capture.
# -------------------------------------------------------------------
$captureContainer = (
    "icslab-capture-" + $runId.ToLower() -replace '[^a-z0-9_.-]', '-'
)

Write-Host "[2/7] Starting PCAP capture..."

& docker run --rm -d `
    --name $captureContainer `
    --network "container:$plcContainer" `
    -v "${runDir}:/captures" `
    $NetshootImage `
    tcpdump -i any -nn -s 0 -U `
    -w /captures/traffic.pcap `
    "tcp port $ModbusPort" | Out-Null

if ($LASTEXITCODE -ne 0) {
    & docker rm -f $attackerContainer | Out-Null
    throw "Failed to start packet capture."
}

Start-Sleep -Seconds 2

# -------------------------------------------------------------------
# Start process-state recorder.
# -------------------------------------------------------------------
Write-Host "[3/7] Starting process-state recorder..."

$recorderScript = Join-Path $repoRoot "scripts\record_process_state.ps1"

$processJob = Start-Job -ScriptBlock {
    param(
        $ScriptPath,
        $OutputPath,
        $Duration,
        $Compose,
        $Port,
        $RecorderName
    )

    & powershell.exe `
        -NoProfile `
        -ExecutionPolicy Bypass `
        -File $ScriptPath `
        -Output $OutputPath `
        -DurationSeconds $Duration `
        -IntervalSeconds 1 `
        -ComposeFile $Compose `
        -HmiService "aloha-hmi" `
        -PlcHost "aloha-plc" `
        -PlcPort $Port `
        -ContainerName $RecorderName
    if ($LASTEXITCODE -ne 0) { throw "Process recorder failed" }
} -ArgumentList `
    $recorderScript,
    $processPath,
    $totalDuration,
    $composePath,
    $ModbusPort,
    $RecorderContainer

try {
    # Warmup
    Write-Host "[4/7] Warmup: $WarmupSeconds sec..."
    Start-Sleep -Seconds $WarmupSeconds

    Write-Host "[5/7] Running controlled read-only reconnaissance..."

    $attackOutput = & docker exec `
        $attackerContainer `
        python3 /workspace/scripts/modbus_recon.py `
        --host aloha-plc `
        --port $ModbusPort `
        --unit-id 1 `
        --duration $AttackSeconds `
        --rate $RequestsPerSecond

    if ($LASTEXITCODE -ne 0) {
        throw "Reconnaissance execution failed."
    }

    $attackOutput | Set-Content -Path $attackStatsPath -Encoding utf8

    $attackStats = Get-Content $attackStatsPath -Raw | ConvertFrom-Json
    $attackStartUtc = [string]$attackStats.started_utc
    $attackEndUtc = [string]$attackStats.ended_utc

    Append-JsonLine -Path $groundTruthPath -Object @{
        timestamp_utc = $attackStartUtc
        event = "attack_start"
        run_id = $runId
        scenario_id = $ScenarioId
        protocol = "modbus_tcp"
        phase = "attack"
        attack_active = $true
        attacker_ip = $attackerIp
        target_asset = "aloha-plc"
        attack_family = "reconnaissance"
        attack_type = "unauthorized_read"
        expected_process_impact = "none"
    }

    Append-JsonLine -Path $groundTruthPath -Object @{
        timestamp_utc = $attackEndUtc
        event = "attack_end"
        run_id = $runId
        scenario_id = $ScenarioId
        protocol = "modbus_tcp"
        phase = "recovery"
        attack_active = $false
        attacker_ip = $attackerIp
        target_asset = "aloha-plc"
        attack_family = "reconnaissance"
        attack_type = "unauthorized_read"
        expected_process_impact = "none"
    }

    Write-Host "      Recovery: $RecoverySeconds sec..."
    Start-Sleep -Seconds $RecoverySeconds
}
finally {
    Write-Host "      Waiting for process recorder..."
    Wait-Job $processJob | Out-Null
    $recorderFailed = $processJob.State -eq "Failed"
    Receive-Job $processJob -ErrorAction Continue | Out-Host
    Remove-Job $processJob -Force

    Write-Host "      Stopping capture..."
    & docker stop $captureContainer | Out-Null

    Write-Host "      Removing attacker container..."
    & docker rm -f $attackerContainer | Out-Null
}

if ($recorderFailed) { throw "Process recorder failed; dataset is incomplete" }

$endUtc = Get-UtcIso

Append-JsonLine -Path $groundTruthPath -Object @{
    timestamp_utc = $endUtc
    event = "run_end"
    run_id = $runId
    scenario_id = $ScenarioId
    protocol = "modbus_tcp"
    phase = "complete"
    attack_active = $false
    attacker_ip = $attackerIp
}

# -------------------------------------------------------------------
# Extract Modbus application-layer fields.
# -------------------------------------------------------------------
Write-Host "[6/7] Extracting Modbus application-layer fields..."

& (Join-Path $repoRoot "scripts\extract_modbus.ps1") `
    -Pcap $pcapPath `
    -Output $modbusCsvPath `
    -ModbusPort $ModbusPort `
    -Image $NetshootImage

if ($LASTEXITCODE -ne 0) {
    throw "Modbus extraction failed."
}

# -------------------------------------------------------------------
# Packet-level application-layer labels.
# -------------------------------------------------------------------
Write-Host "[7/7] Applying packet-level attack labels..."

& python `
    (Join-Path $repoRoot "scripts\label_modbus_packets.py") `
    --input $modbusCsvPath `
    --ground-truth $groundTruthPath `
    --output $labeledCsvPath `
    --summary $labelSummaryPath

if ($LASTEXITCODE -ne 0) {
    throw "Packet labeling failed."
}

$pcapBytes = (Get-Item $pcapPath).Length
$processSamples = [Math]::Max(
    0,
    ((Get-Content $processPath | Measure-Object -Line).Lines - 1)
)
$modbusRows = [Math]::Max(
    0,
    ((Get-Content $modbusCsvPath | Measure-Object -Line).Lines - 1)
)

$labelSummary = Get-Content $labelSummaryPath -Raw | ConvertFrom-Json

$manifest = @"
dataset_version: "0.1-dev"
run_id: "$runId"
scenario_id: "$ScenarioId"

run_class: "attack_scenario"

labels:
  packet_binary: "normal|attack"
  attack_family: "reconnaissance"
  attack_type: "unauthorized_read"

protocol:
  name: "modbus_tcp"
  transport: "tcp"
  port: $ModbusPort
  unit_id: 1

roles:
  attacker_ip: "$attackerIp"
  target_asset: "aloha-plc"

simulator:
  name: "MITRE Aloha Water Treatment"
  git_commit: "$alohaCommit"

timing:
  start_utc: "$startUtc"
  attack_start_utc: "$attackStartUtc"
  attack_end_utc: "$attackEndUtc"
  end_utc: "$endUtc"
  warmup_seconds: $WarmupSeconds
  attack_seconds: $AttackSeconds
  recovery_seconds: $RecoverySeconds

attack:
  mode: "read_only"
  requests_per_second: $RequestsPerSecond
  expected_process_impact: "none"
  stats_file: "attack_stats.json"

fidelity_level: "cyber_physical_simulation"

artifacts:
  pcap: "traffic.pcap"
  modbus_packets: "modbus_packets.csv"
  modbus_packets_labeled: "modbus_packets_labeled.csv"
  process_state: "process_state.csv"
  ground_truth: "ground_truth.jsonl"
  attack_stats: "attack_stats.json"
  label_summary: "label_summary.json"

statistics:
  pcap_bytes: $pcapBytes
  process_samples: $processSamples
  modbus_rows: $modbusRows
  labeled_normal_rows: $($labelSummary.normal_rows)
  labeled_attack_rows: $($labelSummary.attack_rows)

ground_truth:
  label_source: "attacker_identity_plus_exact_attack_window"
"@

$manifest | Set-Content -Path $manifestPath -Encoding utf8

Write-Host ""
Write-Host "====================================================="
Write-Host " ATTACK RUN COMPLETE"
Write-Host "====================================================="
Write-Host "Run directory      : $runDir"
Write-Host "Attacker IP        : $attackerIp"
Write-Host "PCAP bytes         : $pcapBytes"
Write-Host "Process rows       : $processSamples"
Write-Host "Modbus rows        : $modbusRows"
Write-Host "Attack-labeled rows: $($labelSummary.attack_rows)"
Write-Host "Normal-labeled rows: $($labelSummary.normal_rows)"
Write-Host ""
Write-Output $runDir

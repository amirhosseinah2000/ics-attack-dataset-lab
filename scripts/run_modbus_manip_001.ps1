param(
    [int]$WarmupSeconds = 30,
    [int]$AttackSeconds = 30,
    [int]$RecoverySeconds = 30,
    [double]$ObservationIntervalSeconds = 1.0,
    [int]$InflowRate = 900,
    [int]$OutflowRate = 50,
    [int]$InitialTankLevel = 0,
    [bool]$Validate = $true,

    [string]$ScenarioId = "MODBUS-MANIP-001",
    [string]$ComposeFile = "external\aloha-water-treatment\docker-compose-example.yml",
    [string]$CaptureRoot = "captures\modbus\attack",
    [int]$ModbusPort = 5020,
    [string]$NetshootImage = "nicolaka/netshoot"
)

$ErrorActionPreference = "Stop"

function Get-UtcIso { return (Get-Date).ToUniversalTime().ToString("o") }
function Append-JsonLine {
    param([string]$Path, [hashtable]$Object)
    $Object | ConvertTo-Json -Compress | Add-Content -Path $Path -Encoding utf8
}
function Get-Sha256([string]$Path) {
    if (-not (Test-Path $Path)) { return "" }
    return (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant()
}

if ($WarmupSeconds -lt 1 -or $AttackSeconds -lt 1 -or $RecoverySeconds -lt 1) {
    throw "WarmupSeconds, AttackSeconds and RecoverySeconds must all be >= 1."
}
if ($ObservationIntervalSeconds -le 0) { throw "ObservationIntervalSeconds must be > 0." }
if ($InflowRate -le $OutflowRate) { throw "InflowRate must be greater than OutflowRate for this scenario." }
if ($InflowRate -lt 0 -or $InflowRate -gt 65535 -or $OutflowRate -lt 0 -or $OutflowRate -gt 65535) {
    throw "Flow values must fit one unsigned 16-bit Modbus register."
}
if ($InitialTankLevel -lt 0 -or $InitialTankLevel -gt 10000) {
    throw "InitialTankLevel must be between 0 and 10000."
}
if ($ModbusPort -ne 5020) {
    throw "Safety guard: this scenario is restricted to the Aloha lab on port 5020."
}

$repoRoot = (Get-Location).Path
$composePath = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $ComposeFile))
$requiredFiles = @(
    "scripts\record_process_state.ps1",
    "scripts\extract_modbus.ps1",
    "scripts\label_modbus_packets.py",
    "scripts\validate_modbus_run.py",
    "scripts\modbus_manual_overflow_lab.py",
    "scripts\reset_modbus_lab_state.py",
    "configs\scenarios\modbus\MODBUS-MANIP-001.yaml"
)

if (-not (Test-Path $composePath)) { throw "Compose file not found: $composePath" }
foreach ($rel in $requiredFiles) {
    if (-not (Test-Path (Join-Path $repoRoot $rel))) { throw "Required file missing: $rel" }
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$runId = "${ScenarioId}_${timestamp}"
$runDir = [System.IO.Path]::GetFullPath((Join-Path $repoRoot (Join-Path $CaptureRoot $runId)))
New-Item -ItemType Directory -Force $runDir | Out-Null

$pcapPath = Join-Path $runDir "traffic.pcap"
$processPath = Join-Path $runDir "process_state.csv"
$modbusCsvPath = Join-Path $runDir "modbus_packets.csv"
$labeledCsvPath = Join-Path $runDir "modbus_packets_labeled.csv"
$groundTruthPath = Join-Path $runDir "ground_truth.jsonl"
$manifestPath = Join-Path $runDir "manifest.yaml"
$attackStatsPath = Join-Path $runDir "attack_stats.json"
$labelSummaryPath = Join-Path $runDir "label_summary.json"
$validationReportPath = Join-Path $runDir "validation_report.json"
$runLogPath = Join-Path $runDir "run.log"

$totalDuration = $WarmupSeconds + $AttackSeconds + $RecoverySeconds + 8
$startUtc = Get-UtcIso

Start-Transcript -Path $runLogPath -Force | Out-Null

$attackerContainer = $null
$captureContainer = $null
$processJob = $null
$runSucceeded = $false
$networkName = $null
$hmiImage = $null
$preRunReset = $null

try {
    Write-Host ""
    Write-Host "====================================================="
    Write-Host " ICS Attack Dataset Lab - MODBUS-MANIP-001"
    Write-Host "====================================================="
    Write-Host "Run ID       : $runId"
    Write-Host "Warmup       : $WarmupSeconds sec"
    Write-Host "Attack       : $AttackSeconds sec"
    Write-Host "Recovery     : $RecoverySeconds sec"
    Write-Host "Inflow       : $InflowRate"
    Write-Host "Outflow      : $OutflowRate"
    Write-Host "Initial tank : $InitialTankLevel"
    Write-Host "Output       : $runDir"
    Write-Host "Safety scope : local Docker Digital Twin only"
    Write-Host ""

    Write-Host "[1/9] Resolving Aloha lab..."
    $plcContainer = (& docker compose -f $composePath ps -q aloha-plc).Trim()
    $hmiContainer = (& docker compose -f $composePath ps -q aloha-hmi).Trim()
    if ([string]::IsNullOrWhiteSpace($plcContainer)) { throw "aloha-plc is not running." }
    if ([string]::IsNullOrWhiteSpace($hmiContainer)) { throw "aloha-hmi is not running." }

    $hmiImage = (& docker inspect $hmiContainer --format '{{.Config.Image}}').Trim()
    $networkName = (& docker inspect $plcContainer --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}').Trim()
    if ([string]::IsNullOrWhiteSpace($networkName)) { throw "Could not resolve Aloha Docker network." }

    $alohaPath = Split-Path $composePath -Parent
    $alohaCommit = "unknown"
    try { $alohaCommit = (& git -C $alohaPath rev-parse HEAD 2>$null).Trim() } catch {}

    Write-Host "      Network: $networkName"
    Write-Host "      Normalizing lab state before capture..."
    $resetOutput = & docker run --rm `
        --network $networkName `
        --entrypoint python3 `
        -v "${repoRoot}:/workspace" `
        $hmiImage `
        /workspace/scripts/reset_modbus_lab_state.py `
        --tank-level $InitialTankLevel
    if ($LASTEXITCODE -ne 0) {
        throw "Pre-run lab-state reset failed: $($resetOutput -join ' ')"
    }
    $preRunReset = ($resetOutput -join "`n") | ConvertFrom-Json
    if (-not [bool]$preRunReset.success) {
        throw "Pre-run lab-state reset was not verified."
    }
    Write-Host "      Canonical baseline verified: tank=$($preRunReset.after.tank_level), controls idle"

    Write-Host "[2/9] Creating isolated attacker identity..."
    $attackerContainer = ("icslab-attacker-" + $runId.ToLower() -replace '[^a-z0-9_.-]', '-')
    & docker run -d `
        --name $attackerContainer `
        --network $networkName `
        --entrypoint sh `
        -v "${repoRoot}:/workspace" `
        $hmiImage `
        -c "while true; do sleep 3600; done" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to start attacker container." }

    $attackerInspectRaw = & docker inspect $attackerContainer
    if ($LASTEXITCODE -ne 0) { throw "Could not inspect attacker container." }
    $attackerInspect = $attackerInspectRaw | ConvertFrom-Json
    $networkProperty = $attackerInspect[0].NetworkSettings.Networks.PSObject.Properties[$networkName]
    if ($null -eq $networkProperty) { throw "Attacker is not attached to expected lab network: $networkName" }
    $attackerIp = [string]$networkProperty.Value.IPAddress
    if ([string]::IsNullOrWhiteSpace($attackerIp)) { throw "Could not determine attacker IP." }
    Write-Host "      Attacker IP: $attackerIp"

    @{
        timestamp_utc = $startUtc
        event = "run_start"
        run_id = $runId
        scenario_id = $ScenarioId
        protocol = "modbus_tcp"
        phase = "warmup"
        attack_active = $false
        attacker_ip = $attackerIp
        target_asset = "aloha-plc"
        data_origin = "local_software_digital_twin"
    } | ConvertTo-Json -Compress | Set-Content -Path $groundTruthPath -Encoding utf8

    Write-Host "[3/9] Starting PCAP capture..."
    $captureContainer = ("icslab-capture-" + $runId.ToLower() -replace '[^a-z0-9_.-]', '-')
    & docker run --rm -d `
        --name $captureContainer `
        --network "container:$plcContainer" `
        -v "${runDir}:/captures" `
        $NetshootImage `
        tcpdump -i any -nn -s 0 -U -w /captures/traffic.pcap "tcp port $ModbusPort" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to start packet capture." }
    Start-Sleep -Seconds 2

    Write-Host "[4/9] Starting process-state recorder..."
    $recorderScript = Join-Path $repoRoot "scripts\record_process_state.ps1"
    $processJob = Start-Job -ScriptBlock {
        param($ScriptPath, $OutputPath, $Duration, $Compose, $Port)
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath `
            -Output $OutputPath `
            -DurationSeconds $Duration `
            -IntervalSeconds 1 `
            -ComposeFile $Compose `
            -HmiService "aloha-hmi" `
            -PlcHost "aloha-plc" `
            -PlcPort $Port
    } -ArgumentList $recorderScript, $processPath, $totalDuration, $composePath, $ModbusPort

    Write-Host "[5/9] Warmup: $WarmupSeconds sec..."
    Start-Sleep -Seconds $WarmupSeconds

    Write-Host "[6/9] Executing bounded local manipulation scenario..."
    $attackOutput = & docker exec $attackerContainer python3 /workspace/scripts/modbus_manual_overflow_lab.py `
        --duration $AttackSeconds `
        --sample-interval $ObservationIntervalSeconds `
        --inflow-rate $InflowRate `
        --outflow-rate $OutflowRate
    $attackExitCode = $LASTEXITCODE

    if ($null -eq $attackOutput -or [string]::IsNullOrWhiteSpace(($attackOutput -join "`n"))) {
        throw "Scenario script returned no JSON stats."
    }
    $attackOutput | Set-Content -Path $attackStatsPath -Encoding utf8
    $attackStats = Get-Content $attackStatsPath -Raw | ConvertFrom-Json

    $attackStartUtc = [string]$attackStats.attack_started_utc
    $attackEndUtc = [string]$attackStats.attack_ended_utc
    if ([string]::IsNullOrWhiteSpace($attackStartUtc) -or [string]::IsNullOrWhiteSpace($attackEndUtc)) {
        throw "Scenario did not provide a precise attack window."
    }

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
        attack_family = "process_manipulation"
        attack_type = "manual_overflow"
        data_origin = "local_software_digital_twin"
        baseline = $attackStats.baseline
        requested_values = $attackStats.requested_values
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
        attack_family = "process_manipulation"
        attack_type = "manual_overflow"
        data_origin = "local_software_digital_twin"
        restored = [bool]$attackStats.restored
        restore_errors = $attackStats.restore_errors
    }

    if ($attackExitCode -ne 0) { throw "Scenario execution failed with exit code $attackExitCode. See attack_stats.json." }
    if (-not [bool]$attackStats.restored) { throw "Restore was not confirmed; refusing to continue as a valid run." }

    Write-Host "      Restore confirmed: YES"
    Write-Host "      Recovery: $RecoverySeconds sec..."
    Start-Sleep -Seconds $RecoverySeconds

    Write-Host "[7/9] Finalizing capture and process recording..."
    if ($null -ne $processJob) {
        Wait-Job $processJob | Out-Null
        Receive-Job $processJob | Out-Host
        Remove-Job $processJob -Force
        $processJob = $null
    }
    if ($null -ne $captureContainer) {
        & docker stop $captureContainer | Out-Null
        $captureContainer = $null
    }

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
        target_asset = "aloha-plc"
    }

    Write-Host "[8/9] Extracting and labeling packets..."
    & (Join-Path $repoRoot "scripts\extract_modbus.ps1") `
        -Pcap $pcapPath -Output $modbusCsvPath -ModbusPort $ModbusPort -Image $NetshootImage
    if ($LASTEXITCODE -ne 0) { throw "Modbus extraction failed." }

    & python (Join-Path $repoRoot "scripts\label_modbus_packets.py") `
        --input $modbusCsvPath `
        --ground-truth $groundTruthPath `
        --output $labeledCsvPath `
        --summary $labelSummaryPath
    if ($LASTEXITCODE -ne 0) { throw "Packet labeling failed." }

    $labelSummary = Get-Content $labelSummaryPath -Raw | ConvertFrom-Json
    $pcapBytes = (Get-Item $pcapPath).Length
    $processSamples = [Math]::Max(0, ((Get-Content $processPath | Measure-Object -Line).Lines - 1))
    $modbusRows = [Math]::Max(0, ((Get-Content $modbusCsvPath | Measure-Object -Line).Lines - 1))

    $initialTank = $attackStats.observations.initial_tank_level
    $maxTank = $attackStats.observations.max_tank_level
    $finalTank = $attackStats.observations.final_tank_level_before_restore
    $overflowSeen = [bool]$attackStats.observations.overflow_alarm_seen
    $restored = [bool]$attackStats.restored

    $manifest = @"
dataset_schema_version: "0.2"
run_id: "$runId"
scenario_id: "$ScenarioId"
created_at_utc: "$startUtc"
data_origin: "local_software_digital_twin"
safety_scope: "docker_internal_only"

protocol:
  name: "modbus_tcp"
  transport: "tcp"
  port: $ModbusPort
  unit_id: 1

labels:
  packet_binary: "normal|attack"
  attack_family: "process_manipulation"
  attack_type: "manual_overflow"
  rule: "attacker_identity_plus_exact_attack_window"

roles:
  attacker_ip: "$attackerIp"
  target_asset: "aloha-plc"

simulator:
  name: "MITRE Aloha Water Treatment"
  git_commit: "$alohaCommit"

process_map:
  coil_pump_switch: 1
  coil_inflow_mode: 5
  hr_tank_level: 0
  hr_inflow_rate: 6
  hr_outflow_rate: 7

parameters:
  warmup_seconds: $WarmupSeconds
  attack_seconds: $AttackSeconds
  recovery_seconds: $RecoverySeconds
  observation_interval_seconds: $ObservationIntervalSeconds
  requested_inflow_rate: $InflowRate
  requested_outflow_rate: $OutflowRate
  initial_tank_level: $InitialTankLevel

attack_window:
  start_utc: "$attackStartUtc"
  end_utc: "$attackEndUtc"

precondition:
  reset_before_capture: true
  requested_initial_tank_level: $InitialTankLevel
  verified_initial_tank_level: $($preRunReset.after.tank_level)

restore:
  required: true
  scope: "control_points_only"
  successful: $($restored.ToString().ToLower())

process_observation:
  initial_tank_level: $initialTank
  max_tank_level: $maxTank
  final_tank_level_before_restore: $finalTank
  overflow_alarm_seen: $($overflowSeen.ToString().ToLower())

statistics:
  pcap_bytes: $pcapBytes
  process_samples: $processSamples
  modbus_rows: $modbusRows
  normal_rows: $($labelSummary.normal_rows)
  attack_rows: $($labelSummary.attack_rows)
  attacker_to_target_rows: $($labelSummary.attacker_to_target_rows)
  target_to_attacker_rows: $($labelSummary.target_to_attacker_rows)
  background_rows_during_attack_window: $($labelSummary.background_rows_during_attack_window)

artifacts:
  traffic_pcap:
    path: "traffic.pcap"
    sha256: "$(Get-Sha256 $pcapPath)"
  process_state:
    path: "process_state.csv"
    sha256: "$(Get-Sha256 $processPath)"
  modbus_packets:
    path: "modbus_packets.csv"
    sha256: "$(Get-Sha256 $modbusCsvPath)"
  modbus_packets_labeled:
    path: "modbus_packets_labeled.csv"
    sha256: "$(Get-Sha256 $labeledCsvPath)"
  ground_truth:
    path: "ground_truth.jsonl"
    sha256: "$(Get-Sha256 $groundTruthPath)"
  attack_stats:
    path: "attack_stats.json"
    sha256: "$(Get-Sha256 $attackStatsPath)"
  label_summary:
    path: "label_summary.json"
    sha256: "$(Get-Sha256 $labelSummaryPath)"
"@
    $manifest | Set-Content -Path $manifestPath -Encoding utf8

    Write-Host "[9/9] Validation..."
    $validationStatus = "SKIPPED"
    if ($Validate) {
        & python (Join-Path $repoRoot "scripts\validate_modbus_run.py") --run-dir $runDir --report $validationReportPath
        if ($LASTEXITCODE -ne 0) { throw "Validation failed. See validation_report.json." }
        $validationStatus = "PASS"
    }

    $runSucceeded = $true
    Write-Host ""
    Write-Host "====================================================="
    Write-Host " MODBUS-MANIP-001 RUN COMPLETE"
    Write-Host "====================================================="
    Write-Host "Run directory      : $runDir"
    Write-Host "Attacker IP        : $attackerIp"
    Write-Host "PCAP bytes         : $pcapBytes"
    Write-Host "Process rows       : $processSamples"
    Write-Host "Modbus rows        : $modbusRows"
    Write-Host "Normal rows        : $($labelSummary.normal_rows)"
    Write-Host "Attack rows        : $($labelSummary.attack_rows)"
    Write-Host "Background@Attack  : $($labelSummary.background_rows_during_attack_window)"
    Write-Host "Initial tank       : $initialTank"
    Write-Host "Max tank           : $maxTank"
    Write-Host "Restored           : $restored"
    Write-Host "Validation         : $validationStatus"
    Write-Host "====================================================="
    Write-Output $runDir
}
finally {
    if ($null -ne $processJob) {
        try { Stop-Job $processJob -ErrorAction SilentlyContinue | Out-Null } catch {}
        try { Receive-Job $processJob -ErrorAction SilentlyContinue | Out-Host } catch {}
        try { Remove-Job $processJob -Force -ErrorAction SilentlyContinue } catch {}
    }
    if ($null -ne $captureContainer) {
        try { & docker stop $captureContainer | Out-Null } catch {}
    }
    if ($null -ne $attackerContainer) {
        try { & docker rm -f $attackerContainer | Out-Null } catch {}
    }

    # Out-of-band lab cleanup. Capture has already been stopped above, so this
    # traffic is not part of the dataset.
    if (-not [string]::IsNullOrWhiteSpace([string]$networkName) -and
        -not [string]::IsNullOrWhiteSpace([string]$hmiImage)) {
        try {
            $cleanupOutput = & docker run --rm `
                --network $networkName `
                --entrypoint python3 `
                -v "${repoRoot}:/workspace" `
                $hmiImage `
                /workspace/scripts/reset_modbus_lab_state.py `
                --tank-level $InitialTankLevel
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Lab baseline restored after run."
            } else {
                Write-Warning "Post-run lab reset failed. Next run will re-check the baseline."
            }
        } catch {
            Write-Warning "Post-run lab reset failed: $($_.Exception.Message)"
        }
    }

    try { Stop-Transcript | Out-Null } catch {}
    if (-not $runSucceeded) {
        Write-Host "Run did not complete successfully. Artifacts were preserved for diagnosis."
        Write-Host "Run directory: $runDir"
    }
}

param(
    [Parameter(Mandatory = $true)]
    [string]$Output,

    [int]$DurationSeconds = 60,

    [double]$IntervalSeconds = 1.0,

    [string]$ComposeFile = "external\aloha-water-treatment\docker-compose-example.yml",

    [string]$HmiService = "aloha-hmi",

    [string]$PlcHost = "aloha-plc",

    [int]$PlcPort = 5020
)

$ErrorActionPreference = "Stop"

$outputPath = [System.IO.Path]::GetFullPath($Output)
$outputDir = Split-Path $outputPath -Parent
New-Item -ItemType Directory -Force $outputDir | Out-Null

$python = @'
import csv
import sys
import time
from datetime import datetime, timezone

from pymodbus.client import ModbusTcpClient

duration = float(sys.argv[1])
interval = float(sys.argv[2])
host = sys.argv[3]
port = int(sys.argv[4])

fields = [
    "sample_index",
    "timestamp_utc",
    "timestamp_epoch",
    "tank_level",
    "emergency_stop",
    "pump_switch",
    "pump_status",
    "inflow_valve",
    "outflow_valve",
    "inflow_rate",
    "outflow_rate",
    "inflow_mode",
    "overflow_alarm",
    "coil_emergency_stop",
    "coil_pump_switch",
    "coil_pump_status",
    "coil_inflow_valve",
    "coil_outflow_valve",
    "coil_inflow_mode",
    "coil_overflow_alarm",
    "coil_low_level_alarm",
    "coil_operator_error_alarm",
    "read_ok",
    "error",
]

writer = csv.writer(sys.stdout, lineterminator="\n")
writer.writerow(fields)
sys.stdout.flush()

client = ModbusTcpClient(host, port=port, timeout=2.0)

if not client.connect():
    print("Could not connect to Modbus PLC", file=sys.stderr)
    sys.exit(2)

start = time.monotonic()
sample_index = 0

try:
    while True:
        cycle_start = time.monotonic()
        now = datetime.now(timezone.utc)
        epoch = time.time()

        regs = [""] * 10
        coils = [""] * 9
        read_ok = True
        errors = []

        try:
            rr = client.read_holding_registers(
                address=0,
                count=10,
                device_id=1,
            )
            if rr.isError():
                read_ok = False
                errors.append(f"holding_registers:{rr}")
            else:
                regs = list(rr.registers[:10])
        except Exception as exc:
            read_ok = False
            errors.append(
                f"holding_registers:{type(exc).__name__}:{exc}"
            )

        try:
            cr = client.read_coils(
                address=0,
                count=9,
                device_id=1,
            )
            if cr.isError():
                read_ok = False
                errors.append(f"coils:{cr}")
            else:
                coils = [int(bool(v)) for v in cr.bits[:9]]
        except Exception as exc:
            read_ok = False
            errors.append(f"coils:{type(exc).__name__}:{exc}")

        row = [
            sample_index,
            now.isoformat().replace("+00:00", "Z"),
            f"{epoch:.9f}",
            *regs,
            *coils,
            int(read_ok),
            " | ".join(errors),
        ]

        writer.writerow(row)
        sys.stdout.flush()

        sample_index += 1
        elapsed = time.monotonic() - start
        if elapsed >= duration:
            break

        cycle_elapsed = time.monotonic() - cycle_start
        time.sleep(max(0.0, interval - cycle_elapsed))

finally:
    client.close()
'@

Write-Host "Recording process state..."
Write-Host "Output   : $outputPath"
Write-Host "Duration : $DurationSeconds sec"
Write-Host "Interval : $IntervalSeconds sec"
Write-Host ""

$stderrPath = "$outputPath.stderr.txt"

# Feed the Python program over STDIN instead of passing it through `python3 -c`.
# This avoids PowerShell/Docker quote mangling on Windows.
$rows = $python | & docker compose `
    -f $ComposeFile `
    exec -T $HmiService `
    python3 - `
    "$DurationSeconds" `
    "$IntervalSeconds" `
    "$PlcHost" `
    "$PlcPort" 2> $stderrPath

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "Recorder failed. stderr:"
    if (Test-Path $stderrPath) {
        Get-Content $stderrPath
    }
    throw "Process-state recorder failed."
}

$rows | Set-Content -Path $outputPath -Encoding utf8

if ((Test-Path $stderrPath) -and ((Get-Item $stderrPath).Length -eq 0)) {
    Remove-Item $stderrPath -Force
}

$lineCount = (Get-Content $outputPath | Measure-Object -Line).Lines
$dataRows = [Math]::Max(0, $lineCount - 1)

Write-Host ""
Write-Host "Done."
Write-Host "Samples : $dataRows"
Write-Host "CSV     : $outputPath"

param(
    [Parameter(Mandatory = $true)]
    [string]$Pcap,

    [string]$Output,

    [int]$ModbusPort = 5020,

    [string]$Image = "nicolaka/netshoot"
)

$ErrorActionPreference = "Stop"

$pcapItem = Get-Item $Pcap
$runDir = $pcapItem.Directory.FullName
$pcapName = $pcapItem.Name

if (-not $Output) {
    $Output = Join-Path $runDir "modbus_packets.csv"
}

$outputItem = [System.IO.Path]::GetFullPath($Output)
$outputDir = Split-Path $outputItem -Parent
$outputName = Split-Path $outputItem -Leaf

if ($outputDir -ne $runDir) {
    throw "For this first version, Output must be inside the same directory as the PCAP."
}

Write-Host "PCAP        : $($pcapItem.FullName)"
Write-Host "Output      : $outputItem"
Write-Host "Modbus port : $ModbusPort"
Write-Host ""

# Discover the fields supported by the TShark version in the Docker image.
$fieldCatalog = docker run --rm $Image tshark -G fields
if ($LASTEXITCODE -ne 0) {
    throw "Failed to query TShark field catalog."
}

$supported = New-Object 'System.Collections.Generic.HashSet[string]'

foreach ($line in $fieldCatalog) {
    $parts = $line -split "`t"
    if ($parts.Count -ge 3 -and $parts[0] -eq "F") {
        [void]$supported.Add($parts[2])
    }
}

# Keep this list broad. Unsupported fields are skipped automatically,
# which makes the extractor portable across TShark versions.
$candidates = @(
    "frame.number",
    "frame.time_epoch",
    "frame.len",

    "ip.src",
    "ip.dst",

    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "tcp.seq",
    "tcp.ack",
    "tcp.len",
    "tcp.payload",

    "mbtcp.trans_id",
    "mbtcp.prot_id",
    "mbtcp.len",
    "mbtcp.unit_id",

    "modbus.func_code",
    "modbus.reference_num",
    "modbus.word_cnt",
    "modbus.byte_cnt",
    "modbus.regnum16",
    "modbus.regval_uint16",
    "modbus.regval_int16",
    "modbus.exception_code",
    "modbus.data"
)

$selected = @()
foreach ($field in $candidates) {
    if ($supported.Contains($field)) {
        $selected += $field
    }
}

$coreFields = @(
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "mbtcp.trans_id",
    "mbtcp.unit_id",
    "modbus.func_code"
)

$missingCore = @()
foreach ($field in $coreFields) {
    if (-not $supported.Contains($field)) {
        $missingCore += $field
    }
}

if ($missingCore.Count -gt 0) {
    throw "Required TShark fields are missing: $($missingCore -join ', ')"
}

Write-Host "Selected fields:"
$selected | ForEach-Object { Write-Host "  - $_" }
Write-Host ""

$args = @(
    "run", "--rm",
    "-v", "${runDir}:/data",
    $Image,
    "tshark",
    "-r", "/data/$pcapName",
    "-d", "tcp.port==$ModbusPort,mbtcp",
    "-Y", "mbtcp || modbus",
    "-T", "fields",
    "-E", "header=y",
    "-E", "separator=,",
    "-E", "quote=d",
    "-E", "occurrence=a"
)

foreach ($field in $selected) {
    $args += @("-e", $field)
}

# Redirect stdout to the CSV file while preserving UTF-8 text.
$csv = & docker @args
if ($LASTEXITCODE -ne 0) {
    throw "TShark extraction failed."
}

$csv | Set-Content -Path $outputItem -Encoding utf8

$rowCount = (Get-Content $outputItem | Measure-Object -Line).Lines - 1

Write-Host ""
Write-Host "Done."
Write-Host "Rows        : $rowCount"
Write-Host "CSV         : $outputItem"

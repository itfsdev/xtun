# Register the split tunnel driver as the XtunSplitTunnel service and start it.
# CTest runs this script before the tests that need the driver (fixture SplitDriver).
# xtun only checks and starts this service; for apps, their installer registers it the same way.
param(
    # Folder with mullvad-split-tunnel.sys from the Conan package.
    [Parameter(Mandatory = $true)][string]$Source,
    # Only administrators can write here, so nobody else can replace the driver file.
    [string]$Directory = (Join-Path $env:ProgramFiles "XtunTests")
)

$ErrorActionPreference = "Stop"

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "skipped: installing a driver requires Administrator"
    # CTest treats this exit code as a skip (SKIP_RETURN_CODE).
    exit 77
}

$service = "XtunSplitTunnel"
$start = Get-Date

# A registration that already exists is used as is.
if (-not (Get-Service -Name $service -ErrorAction SilentlyContinue)) {
    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    foreach ($extension in "sys", "cat", "inf") {
        Copy-Item -LiteralPath (Join-Path $Source "mullvad-split-tunnel.$extension") -Destination $Directory -Force
    }
    # The same settings that WindowsSplitTunnel::open() checks: kernel driver, started on demand.
    & sc.exe create $service type= kernel start= demand binPath= (Join-Path $Directory "mullvad-split-tunnel.sys")
    if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed: $LASTEXITCODE" }
}

# xtun starts the service itself. Start it here to see driver load errors before the tests.
& sc.exe start $service

# 1056 means the service is already running.
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1056) {
    & sc.exe query $service
    # Code integrity events explain why Windows refused to load the driver, for example a signature problem.
    Get-WinEvent -FilterHashtable @{ LogName = "Microsoft-Windows-CodeIntegrity/Operational"; StartTime = $start } `
        -ErrorAction SilentlyContinue | Select-Object -First 10 | Format-List TimeCreated, Id, Message
    throw "sc.exe start failed: $LASTEXITCODE"
}
& sc.exe query $service

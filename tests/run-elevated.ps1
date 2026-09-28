[CmdletBinding()]
param([switch]$Engine)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = Split-Path -Parent $PSScriptRoot
$testName = if ($Engine) { 'windows_engine_integration.exe' } else { 'windows_layout_integration.exe' }
$source = Join-Path $projectRoot ("build\integration\" + $testName)
if (-not (Test-Path -LiteralPath $source)) {
    throw 'Build and run .\build.ps1 -IntegrationOnly first.'
}

# Never elevate the mutable linker output. Consent may remain open while the
# developer rebuilds. Keep a distinct copy and report directory for each run.
# No policy changes, signing exemptions, shell payloads, or persistent tasks.
$expectedHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
$runId = [Guid]::NewGuid().ToString('N')
$runDir = Join-Path $projectRoot ("build\elevation\" + $runId)
New-Item -ItemType Directory -Path $runDir -ErrorAction Stop | Out-Null
$testPath = Join-Path $runDir $testName
Copy-Item -LiteralPath $source -Destination $testPath -ErrorAction Stop
if ((Get-FileHash -LiteralPath $testPath -Algorithm SHA256).Hash -ne $expectedHash) {
    throw 'Executable changed during staging; refusing to elevate.'
}

Write-Host "Staged test: $testPath"
Write-Host "SHA256: $expectedHash"
Write-Host 'Windows will request UAC consent for this unsigned test executable.'
$start = New-Object System.Diagnostics.ProcessStartInfo
$start.FileName = $testPath
$start.Arguments = '--elevated-report'
$start.WorkingDirectory = $runDir
$start.UseShellExecute = $true
$start.Verb = 'runas'
$test = [System.Diagnostics.Process]::Start($start)
if ($null -eq $test) { throw 'Elevated process did not start.' }
try {
    Write-Host "Elevated test PID=$($test.Id)"
    if (-not $test.WaitForExit(30000)) {
        throw 'Elevated tests did not finish within 30 seconds. No passing result accepted.'
    }
    $report = Join-Path $runDir 'windows-elevated-results.txt'
    if (-not (Test-Path -LiteralPath $report)) {
        throw "Elevated report absent; process exit=$($test.ExitCode)."
    }
    Get-Content -LiteralPath $report
    Write-Host "Report: $report"
    if ((Get-FileHash -LiteralPath $testPath -Algorithm SHA256).Hash -ne $expectedHash) {
        throw 'Executable changed during elevated run; result rejected.'
    }
    if ($test.ExitCode -ne 0) { throw "Elevated tests failed: exit=$($test.ExitCode)." }
    Write-Host 'Elevated tests completed successfully.'
} finally { $test.Dispose() }

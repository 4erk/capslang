[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Exe)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Exe = (Resolve-Path -LiteralPath $Exe).Path
function Invoke-Guard([string]$Arguments) {
    $p = New-Object Diagnostics.Process
    $p.StartInfo.FileName = $Exe
    $p.StartInfo.Arguments = $Arguments
    $p.StartInfo.UseShellExecute = $false
    $p.StartInfo.CreateNoWindow = $true
    $p.StartInfo.RedirectStandardOutput = $true
    try {
        if (-not $p.Start()) { throw 'Start failed' }
        $output = $p.StandardOutput.ReadToEndAsync()
        if (-not $p.WaitForExit(12000)) { throw 'Guard test timeout; watchdog remains responsible for restoration' }
        [pscustomobject]@{ Exit=$p.ExitCode; Text=$output.Result }
    } finally { $p.Dispose() }
}
function Status { (Invoke-Guard '--status').Text | ConvertFrom-Json }
function Snapshot {
    # Verify the persistent settings we promised not to touch, including sleep/display.
    [pscustomobject]@{
        Desktop = (Get-ItemProperty 'HKCU:\Control Panel\Desktop' | Select-Object ScreenSaveActive,ScreenSaveTimeOut,ScreenSaverIsSecure,'SCRNSAVE.EXE')
        Power = @(powercfg.exe /query)
    } | ConvertTo-Json -Depth 5 -Compress
}
$before = Status
if ($before.guardRunning -or -not $before.mwbRunning -or -not $before.screensaverActive -or $before.managed) {
    throw 'Test needs running MWB, an enabled unmanaged screensaver and no existing guard'
}
$settings = Snapshot
$stop = Invoke-Guard '--exercise-stop'
if ($stop.Exit -ne 0 -or $stop.Text -notmatch 'lease=1 mwb=1 error=0') { throw "Normal exercise failed: $($stop.Text) exit=$($stop.Exit)" }
$after = Status
if ($after.guardRunning -or -not $after.screensaverActive) { throw 'Normal stop did not restore screensaver' }
Write-Output 'PASS live acquire and orderly restoration'
$crash = Invoke-Guard '--exercise-crash'
if ($crash.Exit -ne 77 -or $crash.Text -notmatch 'lease=1 mwb=1 error=0') { throw "Crash exercise failed: $($crash.Text) exit=$($crash.Exit)" }
$deadline = [DateTime]::UtcNow.AddSeconds(6)
do {
    $after = Status
    if (-not $after.guardRunning -and $after.screensaverActive) { break }
    Start-Sleep -Milliseconds 100
} while ([DateTime]::UtcNow -lt $deadline)
if ($after.guardRunning -or -not $after.screensaverActive) { throw 'Watchdog did not restore screensaver after forced termination' }
Write-Output 'PASS forced parent termination and watchdog restoration'
$child = Start-Process -FilePath $Exe -PassThru
try {
    $deadline = [DateTime]::UtcNow.AddSeconds(6)
    do {
        $after = Status
        if ($after.guardRunning -and -not $after.screensaverActive) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    if (-not $after.guardRunning -or $after.screensaverActive) { throw 'Persistent guard did not acquire' }
    $duplicate = Invoke-Guard ''
    if ($duplicate.Exit -ne 183) { throw "Duplicate guard should be rejected: $($duplicate.Exit)" }
    Write-Output 'PASS singleton and persistent session override'
} finally {
    $null = Invoke-Guard '--stop'
    if (-not $child.WaitForExit(6000)) { throw 'Stop command did not complete' }
    $child.Dispose()
}
$after = Status
if ($after.guardRunning -or -not $after.screensaverActive) { throw 'CLI stop did not restore' }
if ((Snapshot) -cne $settings) { throw 'Persistent screensaver or power settings changed' }
Write-Output 'PASS CLI stop; persistent screensaver, lock, sleep and display settings unchanged'
Write-Output 'These API checks do not constitute a full idle-timeout visual test.'

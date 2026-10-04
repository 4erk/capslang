[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$SourceExe)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$SourceExe = (Resolve-Path -LiteralPath $SourceExe).Path
$destination = Join-Path $env:LOCALAPPDATA 'CapsLang\MwbSaverGuard'
$exe = Join-Path $destination 'CapsLangMwbSaverGuard.exe'
$taskName = 'CapsLang MWB Screensaver Guard'
$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing -and (@($existing.Actions).Count -ne 1 -or $existing.Actions[0].Execute -ne $exe)) {
    throw 'Task name belongs to a different command; refusing to replace it'
}
if (Test-Path -LiteralPath $exe) {
    if ((Get-FileHash $exe).Hash -ne (Get-FileHash $SourceExe).Hash) {
        throw 'A different guard binary is installed. Stop and back it up before an explicit update.'
    }
} else {
    New-Item -ItemType Directory -Force -Path $destination | Out-Null
    Copy-Item -LiteralPath $SourceExe -Destination $exe
}
if ((Get-FileHash $exe).Hash -ne (Get-FileHash $SourceExe).Hash) { throw 'Copy checksum mismatch' }
if (-not $existing) {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $action = New-ScheduledTaskAction -Execute $exe
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew `
        -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal `
        -Settings $settings -Description 'Temporarily inhibit only the screensaver while Mouse Without Borders runs in this user session; restore on exit.' | Out-Null
}
Start-ScheduledTask -TaskName $taskName
[pscustomobject]@{Path=$exe;SHA256=(Get-FileHash $exe).Hash;Task=$taskName;RunLevel='Limited'} | ConvertTo-Json

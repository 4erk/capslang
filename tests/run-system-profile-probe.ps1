[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedHash)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Diagnostic requires an elevated user, not SYSTEM.'
}
if ($identity.User.Value -eq 'S-1-5-18') { throw 'Run coordinator as installation user.' }
$installed = 'C:\Program Files\CapsLang\CapsLang.exe'
$probe = 'C:\Program Files\CapsLangDevProbe\CapsLang.exe'
if ((Get-FileHash -LiteralPath $probe -Algorithm SHA256).Hash -ne $ExpectedHash) { throw 'Probe hash mismatch.' }
if (Get-Service -Name CapsLangLayout -ErrorAction SilentlyContinue) { throw 'Existing layout service preserved; diagnostic endpoint may conflict.' }
$before = (Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash
$sid = $identity.User.Value
$roles = @(('CapsLang Engine ' + $sid), ('CapsLang Broker ' + $sid)) | ForEach-Object {
    $role = Get-ScheduledTask -TaskName $_ -ErrorAction Stop
    if (@($role.Actions).Count -ne 1 -or $role.Actions[0].Execute -ne $installed) { throw 'Unexpected installed task action; preserved.' }
    $role
}
$run = [guid]::NewGuid().ToString('N')
$name = 'CapsLang Dev Profile Probe ' + $run
$directory = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('CapsLang\DevTests\system-profile-' + $run)
New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null
$output = Join-Path $directory 'client.jsonl'
$errors = Join-Path $directory 'client.stderr.txt'
$registered = $false
$paused = $false
$client = $null
try {
    $action = New-ScheduledTaskAction -Execute $probe -Argument '--profile-probe-system'
    $principal = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings | Out-Null
    $registered = $true
    # Stop only the two authenticated existing CapsLang tasks, not MWB/Guard.
    $paused = $true
    foreach ($role in $roles) { Stop-ScheduledTask -InputObject $role }
    Start-ScheduledTask -TaskName $name
    Start-Sleep -Seconds 3
    $client = Start-Process -FilePath $probe -ArgumentList '--profile-probe-client' -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $output -RedirectStandardError $errors
    Write-Output ('probe_started client_pid=' + $client.Id + ' log=' + $output)
    $deadline = [DateTime]::UtcNow.AddSeconds(70)
    while (-not $client.WaitForExit(1000)) {
        if ([DateTime]::UtcNow -ge $deadline) { $client.Kill(); throw 'Owned diagnostic client timed out.' }
    }
    Write-Output ('probe_client_exit=' + $client.ExitCode)
    Get-Content -LiteralPath $output
    if (Test-Path -LiteralPath $errors) { Get-Content -LiteralPath $errors }
} finally {
    if ($client -and -not $client.HasExited) { $client.Kill() }
    if ($registered) {
        Stop-ScheduledTask -TaskName $name -ErrorAction Continue
        Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Continue
    }
    if ($paused) { foreach ($role in $roles) { Start-ScheduledTask -InputObject $role } }
    if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $before) { throw 'Installed hash changed unexpectedly.' }
    Write-Output 'installed_binary_preserved; installed_tasks_restarted; temporary_task_removed'
}

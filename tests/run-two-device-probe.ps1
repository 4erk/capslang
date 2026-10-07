[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedHash,
    [ValidateRange(15,180)][int]$DurationSeconds=180)
$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.User.Value -eq 'S-1-5-18' -or -not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated installation user required.' }
$installed='C:\Program Files\CapsLang\CapsLang.exe'
$probe='C:\Program Files\CapsLangDevProbe\CapsLang.exe'
if ((Get-FileHash -LiteralPath $probe -Algorithm SHA256).Hash -ne $ExpectedHash) { throw 'Probe hash mismatch.' }
if (Get-Service CapsLangLayout -ErrorAction SilentlyContinue) { throw 'Existing SYSTEM endpoint preserved.' }
$before=(Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash
$sid=$identity.User.Value
$old=@(('CapsLang Engine '+$sid),('CapsLang Broker '+$sid)) | ForEach-Object {
    $task=Get-ScheduledTask -TaskName $_
    if (@($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -ne $installed) { throw 'Unexpected old role; preserved.' }
    $task
}
$run=[guid]::NewGuid().ToString('N')
$names=@(('CapsLang Dev SYSTEM '+$run),('CapsLang Dev Engine '+$run),('CapsLang Dev Broker '+$run))
$directory=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('CapsLang\DevTests\sync-'+$run)
New-Item -ItemType Directory -Path $directory | Out-Null
$data=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'CapsLang'
$saved=@{}
foreach($file in @('identity.dat','pair.dat')) {
    $path=Join-Path $data $file
    $saved[$file]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    Copy-Item -LiteralPath $path -Destination (Join-Path $directory $file)
}
$registered=@()
$rule='CapsLang Dev Sync '+$run
$ruleCreated=$false
$paused=$false
try {
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 6) -MultipleInstances IgnoreNew
    $actions=@('--profile-probe-system','--engine','--background')
    for($index=0;$index -lt 3;$index++) {
        $principal=if($index -eq 0) { New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest } else {
            New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel $(if($index -eq 1){'Highest'}else{'Limited'})
        }
        Register-ScheduledTask -TaskName $names[$index] -Action (New-ScheduledTaskAction -Execute $probe -Argument $actions[$index]) -Principal $principal -Settings $settings | Out-Null
        $registered+=$names[$index]
    }
    # Scope is only the diagnostic CapsLang image, its usual port and local LAN.
    New-NetFirewallRule -Name $rule -DisplayName $rule -Program $probe -Direction Inbound -Action Allow -Protocol TCP -LocalPort 42519 -RemoteAddress LocalSubnet -Profile Any | Out-Null
    $ruleCreated=$true
    $paused=$true
    foreach($task in $old){Stop-ScheduledTask -InputObject $task}
    Start-ScheduledTask -TaskName $names[0]
    Start-Sleep -Seconds 2
    Start-ScheduledTask -TaskName $names[1]
    Start-Sleep -Seconds 3
    Start-ScheduledTask -TaskName $names[2]
    Write-Output ('sync_probe_started log_directory='+$directory)
    $deadline=[DateTime]::UtcNow.AddSeconds($DurationSeconds)
    $index=0
    while([DateTime]::UtcNow -lt $deadline) {
        $output=Join-Path $directory ('status-'+$index+'.json')
        $process=Start-Process -FilePath $probe -ArgumentList '--status','--json' -RedirectStandardOutput $output -WindowStyle Hidden -PassThru
        if(-not $process.WaitForExit(3000)){$process.Kill();throw 'Owned status probe timed out.'}
        if(Test-Path -LiteralPath $output){Get-Content -LiteralPath $output}
        $index++
        Start-Sleep -Seconds 2
    }
} finally {
    foreach($name in $registered){Stop-ScheduledTask -TaskName $name -ErrorAction Continue}
    foreach($name in $registered){Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Continue}
    if($ruleCreated){Remove-NetFirewallRule -Name $rule -ErrorAction Continue}
    if($paused){foreach($task in $old){Start-ScheduledTask -InputObject $task}}
    if((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $before){throw 'Installed binary changed unexpectedly.'}
    foreach($file in $saved.Keys){if((Get-FileHash -LiteralPath (Join-Path $data $file) -Algorithm SHA256).Hash -ne $saved[$file]){throw ('Pair/identity changed: '+$file)}}
    Write-Output 'installed_binary_and_pair_preserved; old_roles_restarted; temporary_tasks_and_rule_removed'
}

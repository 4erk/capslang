[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Candidate,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedHash,
    [Parameter(Mandatory=$true)][string]$ExpectedVersion,
    [switch]$ConfirmActiveDesktopUpdate
)
# Reproducible privileged delivery check. Uses the real install transaction,
# running only the migration coordinator as the ordinary interactive owner.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if(-not $ConfirmActiveDesktopUpdate){throw 'Explicit active desktop update opt-in required.'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
if($identity.User.Value -eq 'S-1-5-18' -or -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated interactive installation owner required.'}
$Candidate=(Get-Item -LiteralPath $Candidate).FullName
if((Get-FileHash -LiteralPath $Candidate -Algorithm SHA256).Hash -ne $ExpectedHash){throw 'Candidate hash mismatch.'}
if([Diagnostics.FileVersionInfo]::GetVersionInfo($Candidate).FileVersion -ne $ExpectedVersion){throw 'Candidate version mismatch.'}
$installed=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'CapsLang\CapsLang.exe'
$sid=$identity.User.Value
foreach($role in @('Broker','Engine')) {
    $task=Get-ScheduledTask -TaskName ('CapsLang '+$role+' '+$sid)
    if(@($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -ine $installed){throw 'Unexpected installation task preserved.'}
}
if(Get-ScheduledTask -TaskName 'CapsLang Dev *' -ErrorAction SilentlyContinue){throw 'Diagnostic must complete before update.'}
$before=(Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash
$data=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'CapsLang'
$saved=@{}
foreach($name in @('identity.dat','pair.dat')) {$saved[$name]=(Get-FileHash -LiteralPath (Join-Path $data $name) -Algorithm SHA256).Hash}
function Invoke-OrdinaryMigration([string]$argument) {
    $name='CapsLang Delivery '+[guid]::NewGuid().ToString('N')
    try {
        $principal=New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited
        $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
        Register-ScheduledTask -TaskName $name -Action (New-ScheduledTaskAction -Execute $Candidate -Argument $argument) -Principal $principal -Settings $settings | Out-Null
        $started=Get-Date
        Start-ScheduledTask -TaskName $name
        $deadline=$started.AddSeconds(70)
        do {
            Start-Sleep -Milliseconds 200
            $task=Get-ScheduledTask -TaskName $name
            $info=Get-ScheduledTaskInfo -TaskName $name
            if($info.LastRunTime -ge $started.AddSeconds(-2) -and $task.State -ne 'Running' -and $info.LastTaskResult -notin @(267011,267009)){return [uint32]$info.LastTaskResult}
        } while((Get-Date) -lt $deadline)
        throw 'Migration still pending; inspect before retry.'
    } finally {
        $task=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        if($task -and $task.State -ne 'Running'){Unregister-ScheduledTask -TaskName $name -Confirm:$false}
    }
}
$prepare=Invoke-OrdinaryMigration '--prepare-install'
if($prepare -ne 0){throw ('Prepare failed: '+$prepare)}
$admin=Start-Process -FilePath $Candidate -ArgumentList '--admin-install' -PassThru
if(-not $admin.WaitForExit(120000)){throw 'Administrative transaction pending; inspect before retry.'}
Write-Output ('admin_install_exit='+$admin.ExitCode)
if($admin.ExitCode -ne 0){$abort=Invoke-OrdinaryMigration '--abort-install';Write-Output ('abort_exit='+$abort);throw ('Administrative update failed: '+$admin.ExitCode)}
$complete=Invoke-OrdinaryMigration '--complete-install'
Write-Output ('complete_install_exit='+$complete)
if($complete -ne 0){throw ('Migration completion failed; inspect committed update: '+$complete)}
if((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $ExpectedHash){throw 'Installed hash mismatch.'}
foreach($name in $saved.Keys){if((Get-FileHash -LiteralPath (Join-Path $data $name) -Algorithm SHA256).Hash -ne $saved[$name]){throw 'Encrypted pair/identity changed.'}}
$backup=Join-Path (Split-Path -Parent $installed) ('rollback-'+$before.ToLowerInvariant()+'.exe')
if($before -ne $ExpectedHash -and (-not (Test-Path -LiteralPath $backup) -or (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $before)){throw 'Previous binary backup not verified.'}
$service=Get-CimInstance Win32_Service -Filter "Name='CapsLangLayout'"
if(-not $service -or $service.State -ne 'Running' -or $service.StartName -ne 'LocalSystem' -or $service.PathName -ne ('"'+$installed+'" --layout-service')){throw 'Layout service not verified.'}
foreach($role in @('Broker','Engine')){if((Get-ScheduledTask -TaskName ('CapsLang '+$role+' '+$sid)).State -ne 'Running'){throw ('Role not running: '+$role)}}
Write-Output ('installed_version='+[Diagnostics.FileVersionInfo]::GetVersionInfo($installed).FileVersion)
Write-Output ('installed_sha256='+(Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash)
Write-Output 'encrypted_pair_identity_preserved; previous_binary_backup_verified; service_and_tasks_running'

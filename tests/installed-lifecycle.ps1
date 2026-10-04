[CmdletBinding()]
param([switch]$ConfirmActiveDesktopTest, [ValidateRange(1,10)][int]$Cycles=3)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if (!$ConfirmActiveDesktopTest) { throw 'Opt-in required: temporarily restarts the installed CapsLang on this desktop.' }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this test without elevation: it verifies startup without UAC.' }
$exe=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'CapsLang\CapsLang.exe'
function Invoke-Caps([string]$Arguments) {
    $p=[Diagnostics.Process]::new()
    $p.StartInfo.FileName=$exe
    $p.StartInfo.Arguments=$Arguments
    $p.StartInfo.UseShellExecute=$false
    $p.StartInfo.CreateNoWindow=$true
    $p.StartInfo.RedirectStandardOutput=$true
    try {
        [void]$p.Start()
        $output=$p.StandardOutput.ReadToEndAsync()
        if (!$p.WaitForExit(45000)) { throw 'CapsLang operation pending; inspect before retrying.' }
        [pscustomobject]@{Code=$p.ExitCode;Text=$output.Result}
    } finally { $p.Dispose() }
}
$scheduler=New-Object -ComObject Schedule.Service
$scheduler.Connect()
$folder=$scheduler.GetFolder('\')
$task=$folder.GetTask('CapsLang Broker '+$identity.User.Value)
if ($task.Definition.Actions.Count -ne 1 -or $task.Definition.Actions.Item(1).Path -ine $exe -or $task.Definition.Actions.Item(1).Arguments -cne '--background') { throw 'Unexpected task definition; no changes made.' }
try {
    for ($cycle=1;$cycle -le $Cycles;$cycle++) {
        $stop=Invoke-Caps '--stop'
        if ($stop.Code -ne 0) { throw "Stop failed: $($stop.Code)" }
        $wait=[Diagnostics.Stopwatch]::StartNew()
        do {
            $status=Invoke-Caps '--status --json'
            if ($status.Code -eq 2) { break }
            if ($wait.ElapsedMilliseconds -ge 12000) { throw 'Installed broker did not stop.' }
            Start-Sleep -Milliseconds 50
        } while ($true)
        # Deliberately start ONLY the ordinary broker. Its normal startup path
        # must bring up the protected elevated task without consent or a shell.
        $watch=[Diagnostics.Stopwatch]::StartNew()
        $null=$task.Run($null)
        do {
            $result=Invoke-Caps '--status --json'
            $state=$result.Text | ConvertFrom-Json
            if ($result.Code -eq 0 -and $state.fresh -and $state.engine_error -eq 0 -and $state.elevated -and $state.hook_registered -and $state.hook_responsive) { break }
            if ($watch.ElapsedMilliseconds -ge 16000) { throw 'Broker-first startup did not become healthy.' }
            Start-Sleep -Milliseconds 50
        } while ($true)
        [pscustomobject]@{cycle=$cycle;brokerFirstReadyMs=$watch.ElapsedMilliseconds;engineError=$state.engine_error;elevated=$state.elevated} | ConvertTo-Json -Compress
    }
} catch {
    $failure=$_
    # Bounded best-effort restoration of the same installed application only.
    $restore=Invoke-Caps '--restart'
    Write-Warning "Recovery exit: $($restore.Code)"
    throw $failure
}

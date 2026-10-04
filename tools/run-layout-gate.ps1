[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][string]$Report,
    [ValidateSet('Observe','EN','RU')][string]$Mode='Observe',
    [ValidateRange(1,30)][int]$Seconds=3,
    [ValidateRange(1,4)][int]$Rounds=1,
    [switch]$ConfirmActiveDesktop,
    [switch]$AddressTarget
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run in the ordinary interactive user context; elevated TSF is not this gate.'
}
if ($Mode -ne 'Observe' -and !$ConfirmActiveDesktop) { throw 'Active desktop opt-in required.' }
if ($Mode -eq 'Observe' -and ($ConfirmActiveDesktop -or $AddressTarget)) { throw 'Invalid observe options.' }
if (Test-Path -LiteralPath $Report) { throw 'Report already exists: preserve prior evidence.' }
$probe=(Resolve-Path -LiteralPath $Executable).Path
$installed=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'CapsLang\CapsLang.exe'
function Invoke-Bounded([string]$File,[string]$Arguments,[int]$Timeout) {
    $p=[Diagnostics.Process]::new()
    $p.StartInfo.FileName=$File
    $p.StartInfo.Arguments=$Arguments
    $p.StartInfo.UseShellExecute=$false
    $p.StartInfo.CreateNoWindow=$true
    $p.StartInfo.RedirectStandardOutput=$true
    $p.StartInfo.RedirectStandardError=$true
    try {
        [void]$p.Start()
        $output=$p.StandardOutput.ReadToEndAsync()
        $errors=$p.StandardError.ReadToEndAsync()
        if (!$p.WaitForExit($Timeout)) {
            # Only this owned diagnostic/control child. No user process is killed.
            $p.Kill();$p.WaitForExit()
            throw 'Child timed out; no passing result accepted.'
        }
        [pscustomobject]@{Code=$p.ExitCode;Text=$output.Result;Errors=$errors.Result}
    } finally { $p.Dispose() }
}
$mustRestore=$false
$lines=[Collections.Generic.List[string]]::new()
try {
    $lines.Add(([pscustomobject]@{event='gate_runner';mode=$Mode;sha256=(Get-FileHash -LiteralPath $probe -Algorithm SHA256).Hash;visualAcceptance=$false}|ConvertTo-Json -Compress))
    if ($Mode -ne 'Observe') {
        $before=Invoke-Bounded $installed '--status --json' 5000
        $status=$before.Text | ConvertFrom-Json
        if ($before.Code -ne 0 -or !$status.fresh -or $status.engine_error -ne 0) { throw 'Installed application not healthy before test.' }
        $mustRestore=$true
        $stop=Invoke-Bounded $installed '--stop' 10000
        if ($stop.Code -ne 0) { throw "Stop failed: $($stop.Code)" }
        $watch=[Diagnostics.Stopwatch]::StartNew()
        do {
            $remaining=Get-Process CapsLang -ErrorAction SilentlyContinue | Where-Object { $_.Path -ieq $installed -and $_.SessionId -eq (Get-Process -Id $PID).SessionId }
            if (!$remaining) { break }
            if ($watch.ElapsedMilliseconds -ge 12000) { throw 'Installed application did not exit; test cancelled.' }
            Start-Sleep -Milliseconds 100
        } while ($true)
    }
    $arguments="--seconds $Seconds"
    if ($Mode -ne 'Observe') { $arguments+=" --apply $Mode --confirm-active-desktop" }
    if ($AddressTarget) { $arguments+=' --address-target' }
    for ($round=1;$round -le $Rounds;$round++) {
        $lines.Add(([pscustomobject]@{event='round';number=$round}|ConvertTo-Json -Compress))
        $result=Invoke-Bounded $probe $arguments (($Seconds+10)*1000)
        $lines.Add($result.Text)
        if ($result.Code -ne 0) { throw "Gate failed: $($result.Code) $($result.Errors)" }
    }
} catch {
    $lines.Add(([pscustomobject]@{event='runner_failure';message=$_.Exception.Message}|ConvertTo-Json -Compress))
    throw
} finally {
    if ($mustRestore) {
        try {
            $restart=Invoke-Bounded $installed '--restart' 45000
            $after=Invoke-Bounded $installed '--status --json' 5000
            $lines.Add(([pscustomobject]@{event='restoration';restartExit=$restart.Code;statusExit=$after.Code}|ConvertTo-Json -Compress))
            $lines.Add($after.Text)
            if ($restart.Code -ne 0 -or $after.Code -ne 0) { Write-Warning 'Installed application restoration needs attention.' }
        } catch { $lines.Add(([pscustomobject]@{event='restoration_failure';message=$_.Exception.Message}|ConvertTo-Json -Compress));Write-Warning $_ }
    }
    # CreateNew prevents a retry from destroying the evidence of an unknown run.
    $stream=[IO.File]::Open($Report,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try {
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($lines -join "`n"))
        $stream.Write($bytes,0,$bytes.Length)
    } finally { $stream.Dispose() }
}

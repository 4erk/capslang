# Bounded, user-context live acceptance window. Never changes autostart.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if (([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Use the ordinary interactive user context.' }
$exe='C:\Program Files\CapsLang\CapsLang.exe'
$report=Join-Path $env:LOCALAPPDATA 'CapsLang\gate-typing-hold-20261004.jsonl'
if (Test-Path -LiteralPath $report) { throw 'Existing outcome; do not repeat blindly.' }
$writer=[IO.StreamWriter]::new([IO.File]::Open($report,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read))
$writer.AutoFlush=$true
function Invoke-CapsLang([string]$argument) {
    $p=[Diagnostics.Process]::new()
    $p.StartInfo.FileName=$exe; $p.StartInfo.Arguments=$argument
    $p.StartInfo.UseShellExecute=$false; $p.StartInfo.CreateNoWindow=$true
    try {
        [void]$p.Start()
        if (!$p.WaitForExit(15000)) { $p.Kill(); $p.WaitForExit(); throw 'Owned control process timed out.' }
        return $p.ExitCode
    } finally { $p.Dispose() }
}
try {
    $code=Invoke-CapsLang '--stop'
    if ($code -ne 0) { throw "Stop refused: $code" }
    $session=(Get-Process -Id $PID).SessionId
    $watch=[Diagnostics.Stopwatch]::StartNew()
    do {
        $running=@(Get-Process CapsLang -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $session -and $_.Path -eq $exe })
        if (!$running.Count) { break }
        Start-Sleep -Milliseconds 100
    } while ($watch.ElapsedMilliseconds -lt 15000)
    if ($running.Count) { throw 'Installed roles did not stop; do not run acceptance.' }
    $writer.WriteLine('{"event":"ready","automatic_restart_seconds":180}')
    Start-Sleep -Seconds 180
} finally {
    try { $code=Invoke-CapsLang '--restart'; $writer.WriteLine(('{"event":"restored","exit":'+$code+'}')) }
    finally { $writer.Dispose() }
}

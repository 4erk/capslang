[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Report)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if (([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The interactive observer requires the ordinary user context.'
}
$root=Split-Path -Parent $PSScriptRoot
$probePath=Join-Path $root 'build\message-probe\x64\windows_message_probe.exe'
$dllPath=Join-Path $root 'build\message-probe\x64\layout_message_probe.dll'
$installed='C:\Program Files\CapsLang\CapsLang.exe'
$expected=@{
    $probePath='2819907dc7229ab69daa3b4e16570257c9bb63b9e87aa92bb1be26a3f8bd676c'
    $dllPath='c5414ef937868c2f80eeb0a40fdba6a7b528bd502cb55d4545e2a1420065431f'
    $installed='524dacefc6cabe980b5bf003d727f2aade47657cf7a117ada40e386fc7c4949f'
}
foreach ($entry in $expected.GetEnumerator()) {
    if ((Get-FileHash -LiteralPath $entry.Key -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.Value) {
        throw 'A test or installed binary changed; reconcile its identity before running the experiment.'
    }
}
$session=(Get-Process -Id $PID).SessionId
if (!@(Get-Process CapsLang -ErrorAction SilentlyContinue | Where-Object {$_.SessionId -eq $session}).Count) {
    throw 'Installed CapsLang was not running. Do not change a pre-existing stopped state.'
}
$writer=[IO.StreamWriter]::new([IO.File]::Open([IO.Path]::GetFullPath($Report),[IO.FileMode]::CreateNew,
    [IO.FileAccess]::Write,[IO.FileShare]::Read),[Text.UTF8Encoding]::new($false))
$writer.AutoFlush=$true
function Record([string]$line) {$writer.WriteLine($line);Write-Output $line}
function Control([string]$argument) {
    $command=[Diagnostics.Process]::new()
    $command.StartInfo.FileName=$installed
    $command.StartInfo.Arguments=$argument
    $command.StartInfo.UseShellExecute=$false
    $command.StartInfo.CreateNoWindow=$true
    try {
        if (!$command.Start()) {throw 'Could not start installed application control.'}
        if (!$command.WaitForExit(15000)) {$command.Kill();$command.WaitForExit();throw 'Owned control process timed out.'}
        return $command.ExitCode
    } finally {$command.Dispose()}
}
$probe=[Diagnostics.Process]::new()
$probe.StartInfo.FileName=$probePath
$probe.StartInfo.Arguments='--interactive-message-observer'
$probe.StartInfo.UseShellExecute=$false
$probe.StartInfo.CreateNoWindow=$true
$probe.StartInfo.RedirectStandardOutput=$true
$probe.StartInfo.RedirectStandardError=$true
$restore=$false;$started=$false
try {
    Record "Begin $([DateTime]::UtcNow.ToString('o')); only owned test-window hooks; guard/autostart unchanged."
    $restore=$true
    $exit=Control '--stop'
    if ($exit -ne 0) {throw "Installed CapsLang refused stop: $exit"}
    $deadline=[Diagnostics.Stopwatch]::StartNew()
    do {
        $remaining=@(Get-Process CapsLang -ErrorAction SilentlyContinue | Where-Object {$_.SessionId -eq $session})
        if (!$remaining.Count) {break}
        Start-Sleep -Milliseconds 100
    } while ($deadline.ElapsedMilliseconds -lt 10000)
    if ($remaining.Count) {throw 'CapsLang roles remain; abort contaminated observation.'}
    Record 'Installed CapsLang paused for at most the 3-minute observation plus bounded cleanup.'
    if (!$probe.Start()) {throw 'Could not start the owned test window.'}
    $started=$true
    $watch=[Diagnostics.Stopwatch]::StartNew()
    $stderr=$probe.StandardError.ReadToEndAsync()
    $pending=$probe.StandardOutput.ReadLineAsync()
    while ($true) {
        if ($watch.ElapsedMilliseconds -gt 188000) {throw 'Owned test window exceeded its deadline.'}
        if (!$pending.IsCompleted) {Start-Sleep -Milliseconds 40;continue}
        $line=$pending.Result
        if ($null -eq $line) {break}
        Record $line
        $pending=$probe.StandardOutput.ReadLineAsync()
    }
    if (!$probe.WaitForExit(2000) -or $probe.ExitCode -ne 0) {throw 'Observation process failed.'}
    if ($stderr.Result) {throw 'Observer reported an unexpected error.'}
} finally {
    try {
        if ($started -and !$probe.HasExited) {$probe.Kill();$probe.WaitForExit(2000)|Out-Null}
        $probe.Dispose()
    } finally {
        try {
            if ($restore) {
                $exit=Control '--restart'
                Record "Installed CapsLang restart exit=$exit; $([DateTime]::UtcNow.ToString('o'))"
                if ($exit -ne 0) {throw 'Installed CapsLang restart failed; inspect immediately.'}
            }
        } finally {$writer.Dispose()}
    }
}

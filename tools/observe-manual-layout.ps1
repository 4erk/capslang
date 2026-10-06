[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Report,
      [ValidateRange(1,180)][int]$Seconds=180,
      [switch]$ActiveClient)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Split-Path -Parent $PSScriptRoot
$exe=Join-Path $root 'build\layout-gate\CapsLangLayoutGate.exe'
$hash=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
if ($hash -ne '624ab50aae584ddd3f6c94e47981fa429acd12c056e7ac2a73865a95d13b898c') {
    throw 'Observer binary changed; review/rebuild before updating the expected hash.'
}
# CreateNew preserves evidence if a previous attempt's outcome is unknown.
$file=[IO.File]::Open([IO.Path]::GetFullPath($Report),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
$writer=[IO.StreamWriter]::new($file,[Text.UTF8Encoding]::new($false))
$writer.AutoFlush=$true
$process=[Diagnostics.Process]::new()
$process.StartInfo.FileName=$exe
$process.StartInfo.Arguments="--seconds $Seconds"
if ($ActiveClient) {$process.StartInfo.Arguments+=' --observe-active-client'}
$process.StartInfo.UseShellExecute=$false
$process.StartInfo.CreateNoWindow=$true
$process.StartInfo.RedirectStandardOutput=$true
$process.StartInfo.RedirectStandardError=$true
$started=$false
$last=''
$samples=0
try {
    $writer.WriteLine(([ordered]@{event='observation_start';utc=[DateTime]::UtcNow.ToString('o');sha256=$hash;read_only=$true}|ConvertTo-Json -Compress))
    if (!$process.Start()) {throw 'Cannot start observer'}
    $started=$true
    $watch=[Diagnostics.Stopwatch]::StartNew()
    $stderr=$process.StandardError.ReadToEndAsync()
    $pending=$process.StandardOutput.ReadLineAsync()
    while ($true) {
        if ($watch.ElapsedMilliseconds -gt (($Seconds+8)*1000)) {throw 'Observer deadline exceeded'}
        if (!$pending.IsCompleted) {Start-Sleep -Milliseconds 40;continue}
        $line=$pending.Result
        if ($null -eq $line) {break}
        $writer.WriteLine($line)
        $row=$line|ConvertFrom-Json
        if ($row.event -eq 'sample') {
            ++$samples
            $key="$($row.probe_profile):$($row.foreground_language):$($row.foreground_pid):$($row.notifications):$($row.shell_notifications):$($row.language_changing):$($row.language_changed)"
            if ($key -ne $last) {Write-Output $line;$last=$key}
        } else {Write-Output $line}
        $pending=$process.StandardOutput.ReadLineAsync()
    }
    if (!$process.WaitForExit(2000)) {throw 'Observer did not exit after output closed'}
    if ($process.ExitCode -ne 0) {throw "Observer failed: $($process.ExitCode)"}
    if ($stderr.Result) {throw 'Observer wrote unexpected stderr; inspect before acceptance'}
    $summary=[ordered]@{event='observation_complete';utc=[DateTime]::UtcNow.ToString('o');samples=$samples;exit=0}|ConvertTo-Json -Compress
    $writer.WriteLine($summary)
    Write-Output $summary
} finally {
    if ($started -and !$process.HasExited) {
        $process.Kill() # Only the child started and owned by this invocation.
        $process.WaitForExit(2000)|Out-Null
    }
    $process.Dispose()
    $writer.Dispose()
}

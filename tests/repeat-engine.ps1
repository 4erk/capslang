[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Exe, [ValidateRange(1,20)][int]$Count=3, [switch]$EngineOnly)
$ErrorActionPreference='Stop'
$Exe=(Resolve-Path -LiteralPath $Exe).Path
$hash=(Get-FileHash -LiteralPath $Exe).Hash
$failures=0
for($i=1;$i -le $Count;$i++) {
    $p=New-Object Diagnostics.Process
    $p.StartInfo.FileName=$Exe
    if($EngineOnly){$p.StartInfo.Arguments='--engine-only'}
    $p.StartInfo.UseShellExecute=$false
    $p.StartInfo.CreateNoWindow=$true
    $p.StartInfo.RedirectStandardOutput=$true
    $p.StartInfo.RedirectStandardError=$true
    try {
        if(-not $p.Start()){throw 'Test start failed'}
        $stdout=$p.StandardOutput.ReadToEndAsync()
        $stderr=$p.StandardError.ReadToEndAsync()
        $completed=$p.WaitForExit(45000)
        if(-not $completed){$p.Kill();$p.WaitForExit()}
        $report=$stdout.Result + $stderr.Result
        # Generated diagnostic artifact beside the disposable test executable.
        $path=Join-Path (Split-Path $Exe) ("engine-repeat-{0}-{1}.txt" -f $PID,$i)
        [IO.File]::WriteAllText($path,$report)
        if(-not $completed -or $p.ExitCode -ne 0){$failures++}
        Write-Output ("Run={0} Completed={1} Exit={2} SHA256={3}" -f $i,$completed,$p.ExitCode,$hash)
        $report -split '\r?\n' | Where-Object {$_ -match 'FAIL|failure:|Fixture state|wait chain|node=|Windows layout integration|IPC boundary|MWB metadata'} | Write-Output
    } finally {$p.Dispose()}
    if((Get-FileHash -LiteralPath $Exe).Hash -ne $hash){throw 'Executable changed during tests'}
}
if($failures){throw "$failures of $Count engine runs failed"}

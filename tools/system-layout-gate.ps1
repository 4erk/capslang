# One-time, explicitly authorized SYSTEM feasibility test for 4ERK-PC.
# Not an installer/service. No networking, input injection or security changes.
# Fixed protected executable/report paths, fixed session, fixed EN/RU request.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root='C:\Program Files\CapsLangLayoutGate-cc478039'
$report=Join-Path $root 'system-ru-report.jsonl'
if (Test-Path -LiteralPath $report) { throw 'Existing test outcome; refusing to repeat.' }
$rows=[Collections.Generic.List[string]]::new()
try {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $session=(Get-Process -Id $PID).SessionId
    if ($identity.User.Value -ne 'S-1-5-18' -or $session -ne 1) { throw 'Wrong user or desktop session; no layout request sent.' }
    Add-Type -TypeDefinition @'
using System;using System.Text;using System.Runtime.InteropServices;
public static class GateDesktop {
 [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint p);
 [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
 [DllImport("user32.dll")] public static extern IntPtr GetThreadDesktop(uint t);
 [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
 public static extern bool GetUserObjectInformation(IntPtr h,int n,StringBuilder s,uint bytes,out uint needed);
}
'@
    $name=[Text.StringBuilder]::new(256);[uint32]$needed=0
    if (![GateDesktop]::GetUserObjectInformation([GateDesktop]::GetThreadDesktop([GateDesktop]::GetCurrentThreadId()),2,$name,512,[ref]$needed) -or $name.ToString() -cne 'Default') {
        throw 'Not the normal Default desktop; no layout request sent.'
    }
    [uint32]$foregroundPid=0
    [void][GateDesktop]::GetWindowThreadProcessId([GateDesktop]::GetForegroundWindow(),[ref]$foregroundPid)
    $foreground=Get-CimInstance Win32_Process -Filter "ProcessId=$foregroundPid"
    if ($foreground.Name -cne 'PowerToys.MouseWithoutBordersHelper.exe' -or $foreground.SessionId -ne 1) { throw 'MWB Helper is not foreground; no layout request sent.' }
    $owner=Invoke-CimMethod -InputObject $foreground -MethodName GetOwnerSid
    if ($owner.Sid -ne 'S-1-5-18') { throw 'Unexpected MWB owner; no request sent.' }
    $signature=Get-AuthenticodeSignature -LiteralPath $foreground.ExecutablePath
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw 'Unexpected helper signature; no request sent.' }
    $exe=Join-Path $root 'CapsLangLayoutGate.exe'
    $hash=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
    if ($hash -ne 'CC478039A8C5264D72EB7E12AA8FC214ABC0135F6D0342B25C80BC528FD56CC5') { throw 'Wrong probe hash; no request sent.' }
    $rows.Add(([pscustomobject]@{event='system_gate';system=$true;session=$session;desktop=$name.ToString();foregroundPid=$foregroundPid;sha256=$hash}|ConvertTo-Json -Compress))
    $p=[Diagnostics.Process]::new()
    $p.StartInfo.FileName=$exe
    $p.StartInfo.WorkingDirectory=$root
    $p.StartInfo.Arguments='--apply RU --confirm-active-desktop --address-target --seconds 3'
    $p.StartInfo.UseShellExecute=$false
    $p.StartInfo.CreateNoWindow=$true
    $p.StartInfo.RedirectStandardOutput=$true
    $p.StartInfo.RedirectStandardError=$true
    try {
        [void]$p.Start()
        $output=$p.StandardOutput.ReadToEndAsync();$errorOutput=$p.StandardError.ReadToEndAsync()
        if (!$p.WaitForExit(12000)) { $p.Kill();$p.WaitForExit();throw 'Owned probe timed out; no passing result accepted.' }
        $rows.Add($output.Result)
        $rows.Add(([pscustomobject]@{event='system_gate_exit';code=$p.ExitCode}|ConvertTo-Json -Compress))
        if ($p.ExitCode -ne 0) { throw "Probe failed: $($p.ExitCode) $($errorOutput.Result)" }
    } finally { $p.Dispose() }
} catch {
    $rows.Add(([pscustomobject]@{event='system_gate_failure';message=$_.Exception.Message}|ConvertTo-Json -Compress))
    throw
} finally {
    $file=[IO.File]::Open($report,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try { $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($rows -join "`n"));$file.Write($bytes,0,$bytes.Length) }
    finally { $file.Dispose() }
}

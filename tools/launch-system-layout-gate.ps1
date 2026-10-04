# Explicitly authorized one-time diagnostic, not a reusable service/launcher.
# Duplicates ONLY its own SYSTEM token; never reads another process token.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root='C:\Program Files\CapsLangLayoutGate-cc478039'
$report=Join-Path $root 'system-launch-report.json'
if (Test-Path -LiteralPath $report) { throw 'Existing launch outcome; refusing to repeat.' }
$result=[ordered]@{event='system_launch';childPid=0;exitCode=$null;error=$null}
try {
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') { throw 'SYSTEM required; refusing launch.' }
    if (Test-Path -LiteralPath (Join-Path $root 'system-ru-report.jsonl')) { throw 'Existing probe outcome; refusing launch.' }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
public static class FixedSystemGateLauncher {
 [StructLayout(LayoutKind.Sequential)] struct LUID { public uint Low; public int High; }
 [StructLayout(LayoutKind.Sequential)] struct PRIV { public uint Count; public LUID Id; public uint Attributes; }
 [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct STARTUP {
  public uint cb; public string reserved, desktop, title;
  public uint x,y,xSize,ySize,xChars,yChars,fill,flags;
  public ushort show,reserved2; public IntPtr reservedPtr,stdin,stdout,stderr;
 }
 [StructLayout(LayoutKind.Sequential)] struct INFO { public IntPtr process,thread; public uint pid,tid; }
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll")] static extern uint WTSGetActiveConsoleSessionId();
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h,uint ms);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr h,out uint code);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr h,uint code);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr p,uint access,out IntPtr token);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeValue(string system,string name,out LUID id);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token,bool disable,ref PRIV value,uint size,IntPtr previous,IntPtr returned);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool DuplicateTokenEx(IntPtr token,uint access,IntPtr attributes,int level,int type,out IntPtr duplicate);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool SetTokenInformation(IntPtr token,int type,ref uint value,uint size);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessAsUser(IntPtr token,string application,StringBuilder command,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr environment,string directory,ref STARTUP startup,out INFO info);
 static void Check(bool ok) { if(!ok) throw new Win32Exception(Marshal.GetLastWin32Error()); }
 static void Enable(IntPtr token,string name) {
  var p=new PRIV(); p.Count=1; p.Attributes=2;
  Check(LookupPrivilegeValue(null,name,out p.Id));
  Check(AdjustTokenPrivileges(token,false,ref p,0,IntPtr.Zero,IntPtr.Zero));
  int error=Marshal.GetLastWin32Error(); if(error!=0) throw new Win32Exception(error);
 }
 public static uint Run(out uint childPid) {
  childPid=0;
  if(WTSGetActiveConsoleSessionId()!=1) throw new InvalidOperationException("Expected console session 1; no launch.");
  IntPtr token=IntPtr.Zero,copy=IntPtr.Zero; INFO info=new INFO();
  try {
   Check(OpenProcessToken(GetCurrentProcess(),0x2b,out token));
   Enable(token,"SeTcbPrivilege"); Enable(token,"SeAssignPrimaryTokenPrivilege"); Enable(token,"SeIncreaseQuotaPrivilege");
   Check(DuplicateTokenEx(token,0x02000000,IntPtr.Zero,2,1,out copy));
   uint session=1; Check(SetTokenInformation(copy,12,ref session,4));
   var startup=new STARTUP(); startup.cb=(uint)Marshal.SizeOf(typeof(STARTUP)); startup.desktop="winsta0\\default";
   const string exe=@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
   var command=new StringBuilder("\""+exe+"\" -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File \"C:\\Program Files\\CapsLangLayoutGate-cc478039\\system-layout-gate.ps1\"");
   Check(CreateProcessAsUser(copy,exe,command,IntPtr.Zero,IntPtr.Zero,false,0x08000000,IntPtr.Zero,@"C:\Program Files\CapsLangLayoutGate-cc478039",ref startup,out info));
   childPid=info.pid;
   if(WaitForSingleObject(info.process,45000)!=0) {
    TerminateProcess(info.process,1460); throw new TimeoutException("Owned diagnostic timed out; no passing result.");
   }
   uint code; Check(GetExitCodeProcess(info.process,out code)); return code;
  } finally {
   if(info.thread!=IntPtr.Zero) CloseHandle(info.thread);
   if(info.process!=IntPtr.Zero) CloseHandle(info.process);
   if(copy!=IntPtr.Zero) CloseHandle(copy);
   if(token!=IntPtr.Zero) CloseHandle(token);
  }
 }
}
'@
    [uint32]$childPid=0
    try { $result.exitCode=[FixedSystemGateLauncher]::Run([ref]$childPid) }
    finally { $result.childPid=$childPid }
    if ($result.exitCode -ne 0) { throw "Child diagnostic failed: $($result.exitCode)" }
} catch { $result.error=$_.Exception.Message; throw }
finally {
    $file=[IO.File]::Open($report,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try { $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Compress)); $file.Write($bytes,0,$bytes.Length) }
    finally { $file.Dispose() }
}

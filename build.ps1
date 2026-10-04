[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$Clean,
    [switch]$ProbeOnly,
    [switch]$IntegrationOnly,
    [switch]$RuntimeTestsOnly,
    [switch]$SaverGuardOnly,
    [switch]$RecipientProbeOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (@(@($ProbeOnly, $IntegrationOnly, $RuntimeTestsOnly, $SaverGuardOnly, $RecipientProbeOnly) | Where-Object { $_ }).Count -gt 1) {
    throw 'Choose only one development build mode.'
}
# Some WSL hosts inherit PATHEXT=.CPL. PowerShell then fails to wait for .exe
# invocations or set LASTEXITCODE. Repair only this build process, and restore
# the caller's environment even on failure or an early return.
$originalPathExt = $env:PATHEXT
try {
if (($env:PATHEXT -split ';') -notcontains '.EXE') { $env:PATHEXT = $env:PATHEXT + ';.EXE' }

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$buildDir = Join-Path $projectRoot 'build'
$distDir = Join-Path $projectRoot 'dist'
$probeDir = Join-Path $buildDir 'probe'
$integrationDir = Join-Path $buildDir 'integration'
$toolRoot = Join-Path $env:LOCALAPPDATA 'CapsLangBuildCache'
$toolVersion = '20260616'
$archiveName = "llvm-mingw-$toolVersion-ucrt-x86_64.zip"
$archivePath = Join-Path $toolRoot $archiveName
$expandedRoot = Join-Path $toolRoot "llvm-mingw-$toolVersion-ucrt-x86_64"
$downloadUrl = "https://github.com/mstorsjo/llvm-mingw/releases/download/$toolVersion/$archiveName"
$expectedSha256 = 'b9b68a4d276e16fa25802aaba458e4638f64b3884c290aaccdc2d87083b6ca35'

if ($Clean) {
    if ($RecipientProbeOnly) {
        Remove-Item -LiteralPath (Join-Path $buildDir 'recipient-probe') -Recurse -Force -ErrorAction SilentlyContinue
    } elseif ($SaverGuardOnly) {
        Remove-Item -LiteralPath (Join-Path $buildDir 'saver-guard') -Recurse -Force -ErrorAction SilentlyContinue
    } elseif ($IntegrationOnly -or $RuntimeTestsOnly) {
        Remove-Item -LiteralPath $integrationDir -Recurse -Force -ErrorAction SilentlyContinue
    } elseif ($ProbeOnly) {
        Remove-Item -LiteralPath $probeDir -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Remove-Item -LiteralPath $buildDir -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $distDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

New-Item -ItemType Directory -Force -Path $buildDir, $distDir, $toolRoot | Out-Null

$compiler = Join-Path $expandedRoot 'bin\clang++.exe'
$windres = Join-Path $expandedRoot 'bin\llvm-windres.exe'
if (-not (Test-Path -LiteralPath $compiler)) {
    $archiveValid = $false
    if (Test-Path -LiteralPath $archivePath) {
        $archiveValid = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant() -eq $expectedSha256
    }
    if (-not $archiveValid) {
        Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue
        Write-Host "Downloading pinned LLVM-MinGW $toolVersion..."
        Invoke-WebRequest -Uri $downloadUrl -OutFile $archivePath
    }
    $actualSha256 = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualSha256 -ne $expectedSha256) {
        throw "LLVM-MinGW checksum mismatch. Expected $expectedSha256, got $actualSha256"
    }
    Write-Host 'Extracting toolchain...'
    Expand-Archive -LiteralPath $archivePath -DestinationPath $toolRoot -Force
}

if (-not (Test-Path -LiteralPath $compiler)) {
    throw "Compiler not found after extraction: $compiler"
}
if (-not (Test-Path -LiteralPath $windres)) {
    throw "Resource compiler not found after extraction: $windres"
}

if ($RecipientProbeOnly) {
    $recipientDir = Join-Path $buildDir 'recipient-probe'
    New-Item -ItemType Directory -Force -Path $recipientDir | Out-Null
    $recipientExe = Join-Path $recipientDir 'mwb_recipient_probe.exe'
    & $compiler '-std=c++17' '-O2' '-DNDEBUG' '-D_WIN32_WINNT=0x0A00' '-DWINVER=0x0A00' `
        '-static' '-s' '-Wall' '-Wextra' '-Wpedantic' '-Werror' '-Wl,--no-insert-timestamp' `
        (Join-Path $projectRoot 'tools\mwb_recipient_probe.cpp') `
        (Join-Path $projectRoot 'src\platform\mwb.cpp') (Join-Path $projectRoot 'src\platform\windows_support.cpp') `
        '-o' $recipientExe '-lole32' '-luuid' '-luser32' '-ladvapi32' '-lsetupapi' `
        '-lwtsapi32' '-lversion' '-lwintrust' '-lcrypt32'
    if ($LASTEXITCODE -ne 0) { throw 'Recipient observer compilation failed.' }
    Write-Host "Built $recipientExe. Not run: requires coordinated physical input on both devices."
    return
}

if ($SaverGuardOnly) {
    $guardDir = Join-Path $buildDir 'saver-guard'
    New-Item -ItemType Directory -Force -Path $guardDir | Out-Null
    $guardExe = Join-Path $guardDir 'CapsLangMwbSaverGuard.exe'
    & $compiler '-std=c++17' '-O2' '-DNDEBUG' '-D_WIN32_WINNT=0x0A00' '-DWINVER=0x0A00' `
        '-static' '-Wall' '-Wextra' '-Wpedantic' '-Werror' '-Wl,--no-insert-timestamp' `
        '-s' '-municode' '-mwindows' (Join-Path $projectRoot 'tools\mwb_saver_guard.cpp') `
        '-o' $guardExe '-luser32' '-ladvapi32' '-lwtsapi32' '-lshell32'
    if ($LASTEXITCODE -ne 0) { throw 'Screensaver companion compilation failed.' }
    Write-Host "Built $guardExe. Not installed; live exercises are opt-in."
    return
}

if ($RuntimeTestsOnly) {
    New-Item -ItemType Directory -Force -Path $integrationDir | Out-Null
    $flags = @('-std=c++17', '-O2', '-DNDEBUG', '-D_WIN32_WINNT=0x0A00', '-DWINVER=0x0A00',
        '-static', '-Wall', '-Wextra', '-Wpedantic', '-Werror', '-Wl,--no-insert-timestamp')
    $platform = Join-Path $projectRoot 'src\platform\windows_support.cpp'
    $libs = @('-lole32', '-luuid', '-luser32', '-ladvapi32', '-lsetupapi')
    $runtimeFailures = New-Object 'System.Collections.Generic.List[string]'
    function Invoke-BoundedTest([string]$Path) {
        $test = New-Object System.Diagnostics.Process
        $test.StartInfo.FileName = $Path
        $test.StartInfo.UseShellExecute = $false
        $test.StartInfo.CreateNoWindow = $true
        $test.StartInfo.RedirectStandardOutput = $true
        $test.StartInfo.RedirectStandardError = $true
        try {
            if (-not $test.Start()) { throw "Cannot start $Path" }
            $stdoutTask = $test.StandardOutput.ReadToEndAsync()
            $stderrTask = $test.StandardError.ReadToEndAsync()
            if (-not $test.WaitForExit(45000)) {
                $test.Kill()
                $test.WaitForExit()
                Write-Host $stdoutTask.Result
                if ($stderrTask.Result) { Write-Host $stderrTask.Result }
                $runtimeFailures.Add("Test exceeded 45 seconds: $Path")
                return
            }
            Write-Host $stdoutTask.Result
            if ($stderrTask.Result) { Write-Host $stderrTask.Result }
            if ($test.ExitCode -ne 0) { $runtimeFailures.Add("Test failed: $Path") }
        } finally { $test.Dispose() }
    }
    $core = Join-Path $integrationDir 'core_tests.exe'
    & $compiler @flags (Join-Path $projectRoot 'tests\core_tests.cpp') '-o' $core
    if ($LASTEXITCODE -ne 0) { throw 'Core test compilation failed.' }
    Invoke-BoundedTest $core
    $sync = Join-Path $integrationDir 'sync_tests.exe'
    & $compiler @flags (Join-Path $projectRoot 'tests\sync_tests.cpp') '-o' $sync
    if ($LASTEXITCODE -ne 0) { throw 'Sync protocol compilation failed.' }
    Invoke-BoundedTest $sync
    $reconnect = Join-Path $integrationDir 'reconnect_tests.exe'
    & $compiler @flags (Join-Path $projectRoot 'tests\reconnect_tests.cpp') '-o' $reconnect
    if ($LASTEXITCODE -ne 0) { throw 'Reconnect policy compilation failed.' }
    Invoke-BoundedTest $reconnect
    $broker = Join-Path $integrationDir 'broker_tests.exe'
    & $compiler @flags (Join-Path $projectRoot 'tests\broker_tests.cpp') '-o' $broker
    if ($LASTEXITCODE -ne 0) { throw 'Broker state compilation failed.' }
    Invoke-BoundedTest $broker
    $engine = Join-Path $integrationDir 'windows_engine_integration.exe'
    & $compiler @flags '-municode' '-DCAPSLANG_ENGINE_INTEGRATION' `
        (Join-Path $projectRoot 'tests\windows_layout_integration.cpp') $platform `
        (Join-Path $projectRoot 'src\runtime\engine.cpp') (Join-Path $projectRoot 'src\platform\mwb.cpp') `
        (Join-Path $projectRoot 'src\runtime\led_worker.cpp') `
        (Join-Path $projectRoot 'src\runtime\engine_host.cpp') `
        (Join-Path $projectRoot 'src\runtime\engine_client.cpp') `
        (Join-Path $projectRoot 'src\network\session.cpp') (Join-Path $projectRoot 'src\network\lan.cpp') `
        (Join-Path $projectRoot 'src\network\pairing.cpp') (Join-Path $projectRoot 'src\network\tls.cpp') `
        (Join-Path $projectRoot 'src\platform\private_store.cpp') `
        (Join-Path $projectRoot 'src\runtime\local_ipc.cpp') `
        '-o' $engine @libs '-lwtsapi32' '-lversion' '-lwintrust' '-lcrypt32' '-lbcrypt' '-lws2_32' '-liphlpapi' '-lsecur32' '-lncrypt'
    if ($LASTEXITCODE -ne 0) { throw 'Engine integration compilation failed.' }
    Invoke-BoundedTest $engine
    $ipc = Join-Path $integrationDir 'windows_ipc_tests.exe'
    & $compiler @flags (Join-Path $projectRoot 'tests\windows_ipc_tests.cpp') `
        (Join-Path $projectRoot 'src\runtime\local_ipc.cpp') $platform '-o' $ipc @libs
    if ($LASTEXITCODE -ne 0) { throw 'IPC test compilation failed.' }
    Invoke-BoundedTest $ipc
    $tls = Join-Path $integrationDir 'windows_tls_tests.exe'
    & $compiler @flags '-municode' (Join-Path $projectRoot 'tests\windows_tls_tests.cpp') `
        (Join-Path $projectRoot 'src\network\tls.cpp') (Join-Path $projectRoot 'src\platform\private_store.cpp') `
        (Join-Path $projectRoot 'src\network\pairing.cpp') `
        (Join-Path $projectRoot 'src\network\enrollment.cpp') `
        '-o' $tls '-lws2_32' '-lsecur32' '-lcrypt32' '-lncrypt' '-lbcrypt' '-ladvapi32'
    if ($LASTEXITCODE -ne 0) { throw 'TLS test compilation failed.' }
    Invoke-BoundedTest $tls
    $lan = Join-Path $integrationDir 'windows_lan_tests.exe'
    & $compiler @flags (Join-Path $projectRoot 'tests\windows_lan_tests.cpp') `
        (Join-Path $projectRoot 'src\network\lan.cpp') (Join-Path $projectRoot 'src\network\pairing.cpp') `
        (Join-Path $projectRoot 'src\network\tls.cpp') (Join-Path $projectRoot 'src\platform\private_store.cpp') `
        '-o' $lan '-lws2_32' '-liphlpapi' '-lsecur32' '-lcrypt32' '-lncrypt' '-lbcrypt' '-ladvapi32'
    if ($LASTEXITCODE -ne 0) { throw 'LAN transport test compilation failed.' }
    Invoke-BoundedTest $lan
    $session = Join-Path $integrationDir 'windows_session_tests.exe'
    & $compiler @flags (Join-Path $projectRoot 'tests\windows_session_tests.cpp') `
        (Join-Path $projectRoot 'src\network\session.cpp') (Join-Path $projectRoot 'src\network\lan.cpp') `
        (Join-Path $projectRoot 'src\network\pairing.cpp') (Join-Path $projectRoot 'src\network\tls.cpp') `
        (Join-Path $projectRoot 'src\platform\private_store.cpp') `
        '-o' $session '-lws2_32' '-liphlpapi' '-lsecur32' '-lcrypt32' '-lncrypt' '-lbcrypt' '-ladvapi32'
    if ($LASTEXITCODE -ne 0) { throw 'Broker session test compilation failed.' }
    Invoke-BoundedTest $session
    $ledWorker = Join-Path $integrationDir 'windows_led_worker_tests.exe'
    & $compiler @flags (Join-Path $projectRoot 'tests\windows_led_worker_tests.cpp') `
        (Join-Path $projectRoot 'src\runtime\led_worker.cpp') $platform '-o' $ledWorker @libs
    if ($LASTEXITCODE -ne 0) { throw 'LED worker compilation failed.' }
    Invoke-BoundedTest $ledWorker
    $lanProbe = Join-Path $integrationDir 'lan_pair_probe.exe'
    & $compiler @flags '-municode' (Join-Path $projectRoot 'tools\lan_pair_probe.cpp') `
        (Join-Path $projectRoot 'src\network\lan.cpp') (Join-Path $projectRoot 'src\network\pairing.cpp') `
        (Join-Path $projectRoot 'src\network\tls.cpp') (Join-Path $projectRoot 'src\platform\private_store.cpp') `
        '-o' $lanProbe '-lws2_32' '-liphlpapi' '-lsecur32' '-lcrypt32' '-lncrypt' '-lbcrypt' '-ladvapi32'
    if ($LASTEXITCODE -ne 0) { throw 'Opt-in LAN probe compilation failed.' }
    # Built but NEVER automatically run: this is the only hardware-writing test.
    $led = Join-Path $integrationDir 'windows_led_integration.exe'
    & $compiler @flags '-municode' (Join-Path $projectRoot 'tests\windows_led_integration.cpp') `
        $platform '-o' $led @libs
    if ($LASTEXITCODE -ne 0) { throw 'LED test compilation failed.' }
    if ($runtimeFailures.Count) { throw ($runtimeFailures -join [Environment]::NewLine) }
    Write-Host 'Development components tested. No app installation or release artifact produced.'
    return
}

if ($IntegrationOnly) {
    New-Item -ItemType Directory -Force -Path $integrationDir | Out-Null
    $integrationExe = Join-Path $integrationDir 'windows_layout_integration.exe'
    & $compiler '-std=c++17' '-O2' '-DNDEBUG' '-D_WIN32_WINNT=0x0A00' '-DWINVER=0x0A00' `
        '-static' '-static-libgcc' '-static-libstdc++' '-Wall' '-Wextra' '-Wpedantic' '-Werror' `
        '-Wl,--no-insert-timestamp' '-municode' (Join-Path $projectRoot 'tests\windows_layout_integration.cpp') `
        (Join-Path $projectRoot 'src\platform\windows_support.cpp') '-o' $integrationExe `
        '-lole32' '-luuid' '-luser32' '-ladvapi32' '-lsetupapi'
    if ($LASTEXITCODE -ne 0) { throw 'Integration test compilation failed.' }
    $test = New-Object System.Diagnostics.Process
    $test.StartInfo.FileName = $integrationExe
    $test.StartInfo.UseShellExecute = $false
    $test.StartInfo.CreateNoWindow = $true
    $test.StartInfo.RedirectStandardOutput = $true
    $test.StartInfo.RedirectStandardError = $true
    try {
        if (-not $test.Start()) { throw 'Cannot start Windows integration tests.' }
        $stdoutTask = $test.StandardOutput.ReadToEndAsync()
        $stderrTask = $test.StandardError.ReadToEndAsync()
        if (-not $test.WaitForExit(30000)) {
            $test.Kill() # Exact child test process; its job reaps only its fixtures.
            $test.WaitForExit()
            Write-Host $stdoutTask.Result
            if ($stderrTask.Result) { Write-Host $stderrTask.Result }
            throw 'Windows integration tests exceeded 30 seconds.'
        }
        Write-Host $stdoutTask.Result
        if ($stderrTask.Result) { Write-Host $stderrTask.Result }
        if ($test.ExitCode -ne 0) { throw 'Windows integration tests failed.' }
    } finally { $test.Dispose() }
    return
}

if ($ProbeOnly) {
    New-Item -ItemType Directory -Force -Path $probeDir | Out-Null
    $probeArgs = @(
        '-std=c++17', '-O2', '-DNDEBUG', '-D_WIN32_WINNT=0x0A00', '-DWINVER=0x0A00',
        '-static', '-static-libgcc', '-static-libstdc++', '-Wall', '-Wextra', '-Wpedantic',
        '-Werror', '-Wl,--no-insert-timestamp'
    )
    $probeTestExe = Join-Path $probeDir 'activity_tests.exe'
    if (-not $SkipTests) {
        & $compiler @probeArgs (Join-Path $projectRoot 'tests\activity_tests.cpp') '-o' $probeTestExe
        if ($LASTEXITCODE -ne 0) { throw 'Probe test compilation failed.' }
        & $probeTestExe
        if ($LASTEXITCODE -ne 0) { throw 'Probe tests failed.' }
        $platformTestExe = Join-Path $probeDir 'platform_tests.exe'
        & $compiler @probeArgs (Join-Path $projectRoot 'tests\platform_tests.cpp') `
            (Join-Path $projectRoot 'src\platform\windows_support.cpp') '-o' $platformTestExe `
            '-lole32' '-luuid' '-luser32' '-ladvapi32' '-lsetupapi'
        if ($LASTEXITCODE -ne 0) { throw 'Platform test compilation failed.' }
        & $platformTestExe
        if ($LASTEXITCODE -ne 0) { throw 'Platform tests failed.' }
    }
    $probeResource = Join-Path $probeDir 'probe.res'
    & $windres (Join-Path $projectRoot 'tools\probe.rc') '-I' (Join-Path $projectRoot 'tools') '-O' 'coff' '-o' $probeResource
    if ($LASTEXITCODE -ne 0) { throw 'Probe resource compilation failed.' }
    $probeExe = Join-Path $probeDir 'CapsLangInventory.exe'
    & $compiler @probeArgs '-municode' '-mwindows' (Join-Path $projectRoot 'tools\capslang_probe.cpp') `
        (Join-Path $projectRoot 'src\platform\windows_support.cpp') $probeResource '-o' $probeExe `
        '-lole32' '-luuid' '-luser32' '-ladvapi32' '-lsetupapi' '-lshell32' '-lcomdlg32'
    if ($LASTEXITCODE -ne 0) { throw 'Probe compilation failed.' }
    Write-Host "Built read-only inventory (NOT CapsLang or a release candidate): $probeExe"
    Write-Host "SHA256: $((Get-FileHash -LiteralPath $probeExe -Algorithm SHA256).Hash)"
    return
}

$source = Join-Path $projectRoot 'src\capslang.cpp'
$resourceScript = Join-Path $projectRoot 'src\capslang.rc'
$resourceObject = Join-Path $buildDir 'capslang.res'
$testExe = Join-Path $buildDir 'capslang_tests.exe'
$appExe = Join-Path $distDir 'CapsLang.exe'

& $windres $resourceScript -I (Join-Path $projectRoot 'src') -O coff -o $resourceObject
if ($LASTEXITCODE -ne 0) { throw 'Resource compilation failed.' }

$commonArguments = @(
    '-std=c++17', '-O2', '-DNDEBUG',
    '-D_WIN32_WINNT=0x0A00', '-DWINVER=0x0A00',
    '-static', '-static-libgcc', '-static-libstdc++',
    '-Wall', '-Wextra', '-Wpedantic'
)
$libraries = @('-ladvapi32', '-lcomctl32', '-lshell32', '-lole32', '-luuid', '-lwtsapi32', '-luser32')

if (-not $SkipTests) {
    Write-Host 'Building state-machine tests...'
    & $compiler @commonArguments '-Wno-unused-function' '-DCAPSLANG_TEST' $source '-o' $testExe @libraries
    if ($LASTEXITCODE -ne 0) { throw 'Test compilation failed.' }
    & $testExe
    if ($LASTEXITCODE -ne 0) { throw 'CapsLang tests failed.' }
}

Write-Host 'Building CapsLang.exe...'
& $compiler @commonArguments '-municode' '-mwindows' $source $resourceObject '-o' $appExe @libraries
if ($LASTEXITCODE -ne 0) { throw 'CapsLang compilation failed.' }

$artifact = Get-Item -LiteralPath $appExe
$hash = (Get-FileHash -LiteralPath $appExe -Algorithm SHA256).Hash
Write-Host "Built $($artifact.FullName)"
Write-Host "Size: $($artifact.Length) bytes"
Write-Host "SHA256: $hash"
} finally { $env:PATHEXT = $originalPathExt }

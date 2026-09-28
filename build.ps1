[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$Clean,
    [switch]$ProbeOnly,
    [switch]$IntegrationOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($ProbeOnly -and $IntegrationOnly) { throw 'Choose either -ProbeOnly or -IntegrationOnly.' }
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
    if ($IntegrationOnly) {
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

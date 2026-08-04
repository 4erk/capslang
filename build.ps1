[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$buildDir = Join-Path $projectRoot 'build'
$distDir = Join-Path $projectRoot 'dist'
$toolRoot = Join-Path $env:LOCALAPPDATA 'CapsLangBuildCache'
$toolVersion = '20260616'
$archiveName = "llvm-mingw-$toolVersion-ucrt-x86_64.zip"
$archivePath = Join-Path $toolRoot $archiveName
$expandedRoot = Join-Path $toolRoot "llvm-mingw-$toolVersion-ucrt-x86_64"
$downloadUrl = "https://github.com/mstorsjo/llvm-mingw/releases/download/$toolVersion/$archiveName"
$expectedSha256 = 'b9b68a4d276e16fa25802aaba458e4638f64b3884c290aaccdc2d87083b6ca35'

if ($Clean) {
    Remove-Item -LiteralPath $buildDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $distDir -Recurse -Force -ErrorAction SilentlyContinue
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

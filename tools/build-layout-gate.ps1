[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Split-Path -Parent $PSScriptRoot
$compiler=Join-Path $env:LOCALAPPDATA 'CapsLangBuildCache\llvm-mingw-20260616-ucrt-x86_64\bin\clang++.exe'
if (!(Test-Path -LiteralPath $compiler)) { throw 'Pinned toolchain unavailable; run build.ps1 first.' }
$directory=Join-Path $root 'build\layout-gate'
New-Item -ItemType Directory -Force -Path $directory | Out-Null
$output=Join-Path $directory 'CapsLangLayoutGate.exe'
$oldPathExt=$env:PATHEXT
try {
    if (($env:PATHEXT -split ';') -notcontains '.EXE') { $env:PATHEXT+=';.EXE' }
    & $compiler '-std=c++17' '-O2' '-static' '-municode' '-Wall' '-Wextra' '-Werror' `
        '-Wl,--no-insert-timestamp' (Join-Path $PSScriptRoot 'layout_gate.cpp') `
        (Join-Path $root 'src\platform\windows_support.cpp') '-o' $output `
        '-lole32' '-luuid' '-luser32' '-ladvapi32' '-lsetupapi'
    if ($LASTEXITCODE -ne 0) { throw 'Layout gate compilation failed.' }
    Get-FileHash -LiteralPath $output -Algorithm SHA256
} finally { $env:PATHEXT=$oldPathExt }

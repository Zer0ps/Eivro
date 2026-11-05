$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
if (-not [Environment]::Is64BitProcess -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { throw 'Build on x64 Windows with the MSVC toolchain.' }
python scripts/fetch-windows.py
if ($LASTEXITCODE -ne 0) { throw 'Core verification failed.' }
& "$PSScriptRoot\fetch-inno.ps1"
cargo build --locked --release
if ($LASTEXITCODE -ne 0) { throw 'Release build failed.' }
& "$PSScriptRoot\package-windows.ps1"

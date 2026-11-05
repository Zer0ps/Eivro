param([switch]$AllowNetworkTests)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -and -not $AllowNetworkTests) {
    throw 'Use only in a disposable Windows lab; pass -AllowNetworkTests explicitly.'
}
Set-Location (Split-Path $PSScriptRoot -Parent)
$metadata = cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Cargo metadata failed.' }
$version = ($metadata.packages | Where-Object name -eq 'eivro').version
$installer = (Resolve-Path "dist\Eivro-$version-windows-x86_64-setup.exe").Path
foreach ($line in Get-Content dist\SHA256SUMS-windows-x86_64) {
    $parts = $line -split '  ',2
    if ($parts.Count -ne 2 -or (Get-FileHash (Join-Path dist $parts[1]) -Algorithm SHA256).Hash -ne $parts[0]) { throw 'Package checksum mismatch.' }
}
$directory = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Eivro'
if (Get-Service EivroTunnel -ErrorAction SilentlyContinue) { throw 'A pre-existing Eivro installation must not be replaced by this smoke test.' }
$before = Get-NetIPInterface | Select-Object InterfaceIndex,AddressFamily,WeakHostSend
$installed = $false
try {
    $setup = Start-Process -FilePath $installer -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART' -Wait -PassThru
    $installed = Test-Path "$directory\unins000.exe"
    if ($setup.ExitCode -ne 0) { throw 'Installer failed.' }
    if ((Get-Service EivroTunnel).Status -ne 'Running') { throw 'Tunnel service is not running.' }
    $owner = (Get-Acl "$directory\eivro-tun.exe").GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -ne 'S-1-5-32-544') { throw 'Unexpected helper ownership.' }
    $env:EIVRO_WINDOWS_LAB = '1'
    cargo test --locked --release --lib windows_lab_proxy_watchdog -- --ignored --test-threads=1
    if ($LASTEXITCODE -ne 0) { throw 'System proxy recovery test failed.' }
    cargo test --locked --release --test windows installed_tunnel_passes_https_and_restores_adapter -- --ignored --exact --test-threads=1 --nocapture
    if ($LASTEXITCODE -ne 0) { throw 'Installed tunnel test failed.' }
    foreach ($test in @(
        'windows_lab_named_exit_resolves_private_domains_and_rejects_missing_adapter',
        'windows_lab_application_paths_match_windows_case_and_separator_rules',
        'windows_lab_tunnel_recovers_from_client_core_and_service_loss'
    )) {
        cargo test --locked --release --test windows $test -- --ignored --exact --test-threads=1 --nocapture
        if ($LASTEXITCODE -ne 0) { throw "Installed network/recovery test failed: $test" }
    }
    if (Get-NetAdapter -Name Eivro -ErrorAction SilentlyContinue) { throw 'Tunnel adapter remained after disconnect.' }
    foreach ($row in $before) {
        $current = Get-NetIPInterface -AddressFamily $row.AddressFamily -InterfaceIndex $row.InterfaceIndex -ErrorAction SilentlyContinue
        if ($current -and $current.WeakHostSend -ne $row.WeakHostSend) { throw 'An existing adapter was not restored.' }
    }
} finally {
    Remove-Item Env:EIVRO_WINDOWS_LAB -ErrorAction SilentlyContinue
    if ($installed) {
        $uninstaller = Start-Process -FilePath "$directory\unins000.exe" -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART' -Wait -PassThru
        if ($uninstaller.ExitCode -ne 0) { throw 'Uninstall failed; inspect and restore this lab before continuing.' }
        if (Get-Service EivroTunnel -ErrorAction SilentlyContinue) { throw 'Service remained after uninstall.' }
    }
}

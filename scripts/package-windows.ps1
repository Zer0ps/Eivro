param([string]$Iscc)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
if (-not $Iscc) { $Iscc = Join-Path $root '.tools\inno\ISCC.exe' }
if (-not (Test-Path -LiteralPath $Iscc)) { throw 'Run scripts/fetch-inno.ps1 first.' }
$metadata = cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Cargo metadata failed.' }
$version = ($metadata.packages | Where-Object name -eq 'eivro').version
$stage = Join-Path $root 'work\windows-package'
$dist = Join-Path $root 'dist'
New-Item -ItemType Directory -Force $stage,$dist | Out-Null
# A fixed allowlist prevents settings, credentials and development files entering packages.
Get-ChildItem -LiteralPath $stage -File | Remove-Item -Force
$manifest = Get-Content scripts\windows-cores.json -Raw | ConvertFrom-Json
foreach ($core in @('sing-box','xray')) {
    foreach ($item in $manifest.$core.files.PSObject.Properties) {
        $path = Join-Path 'vendor\windows' $item.Value.target
        if ((Get-FileHash $path -Algorithm SHA256).Hash -ne $item.Value.sha256) { throw ('Core checksum mismatch: ' + $item.Value.target) }
        Copy-Item -LiteralPath $path -Destination $stage
    }
}
foreach ($name in @('eivro.exe','eivro-tun.exe')) {
    Copy-Item -LiteralPath (Join-Path $metadata.target_directory ('release\' + $name)) -Destination $stage
}
Copy-Item LICENSE,THIRD_PARTY.md -Destination $stage
Copy-Item assets\Inter.LICENSE,assets\NotoEmoji.LICENSE -Destination $stage
Copy-Item assets\rules\ru-direct\LICENSE -Destination (Join-Path $stage 'ru-direct.LICENSE')
Copy-Item assets\rules\ru-direct\source.json -Destination (Join-Path $stage 'ru-direct-source.json')
Copy-Item vendor\eframe\LICENSE-MIT -Destination (Join-Path $stage 'eframe.LICENSE-MIT')
Copy-Item vendor\eframe\LICENSE-APACHE -Destination (Join-Path $stage 'eframe.LICENSE-APACHE')
$portable = Join-Path $dist "Eivro-$version-windows-x86_64.zip"
$payload = @(Get-ChildItem -LiteralPath $stage -File | ForEach-Object FullName)
Compress-Archive -LiteralPath $payload -DestinationPath $portable -CompressionLevel Optimal -Force
& $Iscc "--define=AppVersion=$version" "--define=StageDir=$stage" "--define=OutputDir=$dist" packaging\windows\eivro.iss
if ($LASTEXITCODE -ne 0) { throw 'Windows installer compilation failed.' }
$installer = Join-Path $dist "Eivro-$version-windows-x86_64-setup.exe"
$lines = @($portable,$installer) | ForEach-Object { (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + (Split-Path $_ -Leaf) }
[IO.File]::WriteAllLines((Join-Path $dist 'SHA256SUMS-windows-x86_64'), $lines, [Text.UTF8Encoding]::new($false))
Get-Item $portable,$installer | Select-Object Name,Length

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$destination = Join-Path $root '.tools\inno'
$compiler = Join-Path $destination 'ISCC.exe'
if (Test-Path -LiteralPath $compiler) {
    $version = (& $compiler --version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $version -notmatch '\b7\.1\.1\b') { throw 'Unexpected Inno Setup version.' }
    Write-Output $compiler
    return
}
$installer = Join-Path ([IO.Path]::GetTempPath()) ('eivro-inno-' + [Guid]::NewGuid().ToString('N') + '.exe')
try {
    Invoke-WebRequest -UseBasicParsing -TimeoutSec 180 -Uri 'https://github.com/jrsoftware/issrc/releases/download/is-7_1_1/innosetup-7.1.1-x64.exe' -OutFile $installer
    if ((Get-FileHash $installer -Algorithm SHA256).Hash -ne '8a5a6711c3766a6e5fb74f280ba0e3551e719ce94538d901fdbd1f8f9920b3f0') { throw 'Inno Setup checksum mismatch.' }
    $signature = Get-AuthenticodeSignature $installer
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Pyrsys B\.V\.') { throw 'Inno Setup publisher verification failed.' }
    $process = Start-Process -FilePath $installer -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/CURRENTUSER',('/DIR="' + $destination + '"')) -Wait -PassThru
    if ($process.ExitCode -ne 0 -or -not (Test-Path $compiler)) { throw 'Inno Setup installation failed.' }
    $version = (& $compiler --version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $version -notmatch '\b7\.1\.1\b') { throw 'Unexpected installed compiler version.' }
    Write-Output $compiler
} finally {
    Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue
}

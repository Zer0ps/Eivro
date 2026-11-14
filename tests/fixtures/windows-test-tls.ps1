# Ephemeral loopback certificate. Nothing is installed into the Windows trust store.
$ErrorActionPreference = 'Stop'
$key = [System.Security.Cryptography.ECDsaCng]::new(256)
try {
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=mux.eivro.test', $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
    $dns = [Text.Encoding]::ASCII.GetBytes('mux.eivro.test')
    [byte[]]$san = @(0x30, ($dns.Length + 2), 0x82, $dns.Length) + $dns
    $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509Extension]::new('2.5.29.17', $san, $false))
    $certificate = $request.CreateSelfSigned([DateTimeOffset]::Now.AddMinutes(-5), [DateTimeOffset]::Now.AddDays(1))
    try {
        $der = $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        $private = $key.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
        @{certificate=@('-----BEGIN CERTIFICATE-----', [Convert]::ToBase64String($der), '-----END CERTIFICATE-----');
          key=@('-----BEGIN PRIVATE KEY-----', [Convert]::ToBase64String($private), '-----END PRIVATE KEY-----')} | ConvertTo-Json -Compress
    } finally { $certificate.Dispose() }
} finally { $key.Dispose() }

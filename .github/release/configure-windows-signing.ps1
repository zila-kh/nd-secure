$ErrorActionPreference = "Stop"

$values = @(
  $env:WINDOWS_CERTIFICATE,
  $env:WINDOWS_CERTIFICATE_PASSWORD,
  $env:WINDOWS_TIMESTAMP_URL
)
$present = @($values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
if ($present -eq 0) {
  Write-Host "Windows signing is not configured; building an unsigned NSIS installer."
  exit 0
}
if ($present -ne $values.Count) {
  throw "Configure all Windows signing secrets or none of them: WINDOWS_CERTIFICATE, WINDOWS_CERTIFICATE_PASSWORD, and WINDOWS_TIMESTAMP_URL."
}

$certificatePath = Join-Path $env:RUNNER_TEMP "windows-certificate.pfx"
$normalizedCertificate = $env:WINDOWS_CERTIFICATE -replace '\s', ''
[System.IO.File]::WriteAllBytes(
  $certificatePath,
  [System.Convert]::FromBase64String($normalizedCertificate)
)

$password = ConvertTo-SecureString -String $env:WINDOWS_CERTIFICATE_PASSWORD -AsPlainText -Force
$imported = @(Import-PfxCertificate -FilePath $certificatePath -CertStoreLocation Cert:\CurrentUser\My -Password $password)
$signingCertificates = @($imported | Where-Object { $_.HasPrivateKey })
if ($signingCertificates.Count -ne 1) {
  throw "Expected exactly one imported Windows certificate with a private key, found $($signingCertificates.Count)."
}

$now = Get-Date
$certificate = $signingCertificates[0]
if ($certificate.NotBefore -gt $now -or $certificate.NotAfter -lt $now) {
  throw "The configured Windows code-signing certificate is not currently valid."
}

$config = Get-Content -Path $env:RELEASE_CONFIG -Raw | ConvertFrom-Json
if ($null -eq $config.bundle.windows) {
  $config.bundle | Add-Member -NotePropertyName windows -NotePropertyValue ([pscustomobject]@{})
}
$config.bundle.windows | Add-Member -Force -NotePropertyName certificateThumbprint -NotePropertyValue $certificate.Thumbprint
$config.bundle.windows | Add-Member -Force -NotePropertyName digestAlgorithm -NotePropertyValue "sha256"
$config.bundle.windows | Add-Member -Force -NotePropertyName timestampUrl -NotePropertyValue $env:WINDOWS_TIMESTAMP_URL
$config | ConvertTo-Json -Depth 20 | Set-Content -Path $env:RELEASE_CONFIG -Encoding utf8NoBOM

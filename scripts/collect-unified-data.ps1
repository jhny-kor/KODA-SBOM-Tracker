[CmdletBinding()]
param(
    [string]$SigningKey,
    [string]$VerifyKey,
    [string]$OutputArchive,
    [string]$Python = 'python',
    [string]$OpenSsl,
    [string]$GrypeBinary
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$collector = Join-Path $PSScriptRoot 'collect-windows-vulnerability-data.py'
$arguments = @($collector)
if ($SigningKey) {
    $arguments += @('--signing-key', $SigningKey)
}
if ($VerifyKey) {
    $arguments += @('--verify-key', $VerifyKey)
}
if ($OpenSsl) {
    $arguments += @('--openssl', $OpenSsl)
}
if ($OutputArchive) {
    $arguments += @('--output', $OutputArchive)
}
if ($GrypeBinary) {
    $arguments += @('--grype-binary', $GrypeBinary)
}

& $Python @arguments
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

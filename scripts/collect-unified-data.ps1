[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SigningKey,
    [Parameter(Mandatory = $true)][string]$VerifyKey,
    [string]$OutputArchive,
    [string]$Python = 'python',
    [string]$OpenSsl = 'openssl',
    [string]$GrypeBinary
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$collector = Join-Path $PSScriptRoot 'collect-windows-vulnerability-data.py'
$arguments = @($collector, '--signing-key', $SigningKey, '--verify-key', $VerifyKey, '--openssl', $OpenSsl)
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

[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 5173,
    [switch]$OpenBrowser
)

$ErrorActionPreference = "Stop"
$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$WebDir = Join-Path $RootDir "apps\web"
$npm = Get-Command npm.cmd -ErrorAction SilentlyContinue
if ($null -eq $npm) {
    $npm = Get-Command npm -ErrorAction SilentlyContinue
}
if ($null -eq $npm) {
    throw "Node.js/npm을 찾을 수 없습니다. Node.js LTS를 설치한 뒤 새 PowerShell을 여세요."
}
if (-not (Test-Path -LiteralPath (Join-Path $WebDir "package.json"))) {
    throw "웹 앱 package.json을 찾을 수 없습니다: $WebDir"
}

$env:VITE_STANDALONE_MODE = "true"
$env:VITE_DEMO_MODE = "false"
$url = "http://127.0.0.1:$Port/?page=dashboard"
Write-Host "Docker·로그인 없이 로컬 미리보기를 시작합니다: $url"
Write-Host "종료하려면 이 창에서 Ctrl+C를 누르세요."
if ($OpenBrowser) {
    Start-Job -ArgumentList $url -ScriptBlock {
        param($TargetUrl)
        Start-Sleep -Seconds 2
        Start-Process $TargetUrl | Out-Null
    } | Out-Null
}

Push-Location $WebDir
try {
    & $npm.Source run dev -- --host 127.0.0.1 --port $Port
    if ($LASTEXITCODE -ne 0) {
        throw "로컬 미리보기 서버가 종료 코드 $LASTEXITCODE 로 끝났습니다."
    }
} finally {
    Pop-Location
}

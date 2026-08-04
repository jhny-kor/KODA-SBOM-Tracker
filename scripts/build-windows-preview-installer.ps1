[CmdletBinding()]
param(
    [string]$OutputDir = "",
    [string]$InnoSetupPath = "",
    [ValidatePattern("^[0-9][0-9A-Za-z.-]*$")]
    [string]$Version = "0.1.0",
    [switch]$SkipNpmInstall
)

$ErrorActionPreference = "Stop"
$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$WebDir = Join-Path $RootDir "apps\web"
$WebDistDir = Join-Path $WebDir "dist"
$IssFile = Join-Path $RootDir "installer\koda-sbom-tracker-preview.iss"
$ServerScript = Join-Path $RootDir "scripts\serve-windows-preview.ps1"
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $RootDir "dist\windows"
} elseif (-not [System.IO.Path]::IsPathRooted($OutputDir)) {
    $OutputDir = Join-Path (Get-Location).Path $OutputDir
}
$OutputDir = [System.IO.Path]::GetFullPath($OutputDir)

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [string]$WorkingDirectory = ""
    )

    if ([System.IO.Path]::IsPathRooted($Command) -and -not (Test-Path -LiteralPath $Command -PathType Leaf)) {
        throw "실행 파일을 찾을 수 없습니다: $Command"
    }
    Write-Host (">> " + $Command + " " + ($Arguments -join " "))
    if ([string]::IsNullOrWhiteSpace($WorkingDirectory)) {
        & $Command @Arguments
    } else {
        Push-Location $WorkingDirectory
        try {
            & $Command @Arguments
        } finally {
            Pop-Location
        }
    }
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "$Command failed with exit code $exitCode"
    }
}

function Resolve-ExecutablePath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }
    $candidate = $Path.Trim().Trim('"')
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        return (Resolve-Path -LiteralPath $candidate).Path
    }
    return $null
}

function Resolve-InnoSetup {
    param([string]$RequestedPath)

    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
        $resolved = Resolve-ExecutablePath -Path $RequestedPath
        if ($null -ne $resolved) {
            return $resolved
        }
        throw "지정한 Inno Setup ISCC.exe를 찾을 수 없습니다: $RequestedPath"
    }
    $resolved = Resolve-ExecutablePath -Path $env:ISCC
    if ($null -ne $resolved) {
        return $resolved
    }

    $command = Get-Command iscc.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $command) {
        $commandPath = $command.Source
        if ($command.PSObject.Properties.Name -contains "Path") {
            $commandPath = $command.Path
        }
        $resolved = Resolve-ExecutablePath -Path $commandPath
        if ($null -ne $resolved) {
            return $resolved
        }
    }
    $candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"),
        (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe")
    )
    foreach ($candidate in $candidates) {
        $resolved = Resolve-ExecutablePath -Path $candidate
        if ($null -ne $resolved) {
            return $resolved
        }
    }
    throw "Inno Setup 6의 ISCC.exe를 찾을 수 없습니다. Inno Setup 6을 설치하거나 -InnoSetupPath `"C:\Program Files (x86)\Inno Setup 6\ISCC.exe`"를 지정하세요."
}

function Resolve-Npm {
    $command = Get-Command npm.cmd -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        $command = Get-Command npm -ErrorAction SilentlyContinue
    }
    if ($null -eq $command) {
        throw "Node.js/npm을 찾을 수 없습니다. 빌드 PC에 Node.js LTS를 설치한 뒤 새 PowerShell을 여세요."
    }
    return $command.Source
}

if (-not (Test-Path -LiteralPath (Join-Path $WebDir "package.json"))) {
    throw "웹 앱 package.json을 찾을 수 없습니다: $WebDir"
}
if (-not (Test-Path -LiteralPath $IssFile)) {
    throw "Inno Setup 정의 파일이 없습니다: $IssFile"
}
if (-not (Test-Path -LiteralPath $ServerScript)) {
    throw "정적 서버 스크립트가 없습니다: $ServerScript"
}

$npm = Resolve-Npm
$iscc = Resolve-InnoSetup -RequestedPath $InnoSetupPath
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$env:VITE_STANDALONE_MODE = "true"
$env:VITE_DEMO_MODE = "false"
$stageDir = Join-Path $OutputDir (".stage-preview-" + [Guid]::NewGuid().ToString("N"))
try {
    if (-not $SkipNpmInstall) {
        Invoke-Checked -Command $npm -Arguments @("ci") -WorkingDirectory $WebDir
    }
    Invoke-Checked -Command $npm -Arguments @("run", "build") -WorkingDirectory $WebDir
    if (-not (Test-Path -LiteralPath (Join-Path $WebDistDir "index.html"))) {
        throw "standalone 웹 빌드 결과에 index.html이 없습니다: $WebDistDir"
    }

    New-Item -ItemType Directory -Path (Join-Path $stageDir "web") -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $stageDir "scripts") -Force | Out-Null
    Copy-Item -Path (Join-Path $WebDistDir "*") -Destination (Join-Path $stageDir "web") -Recurse -Force
    Copy-Item -LiteralPath $ServerScript -Destination (Join-Path $stageDir "scripts\serve-windows-preview.ps1") -Force
    @(
        "KODA SBOM Tracker Preview",
        "",
        "Start Menu에서 'KODA SBOM Tracker Preview'를 실행하세요.",
        "대시보드: http://127.0.0.1:5173/?page=dashboard",
        "",
        "이 설치파일은 Docker Desktop과 Node.js 없이 동작합니다.",
        "CycloneDX JSON/XML SBOM을 브라우저에서 업로드하면 구성요소와 파일 내 취약점을 확인할 수 있습니다.",
        "업로드 데이터는 브라우저 메모리에만 저장되며 새로고침하면 사라집니다."
    ) | Set-Content -LiteralPath (Join-Path $stageDir "README-preview.txt") -Encoding UTF8

    $env:KODA_PREVIEW_STAGE = $stageDir
    $env:KODA_PREVIEW_OUTPUT = $OutputDir
    $env:KODA_PREVIEW_VERSION = $Version
    $installerPath = Join-Path $OutputDir "KODA-SBOM-Tracker-Preview-Setup.exe"
    if (Test-Path -LiteralPath $installerPath) {
        Remove-Item -LiteralPath $installerPath -Force
    }
    Invoke-Checked -Command $iscc -Arguments @($IssFile)
    if (-not (Test-Path -LiteralPath $installerPath)) {
        throw "Inno Setup이 preview installer를 만들지 못했습니다: $installerPath"
    }
    Write-Host "Dockerless Windows preview installer 생성 완료: $installerPath"
} finally {
    Remove-Item Env:VITE_STANDALONE_MODE -ErrorAction SilentlyContinue
    Remove-Item Env:VITE_DEMO_MODE -ErrorAction SilentlyContinue
    Remove-Item Env:KODA_PREVIEW_STAGE -ErrorAction SilentlyContinue
    Remove-Item Env:KODA_PREVIEW_OUTPUT -ErrorAction SilentlyContinue
    Remove-Item Env:KODA_PREVIEW_VERSION -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $stageDir) {
        Remove-Item -LiteralPath $stageDir -Recurse -Force
    }
}

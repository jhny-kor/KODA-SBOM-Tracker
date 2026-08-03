[CmdletBinding()]
param(
    [string]$OutputDir = "",
    [string]$InnoSetupPath = "",
    [ValidatePattern("^[0-9][0-9A-Za-z.-]*$")]
    [string]$Version = "0.1.0",
    [switch]$SkipDockerBuild
)

$ErrorActionPreference = "Stop"
$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $RootDir "dist\windows"
} elseif (-not [System.IO.Path]::IsPathRooted($OutputDir)) {
    $OutputDir = Join-Path (Get-Location).Path $OutputDir
}
$OutputDir = [System.IO.Path]::GetFullPath($OutputDir)
$envExample = Join-Path $RootDir ".env.example"
$composeFile = Join-Path $RootDir "compose.yaml"
$airgapComposeFile = Join-Path $RootDir "compose.airgap.yaml"
$issFile = Join-Path $RootDir "installer\koda-sbom-tracker.iss"
. (Join-Path $PSScriptRoot "resolve-docker-cli.ps1")

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    Write-Host (">> " + $Command + " " + ($Arguments -join " "))
    & $Command @Arguments
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "$Command failed with exit code $exitCode"
    }
}

function Get-DotEnvValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match "^\s*$Name\s*=(.*)$") {
            $value = $Matches[1].Trim()
            if (($value.StartsWith("'") -and $value.EndsWith("'")) -or ($value.StartsWith('"') -and $value.EndsWith('"'))) {
                $value = $value.Substring(1, $value.Length - 2)
            }
            return $value
        }
    }
    return $null
}

function Resolve-InnoSetup {
    param([string]$RequestedPath)

    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
        if (Test-Path -LiteralPath $RequestedPath) {
            return (Resolve-Path -LiteralPath $RequestedPath).Path
        }
        throw "Inno Setup ISCC.exe를 찾을 수 없습니다: $RequestedPath"
    }

    if (-not [string]::IsNullOrWhiteSpace($env:ISCC) -and (Test-Path -LiteralPath $env:ISCC)) {
        return (Resolve-Path -LiteralPath $env:ISCC).Path
    }

    $command = Get-Command iscc.exe -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }

    $candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"),
        (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe")
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_) }
    if ($candidates.Count -gt 0) {
        return $candidates[0]
    }
    throw "Inno Setup 6의 ISCC.exe를 찾을 수 없습니다. 설치 후 -InnoSetupPath 또는 ISCC 환경변수를 지정하세요."
}

Initialize-KodaDockerCliPath
if (-not (Test-Path -LiteralPath $envExample)) { throw "파일이 없습니다: $envExample" }
if (-not (Test-Path -LiteralPath $composeFile)) { throw "파일이 없습니다: $composeFile" }
if (-not (Test-Path -LiteralPath $airgapComposeFile)) { throw "파일이 없습니다: $airgapComposeFile" }
if (-not (Test-Path -LiteralPath $issFile)) { throw "파일이 없습니다: $issFile" }
$iscc = Resolve-InnoSetup -RequestedPath $InnoSetupPath
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
Invoke-Checked -Command "docker" -Arguments @("info")

$env:DOCKER_DEFAULT_PLATFORM = "linux/amd64"
$composeArgs = @("compose", "--env-file", $envExample, "-f", $composeFile, "-f", $airgapComposeFile)
if (-not $SkipDockerBuild) {
    Invoke-Checked -Command "docker" -Arguments ($composeArgs + @("build", "portal-web", "portal-api", "portal-worker"))
}

$remoteImageKeys = @(
    "DTRACK_APISERVER_IMAGE",
    "DTRACK_FRONTEND_IMAGE",
    "POSTGRES_IMAGE",
    "NGINX_IMAGE",
    "GRYPE_IMAGE",
    "CYCLONEDX_CLI_IMAGE",
    "ALPINE_BASE_IMAGE"
)
$remoteImages = foreach ($key in $remoteImageKeys) {
    $value = Get-DotEnvValue -Path $envExample -Name $key
    if ([string]::IsNullOrWhiteSpace($value)) { throw "$key 값이 .env.example에 없습니다." }
    $value
}
$portalImageTag = Get-DotEnvValue -Path $envExample -Name "PORTAL_IMAGE_TAG"
if ([string]::IsNullOrWhiteSpace($portalImageTag)) { $portalImageTag = "dev" }
$localImages = @(
    "$(Get-DotEnvValue -Path $envExample -Name PORTAL_WEB_IMAGE):$portalImageTag",
    "$(Get-DotEnvValue -Path $envExample -Name PORTAL_API_IMAGE):$portalImageTag",
    "$(Get-DotEnvValue -Path $envExample -Name PORTAL_WORKER_IMAGE):$portalImageTag"
)
$allImages = @($remoteImages + $localImages) | Select-Object -Unique

foreach ($image in $remoteImages) {
    Invoke-Checked -Command "docker" -Arguments @("pull", "--platform", "linux/amd64", $image)
}

$stageDir = Join-Path $OutputDir (".stage-" + [Guid]::NewGuid().ToString("N"))
try {
    New-Item -ItemType Directory -Path (Join-Path $stageDir "images") -Force | Out-Null
    foreach ($image in $allImages) {
        $platform = (& docker image inspect $image --format "{{.Os}}/{{.Architecture}}")
        $inspectExitCode = $LASTEXITCODE
        if ($inspectExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($platform)) {
            throw "Docker image를 찾을 수 없습니다: $image"
        }
        $platform = $platform.Trim()
        if ($platform -ne "linux/amd64") {
            throw "linux/amd64가 아닌 image입니다: $image ($platform)"
        }
        $safeName = $image -replace "[/@:]", "___"
        $archivePath = Join-Path $stageDir "images\$safeName.tar"
        Invoke-Checked -Command "docker" -Arguments @("save", "--platform", "linux/amd64", "--output", $archivePath, $image)
    }

    foreach ($path in @("compose.yaml", "compose.airgap.yaml", ".env.example", "README.md")) {
        Copy-Item -LiteralPath (Join-Path $RootDir $path) -Destination (Join-Path $stageDir $path) -Force
    }
    foreach ($directory in @("scripts", "docs", "deploy")) {
        Copy-Item -LiteralPath (Join-Path $RootDir $directory) -Destination (Join-Path $stageDir $directory) -Recurse -Force
    }

    $createdAt = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    @(
        "RELEASE_CREATED_AT=$createdAt",
        "TARGET_PLATFORM=linux/amd64",
        "INSTALLER=KODA-SBOM-Tracker-Setup.exe",
        "RUNTIME_SOURCE=.env.example only; production .env is supplied after installation"
    ) | Set-Content -LiteralPath (Join-Path $stageDir "metadata.env") -Encoding UTF8

    $manifestPath = Join-Path $stageDir "manifest.sha256"
    $manifest = Get-ChildItem -LiteralPath $stageDir -Recurse -File |
        Where-Object { $_.FullName -ne $manifestPath } |
        Sort-Object FullName |
        ForEach-Object {
            $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
            $relative = $_.FullName.Substring($stageDir.Length + 1).Replace("\", "/")
            "$hash  $relative"
        }
    $manifest | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    $env:KODA_WINDOWS_STAGE = $stageDir
    $env:KODA_WINDOWS_OUTPUT = $OutputDir
    $env:KODA_WINDOWS_VERSION = $Version
    $installerPath = Join-Path $OutputDir "KODA-SBOM-Tracker-Setup.exe"
    if (Test-Path -LiteralPath $installerPath) {
        Remove-Item -LiteralPath $installerPath -Force
    }
    Invoke-Checked -Command $iscc -Arguments @($issFile)
    if (-not (Test-Path -LiteralPath $installerPath)) {
        throw "Inno Setup이 installer를 만들지 못했습니다: $installerPath"
    }
    Write-Host "Windows installer 생성 완료: $installerPath"
} finally {
    Remove-Item Env:KODA_WINDOWS_STAGE -ErrorAction SilentlyContinue
    Remove-Item Env:KODA_WINDOWS_OUTPUT -ErrorAction SilentlyContinue
    Remove-Item Env:KODA_WINDOWS_VERSION -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $stageDir) {
        Remove-Item -LiteralPath $stageDir -Recurse -Force
    }
}

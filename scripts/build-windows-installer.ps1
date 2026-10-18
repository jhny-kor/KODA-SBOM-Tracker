[CmdletBinding()]
param(
    [string]$OutputDir = "",
    [string]$InnoSetupPath = "",
    [ValidatePattern("^[0-9][0-9A-Za-z.-]*$")]
    [string]$Version = "0.1.0",
    [ValidateSet("Internal", "External")]
    [string]$DistributionScope = "Internal",
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

if ($DistributionScope -eq "External") {
    throw "외부 배포용 이미지 번들은 지원하지 않습니다. 대응 소스 제공 절차와 법무 검토가 승인된 뒤 별도 릴리스를 구성하세요."
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    if ([System.IO.Path]::IsPathRooted($Command) -and -not (Test-Path -LiteralPath $Command -PathType Leaf)) {
        throw "실행 파일을 찾을 수 없습니다: $Command"
    }
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

Initialize-KodaDockerCliPath
if (-not (Test-Path -LiteralPath $envExample)) { throw "파일이 없습니다: $envExample" }
if (-not (Test-Path -LiteralPath $composeFile)) { throw "파일이 없습니다: $composeFile" }
if (-not (Test-Path -LiteralPath $airgapComposeFile)) { throw "파일이 없습니다: $airgapComposeFile" }
if (-not (Test-Path -LiteralPath $issFile)) { throw "파일이 없습니다: $issFile" }
foreach ($path in @("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md")) {
    if (-not (Test-Path -LiteralPath (Join-Path $RootDir $path) -PathType Leaf)) { throw "파일이 없습니다: $path" }
}
$iscc = Resolve-InnoSetup -RequestedPath $InnoSetupPath
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
Invoke-Checked -Command "docker" -Arguments @("info")

$env:DOCKER_DEFAULT_PLATFORM = "linux/amd64"
$composeArgs = @("compose", "--env-file", $envExample, "-f", $composeFile, "-f", $airgapComposeFile)
if (-not $SkipDockerBuild) {
    Invoke-Checked -Command "docker" -Arguments ($composeArgs + @("build", "portal-web", "portal-api", "portal-worker"))
}

$remoteImageKeys = @(
    "POSTGRES_IMAGE",
    "NGINX_IMAGE",
    "GRYPE_IMAGE",
    "CYCLONEDX_CLI_IMAGE",
    "ALPINE_BASE_IMAGE"
)
if ($env:KODA_INCLUDE_DEPENDENCY_TRACK -match '^(?i:true|1)$') {
    $remoteImageKeys += @("DTRACK_APISERVER_IMAGE", "DTRACK_FRONTEND_IMAGE")
}
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

    foreach ($path in @("compose.yaml", "compose.airgap.yaml", ".env.example", "README.md", "LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md")) {
        Copy-Item -LiteralPath (Join-Path $RootDir $path) -Destination (Join-Path $stageDir $path) -Force
    }
    foreach ($directory in @("scripts", "docs", "deploy")) {
        Copy-Item -LiteralPath (Join-Path $RootDir $directory) -Destination (Join-Path $stageDir $directory) -Recurse -Force
    }

    $createdAt = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    @(
        "RELEASE_CREATED_AT=$createdAt",
        "TARGET_PLATFORM=linux/amd64",
        "DISTRIBUTION_SCOPE=internal-only",
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

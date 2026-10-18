[CmdletBinding()]
param(
    [ValidateSet("Start", "Stop", "Status")]
    [string]$Action = "Start",
    [switch]$OpenDashboard,
    [ValidateRange(30, 3600)]
    [int]$HealthTimeoutSeconds = 300
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $PSScriptRoot
$EnvFile = Join-Path $RootDir ".env"
$ExampleEnvFile = Join-Path $RootDir ".env.example"
$ComposeFiles = @(
    "compose", "--env-file", $EnvFile,
    "-f", (Join-Path $RootDir "compose.yaml"),
    "-f", (Join-Path $RootDir "compose.airgap.yaml")
)
. (Join-Path $PSScriptRoot "resolve-docker-cli.ps1")

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

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

function Assert-DockerReady {
    Initialize-KodaDockerCliPath
    & docker info *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Desktop이 실행 중이 아닙니다. Docker Desktop을 시작한 뒤 다시 실행하세요."
    }
}

function Test-HttpEndpoint {
    param([Parameter(Mandatory = $true)][string]$Url)

    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 5
        return $response.StatusCode -ge 200 -and $response.StatusCode -lt 400
    } catch {
        return $false
    }
}

function Test-ExpectedComposeServices {
    param(
        [Parameter(Mandatory = $true)][string[]]$Services,
        [Parameter(Mandatory = $true)][string[]]$ComposeArguments
    )

    if ($Services.Count -eq 0) { return $false }
    foreach ($service in $Services) {
        $ids = @(& docker @($ComposeArguments + @("ps", "-a", "-q", $service)))
        if ($LASTEXITCODE -ne 0 -or $ids.Count -eq 0) { return $false }
        foreach ($containerId in $ids) {
            if ([string]::IsNullOrWhiteSpace($containerId)) { return $false }
            $state = & docker inspect -f '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' $containerId
            if ($LASTEXITCODE -ne 0 -or $state -notmatch '^running(?:\s|$)' -or $state -match 'starting|unhealthy') { return $false }
        }
    }
    return $true
}

function Import-BundledImages {
    $imageDir = Join-Path $RootDir "images"
    $manifestPath = Join-Path $RootDir "manifest.sha256"
    $stateRoot = if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        Join-Path $env:LOCALAPPDATA "KODA-SBOM-Tracker"
    } else {
        Join-Path $RootDir ".windows-state"
    }
    New-Item -ItemType Directory -Path $stateRoot -Force | Out-Null
    $markerPath = Join-Path $stateRoot "images.loaded"
    $archives = @(Get-ChildItem -LiteralPath $imageDir -Filter "*.tar" -File -ErrorAction SilentlyContinue | Sort-Object Name)
    if ($archives.Count -eq 0) {
        throw "설치 파일에 Docker image tar가 없습니다: $imageDir"
    }

    $manifestHash = if (Test-Path -LiteralPath $manifestPath) {
        (Get-FileHash -Algorithm SHA256 -LiteralPath $manifestPath).Hash
    } else {
        "no-manifest"
    }
    $needsImport = -not (Test-Path -LiteralPath $markerPath) -or ((Get-Content -Raw -LiteralPath $markerPath).Trim() -ne $manifestHash)
    if (-not $needsImport) {
        $configuredImages = @(& docker @($ComposeFiles + @("config", "--images")))
        if ($LASTEXITCODE -ne 0 -or $configuredImages.Count -eq 0) {
            $needsImport = $true
        } else {
            foreach ($image in $configuredImages) {
                & docker image inspect $image *> $null
                if ($LASTEXITCODE -ne 0) {
                    $needsImport = $true
                    break
                }
            }
        }
    }
    if (-not $needsImport) {
        return
    }

    foreach ($archive in $archives) {
        Write-Host "Docker image 로드: $($archive.Name)"
        Invoke-Checked -Command "docker" -Arguments @("load", "--input", $archive.FullName)
    }
    Set-Content -LiteralPath $markerPath -Value $manifestHash -Encoding ASCII
}

if (-not (Test-Path -LiteralPath $ExampleEnvFile)) {
    throw "설치 파일에 .env.example이 없습니다: $ExampleEnvFile"
}

if ($Action -eq "Start" -and -not (Test-Path -LiteralPath $EnvFile)) {
    Copy-Item -LiteralPath $ExampleEnvFile -Destination $EnvFile
    throw "`.env`를 만들었습니다. 실제 비밀번호/API 키를 입력한 뒤 다시 실행하세요: $EnvFile"
}

$ComposeEnvFile = if (Test-Path -LiteralPath $EnvFile) { $EnvFile } else { $ExampleEnvFile }
$ComposeFiles[2] = $ComposeEnvFile

$dependencyTrackEnabled = (Get-DotEnvValue -Path $ComposeEnvFile -Name "TRACKER_DEPENDENCY_TRACK_ENABLED") -match '^(?i:true|1|yes|on)$'
if ($dependencyTrackEnabled) { $ComposeFiles += @("--profile", "dependency-track") }

Assert-DockerReady

if ($Action -eq "Status") {
    Invoke-Checked -Command "docker" -Arguments ($ComposeFiles + @("ps"))
    exit 0
}

if ($Action -eq "Stop") {
    Invoke-Checked -Command "docker" -Arguments ($ComposeFiles + @("down"))
    Write-Host "KODA SBOM Tracker를 중지했습니다. Docker named volume의 데이터는 보존됩니다."
    exit 0
}

$requiredNames = @(
    "POSTGRES_PASSWORD",
    "TRACKER_DB_PASSWORD",
    "TRACKER_BOOTSTRAP_ADMIN_PASSWORD",
    "TRACKER_DATABASE_URL"
)
if ($dependencyTrackEnabled) { $requiredNames += @("DTRACK_DB_PASSWORD", "TRACKER_DEPENDENCY_TRACK_API_KEY") }
foreach ($name in $requiredNames) {
    $value = Get-DotEnvValue -Path $EnvFile -Name $name
    if ([string]::IsNullOrWhiteSpace($value) -or $value -match "(?i)(change-me-|your-|example|todo|<[^>]+>)") {
        throw "$name 값이 없거나 예시 값입니다. $EnvFile 을 수정하세요."
    }
}

Import-BundledImages
& docker @($ComposeFiles + @("config")) *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Docker Compose 설정이 올바르지 않습니다. $EnvFile 과 Compose 파일을 확인하세요."
}
if ($dependencyTrackEnabled) {
    Invoke-Checked -Command "docker" -Arguments ($ComposeFiles + @("up", "-d", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "$HealthTimeoutSeconds", "postgres"))
    Invoke-Checked -Command "docker" -Arguments ($ComposeFiles + @("exec", "-T", "postgres", "sh", "/docker-entrypoint-initdb.d/10-init-multi-db.sh"))
}
Invoke-Checked -Command "docker" -Arguments ($ComposeFiles + @("up", "-d", "--no-build", "--pull", "never"))

$port = 8088
$portValue = Get-DotEnvValue -Path $EnvFile -Name "PUBLIC_HTTP_PORT"
if (-not [string]::IsNullOrWhiteSpace($portValue)) {
    try {
        $port = [int]$portValue
    } catch {
        throw "PUBLIC_HTTP_PORT가 올바른 숫자가 아닙니다: $portValue"
    }
}
if ($port -lt 1 -or $port -gt 65535) {
    throw "PUBLIC_HTTP_PORT 범위가 올바르지 않습니다: $port"
}

$baseUrl = "http://127.0.0.1:$port"
$endpoints = @("$baseUrl/healthz", "$baseUrl/api/v1/healthz")
if ($dependencyTrackEnabled) { $endpoints += @("$baseUrl/dependency-track/", "$baseUrl/dependency-track/api/version") }
$expectedServices = @(& docker @($ComposeFiles + @("config", "--services")))
if ($LASTEXITCODE -ne 0 -or $expectedServices.Count -eq 0) { throw "기동할 Compose 서비스를 확인할 수 없습니다." }
if (-not $dependencyTrackEnabled) { $expectedServices = @($expectedServices | Where-Object { $_ -notin @("dtrack-apiserver", "dtrack-frontend") }) }
$deadline = (Get-Date).AddSeconds($HealthTimeoutSeconds)
$ready = $false
while ((Get-Date) -lt $deadline) {
    $ready = (Test-ExpectedComposeServices -Services $expectedServices -ComposeArguments $ComposeFiles) -and (($endpoints | ForEach-Object { Test-HttpEndpoint -Url $_ }) -notcontains $false)
    if ($ready) {
        break
    }
    Start-Sleep -Seconds 5
}

if (-not $ready) {
    & docker @($ComposeFiles + @("ps"))
    throw "서비스가 $HealthTimeoutSeconds 초 안에 준비되지 않았습니다. 위 상태와 Docker Desktop 로그를 확인하세요."
}

$dashboardUrl = "$baseUrl/?page=dashboard"
Write-Host "KODA SBOM Tracker가 준비되었습니다: $dashboardUrl"
if ($OpenDashboard) {
    Start-Process $dashboardUrl | Out-Null
}

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$GrypeDbPath,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')]
    [string]$DataDate,
    [string]$OutputArchive = "",
    [string]$Version = "",
    [string]$NvdIndex = "",
    [string[]]$NvdFeed = @(),
    [string]$NvdDate = "unknown",
    [string]$AliasIndex = "",
    [string]$KevCatalog = "",
    [string]$KevDate = "unknown",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$UtcNow = [DateTime]::UtcNow
if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = $UtcNow.ToString("yyyyMMddTHHmmssZ")
}
if ($Version -notmatch '^[A-Za-z0-9._-]+$') {
    throw "Version에는 영문, 숫자, ., _, -만 사용할 수 있습니다: $Version"
}
if ($NvdDate -notmatch '^(unknown|\d{4}-\d{2}-\d{2})$') {
    throw "NvdDate는 YYYY-MM-DD 또는 unknown이어야 합니다: $NvdDate"
}
if ($KevDate -notmatch '^(unknown|\d{4}-\d{2}-\d{2})$') {
    throw "KevDate는 YYYY-MM-DD 또는 unknown이어야 합니다: $KevDate"
}
if (-not [string]::IsNullOrWhiteSpace($NvdIndex) -and @($NvdFeed).Count -gt 0) {
    throw "NvdIndex와 NvdFeed는 함께 사용할 수 없습니다."
}
if ([string]::IsNullOrWhiteSpace($OutputArchive)) {
    $OutputArchive = Join-Path $RootDir "dist\vuln-bundle\koda-vuln-bundle-$Version.zip"
}
if (-not [System.IO.Path]::IsPathRooted($OutputArchive)) {
    $OutputArchive = Join-Path (Get-Location).Path $OutputArchive
}
$OutputArchive = [System.IO.Path]::GetFullPath($OutputArchive)
if ([System.IO.Path]::GetExtension($OutputArchive).ToLowerInvariant() -ne ".zip") {
    throw "OutputArchive는 .zip 파일이어야 합니다: $OutputArchive"
}

function Resolve-ExistingDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "디렉터리를 찾을 수 없습니다: $Path"
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

function Resolve-ExistingFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label 파일을 찾을 수 없습니다: $Path"
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Get-JsonProperty {
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $Object) {
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Read-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fileStream = [System.IO.File]::OpenRead($Path)
    $reader = $null
    $gzipStream = $null
    try {
        if ($Path.ToLowerInvariant().EndsWith(".gz")) {
            $gzipStream = New-Object System.IO.Compression.GZipStream -ArgumentList $fileStream, ([System.IO.Compression.CompressionMode]::Decompress)
            $reader = New-Object System.IO.StreamReader -ArgumentList $gzipStream, ([System.Text.Encoding]::UTF8), $true
        } else {
            $reader = New-Object System.IO.StreamReader -ArgumentList $fileStream, ([System.Text.Encoding]::UTF8), $true
        }
        $raw = $reader.ReadToEnd()
    } finally {
        if ($null -ne $reader) { $reader.Dispose() }
        if ($null -ne $gzipStream) { $gzipStream.Dispose() }
        $fileStream.Dispose()
    }
    return ($raw | ConvertFrom-Json)
}

function Get-Identifiers {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return @()
    }
    if ($Value -is [string]) {
        return @([regex]::Matches(
            $Value,
            '\b(?:CVE-\d{4}-\d{4,}|GHSA-[0-9A-Z-]+)\b',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        ) | ForEach-Object { $_.Value.ToUpperInvariant() })
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = @()
        foreach ($item in $Value) {
            $items += @(Get-Identifiers -Value $item)
        }
        return $items
    }
    $nested = @()
    foreach ($property in $Value.PSObject.Properties) {
        $nested += @(Get-Identifiers -Value $property.Value)
    }
    return $nested
}

function Get-NvdRecords {
    param([Parameter(Mandatory = $true)][object]$Payload)

    $records = Get-JsonProperty -Object $Payload -Name "vulnerabilities"
    if ($null -ne $records) {
        return @($records)
    }
    if ($Payload -is [System.Collections.IEnumerable] -and -not ($Payload -is [string])) {
        return @($Payload)
    }
    return @()
}

function Convert-NvdRecord {
    param([Parameter(Mandatory = $true)][object]$Record)

    $cve = Get-JsonProperty -Object $Record -Name "cve"
    if ($null -eq $cve) { $cve = $Record }
    $identifier = @(Get-Identifiers -Value (Get-JsonProperty -Object $cve -Name "id")) |
        Where-Object { $_ -like "CVE-*" } |
        Sort-Object |
        Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($identifier)) {
        return $null
    }

    $description = $null
    foreach ($item in @(Get-JsonProperty -Object $cve -Name "descriptions")) {
        $value = Get-JsonProperty -Object $item -Name "value"
        $language = Get-JsonProperty -Object $item -Name "lang"
        if (-not [string]::IsNullOrWhiteSpace([string]$value) -and ([string]$language).ToLowerInvariant().StartsWith("en")) {
            $description = [string]$value
            break
        }
    }
    if ($null -eq $description) {
        foreach ($item in @(Get-JsonProperty -Object $cve -Name "descriptions")) {
            $value = Get-JsonProperty -Object $item -Name "value"
            if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
                $description = [string]$value
                break
            }
        }
    }

    $cvss = [ordered]@{}
    $metrics = Get-JsonProperty -Object $cve -Name "metrics"
    $metricSpecs = @(
        [pscustomobject]@{ Name = "cvssV4"; Source = "cvssMetricV40" },
        [pscustomobject]@{ Name = "cvssV3"; Source = "cvssMetricV31" },
        [pscustomobject]@{ Name = "cvssV3"; Source = "cvssMetricV30" },
        [pscustomobject]@{ Name = "cvssV2"; Source = "cvssMetricV2" }
    )
    foreach ($spec in $metricSpecs) {
        $entries = @(Get-JsonProperty -Object $metrics -Name $spec.Source)
        if ($entries.Count -eq 0) { continue }
        $data = Get-JsonProperty -Object $entries[0] -Name "cvssData"
        if ($null -eq $data) { continue }
        $metric = [ordered]@{}
        foreach ($field in @("baseScore", "baseSeverity", "vectorString", "exploitabilityScore", "impactScore")) {
            $value = Get-JsonProperty -Object $data -Name $field
            if ($null -eq $value) {
                $value = Get-JsonProperty -Object $entries[0] -Name $field
            }
            if ($null -ne $value) { $metric[$field] = $value }
        }
        if ($metric.Count -gt 0) {
            $cvss[$spec.Name] = $metric
            break
        }
    }

    $cpes = New-Object 'System.Collections.Generic.List[string]'
    foreach ($configuration in @(Get-JsonProperty -Object $cve -Name "configurations")) {
        foreach ($node in @(Get-JsonProperty -Object $configuration -Name "nodes")) {
            foreach ($match in @(Get-JsonProperty -Object $node -Name "cpeMatch")) {
                $criteria = Get-JsonProperty -Object $match -Name "criteria"
                if (-not [string]::IsNullOrWhiteSpace([string]$criteria) -and -not $cpes.Contains([string]$criteria)) {
                    [void]$cpes.Add([string]$criteria)
                }
            }
        }
    }
    $references = New-Object 'System.Collections.Generic.List[string]'
    foreach ($reference in @(Get-JsonProperty -Object $cve -Name "references")) {
        $url = Get-JsonProperty -Object $reference -Name "url"
        if (-not [string]::IsNullOrWhiteSpace([string]$url) -and -not $references.Contains([string]$url)) {
            [void]$references.Add([string]$url)
        }
    }

    return [ordered]@{
        id = [string]$identifier
        description = $description
        cvss = $cvss
        cpe = @($cpes | Sort-Object | Select-Object -First 100)
        references = @($references | Sort-Object | Select-Object -First 100)
        published = Get-JsonProperty -Object $cve -Name "published"
        lastModified = Get-JsonProperty -Object $cve -Name "lastModified"
    }
}

function Convert-NvdFeedsToIndex {
    param(
        [Parameter(Mandatory = $true)][string[]]$Paths,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )

    $aliases = @{}
    $details = @{}
    $recordsSeen = 0
    foreach ($path in $Paths) {
        $payload = Read-JsonFile -Path $path
        foreach ($record in @(Get-NvdRecords -Payload $payload)) {
            $metadata = Convert-NvdRecord -Record $record
            if ($null -eq $metadata) { continue }
            $canonical = [string]$metadata.id
            $recordsSeen++
            $aliases[$canonical] = $canonical
            $cve = Get-JsonProperty -Object $record -Name "cve"
            if ($null -eq $cve) { $cve = $record }
            foreach ($alias in @(Get-Identifiers -Value (Get-JsonProperty -Object $cve -Name "references"))) {
                if (-not $aliases.ContainsKey($alias)) { $aliases[$alias] = $canonical }
            }
            $details[$canonical] = $metadata
        }
    }

    $orderedAliases = [ordered]@{}
    foreach ($key in ($aliases.Keys | Sort-Object)) { $orderedAliases[$key] = $aliases[$key] }
    $orderedDetails = [ordered]@{}
    foreach ($key in ($details.Keys | Sort-Object)) { $orderedDetails[$key] = $details[$key] }
    $index = [ordered]@{ aliases = $orderedAliases; vulnerabilities = $orderedDetails }
    Write-Utf8NoBom -Path $OutputPath -Content (($index | ConvertTo-Json -Depth 10) + "`n")
    Write-Host "NVD index 생성: $OutputPath ($recordsSeen개 CVE)"
}

function Copy-DirectoryContents {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    foreach ($item in Get-ChildItem -LiteralPath $Source -Force) {
        Copy-Item -LiteralPath $item.FullName -Destination (Join-Path $Destination $item.Name) -Recurse -Force
    }
}

function Test-BundleManifest {
    param(
        [Parameter(Mandatory = $true)][string]$BundleDir,
        [Parameter(Mandatory = $true)][string]$ManifestPath
    )

    $root = ([System.IO.Path]::GetFullPath($BundleDir)).TrimEnd("\") + "\"
    foreach ($line in Get-Content -LiteralPath $ManifestPath) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -notmatch '^([0-9a-fA-F]{64})\s{2}(.+)$') {
            throw "manifest.sha256 형식이 올바르지 않습니다: $line"
        }
        $expected = $Matches[1].ToLowerInvariant()
        $relative = $Matches[2].Trim()
        if ($relative.StartsWith("./")) { $relative = $relative.Substring(2) }
        $candidate = [System.IO.Path]::GetFullPath((Join-Path $BundleDir $relative.Replace("/", "\")))
        if (-not $candidate.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "manifest 경로가 bundle 바깥을 가리킵니다: $relative"
        }
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            throw "manifest 대상 파일이 없습니다: $relative"
        }
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $candidate).Hash.ToLowerInvariant()
        if ($actual -ne $expected) {
            throw "manifest SHA-256 불일치: $relative ($actual != $expected)"
        }
    }
}

$grypePath = Resolve-ExistingDirectory -Path $GrypeDbPath
if ((Split-Path -Leaf $grypePath) -match '^\d+$') {
    $grypeRoot = Split-Path -Parent $grypePath
} else {
    $grypeRoot = $grypePath
}
$schemaDirs = @(Get-ChildItem -LiteralPath $grypeRoot -Directory -Force | Where-Object { $_.Name -match '^\d+$' } | Sort-Object Name)
$schemaDir = $schemaDirs | Select-Object -First 1
if ($null -eq $schemaDir -or -not (Test-Path -LiteralPath (Join-Path $schemaDir.FullName "vulnerability.db") -PathType Leaf)) {
    throw "Grype DB는 <schema>\vulnerability.db 구조여야 합니다: $GrypeDbPath"
}
$grypeSchema = $schemaDir.Name

foreach ($path in @($NvdFeed)) { $null = Resolve-ExistingFile -Path $path -Label "NVD feed" }
$resolvedNvdIndex = $null
if (-not [string]::IsNullOrWhiteSpace($NvdIndex)) {
    $resolvedNvdIndex = Resolve-ExistingFile -Path $NvdIndex -Label "NVD index"
    $null = Read-JsonFile -Path $resolvedNvdIndex
}
$resolvedAliasIndex = $null
if (-not [string]::IsNullOrWhiteSpace($AliasIndex)) {
    $resolvedAliasIndex = Resolve-ExistingFile -Path $AliasIndex -Label "alias index"
    $null = Read-JsonFile -Path $resolvedAliasIndex
}
$resolvedKevCatalog = $null
if (-not [string]::IsNullOrWhiteSpace($KevCatalog)) {
    $resolvedKevCatalog = Resolve-ExistingFile -Path $KevCatalog -Label "CISA KEV catalog"
    $kevPayload = Read-JsonFile -Path $resolvedKevCatalog
    if ($null -eq (Get-JsonProperty -Object $kevPayload -Name "vulnerabilities")) {
        throw "CISA KEV catalog에는 vulnerabilities 배열이 필요합니다: $KevCatalog"
    }
}

$outputParent = Split-Path -Parent $OutputArchive
New-Item -ItemType Directory -Path $outputParent -Force | Out-Null
if ((Test-Path -LiteralPath $OutputArchive -PathType Leaf) -and -not $Force) {
    throw "출력 ZIP이 이미 존재합니다. 교체하려면 -Force를 사용하세요: $OutputArchive"
}
if (Test-Path -LiteralPath $OutputArchive -PathType Leaf) { Remove-Item -LiteralPath $OutputArchive -Force }

$stageDir = Join-Path $outputParent (".vuln-bundle-" + [Guid]::NewGuid().ToString("N"))
try {
    New-Item -ItemType Directory -Path $stageDir -Force | Out-Null
    Copy-DirectoryContents -Source $grypeRoot -Destination (Join-Path $stageDir "grype-db")

    $metadataExtra = @()
    if ($null -ne $resolvedNvdIndex) {
        Copy-Item -LiteralPath $resolvedNvdIndex -Destination (Join-Path $stageDir "nvd.json") -Force
        $metadataExtra += "NVD_INDEX=nvd.json"
        $metadataExtra += "NVD_SHA256=$((Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $stageDir "nvd.json")).Hash.ToLowerInvariant())"
    } elseif (@($NvdFeed).Count -gt 0) {
        $nvdOutput = Join-Path $stageDir "nvd.json"
        Convert-NvdFeedsToIndex -Paths @($NvdFeed) -OutputPath $nvdOutput
        $metadataExtra += "NVD_INDEX=nvd.json"
        $metadataExtra += "NVD_SHA256=$((Get-FileHash -Algorithm SHA256 -LiteralPath $nvdOutput).Hash.ToLowerInvariant())"
    }
    if ($null -ne $resolvedAliasIndex) {
        $aliasOutput = Join-Path $stageDir "alias-index.json"
        Copy-Item -LiteralPath $resolvedAliasIndex -Destination $aliasOutput -Force
        $metadataExtra += "ALIAS_INDEX=alias-index.json"
        $metadataExtra += "ALIAS_SHA256=$((Get-FileHash -Algorithm SHA256 -LiteralPath $aliasOutput).Hash.ToLowerInvariant())"
    }
    if ($null -ne $resolvedKevCatalog) {
        $kevOutput = Join-Path $stageDir "kev.json"
        Copy-Item -LiteralPath $resolvedKevCatalog -Destination $kevOutput -Force
        $metadataExtra += "KEV_CATALOG=kev.json"
        $metadataExtra += "KEV_SHA256=$((Get-FileHash -Algorithm SHA256 -LiteralPath $kevOutput).Hash.ToLowerInvariant())"
    }

    $metadataLines = @(
        "BUNDLE_VERSION=$Version",
        "DATASET_DATE=$DataDate",
        "GRYPE_DB_SCHEMA=$grypeSchema",
        "NVD_DATASET_DATE=$NvdDate",
        "KEV_DATASET_DATE=$KevDate"
    ) + $metadataExtra
    Write-Utf8NoBom -Path (Join-Path $stageDir "metadata.env") -Content (($metadataLines -join "`n") + "`n")

    $manifestPath = Join-Path $stageDir "manifest.sha256"
    $manifestLines = @(Get-ChildItem -LiteralPath $stageDir -Recurse -File -Force |
        Sort-Object FullName |
        ForEach-Object {
            $relative = $_.FullName.Substring($stageDir.Length + 1).Replace("\", "/")
            $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
            "$hash  ./$relative"
        })
    Write-Utf8NoBom -Path $manifestPath -Content (($manifestLines -join "`n") + "`n")
    Test-BundleManifest -BundleDir $stageDir -ManifestPath $manifestPath

    Compress-Archive -Path (Join-Path $stageDir "*") -DestinationPath $OutputArchive -CompressionLevel Optimal -Force
    Write-Host "취약점 데이터 bundle ZIP 생성 완료: $OutputArchive"
    Write-Host "SHA-256: $((Get-FileHash -Algorithm SHA256 -LiteralPath $OutputArchive).Hash.ToLowerInvariant())"
} finally {
    if (Test-Path -LiteralPath $stageDir) {
        Remove-Item -LiteralPath $stageDir -Recurse -Force
    }
}

[CmdletBinding()]
param(
    [ValidateSet("Start", "Stop", "Status")]
    [string]$Action = "Start",
    [ValidateRange(1024, 65535)]
    [int]$Port = 5173,
    [switch]$OpenBrowser,
    [string]$WebRoot = ""
)

$ErrorActionPreference = "Stop"
$StateRoot = if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    Join-Path $env:LOCALAPPDATA "KODA-SBOM-Tracker-Preview"
} else {
    Join-Path $env:TEMP "KODA-SBOM-Tracker-Preview"
}
$PidPath = Join-Path $StateRoot "preview.pid"
$LogPath = Join-Path $StateRoot "preview.log"

function Get-ManagedPid {
    if (-not (Test-Path -LiteralPath $PidPath)) {
        return $null
    }
    try {
        return [int](Get-Content -Raw -LiteralPath $PidPath).Trim()
    } catch {
        return $null
    }
}

function Test-ManagedProcess {
    param([Parameter(Mandatory = $true)][int]$ProcessId)

    $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        return $false
    }

    $processInfo = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
    if ($null -ne $processInfo -and -not [string]::IsNullOrWhiteSpace($processInfo.CommandLine)) {
        return $processInfo.CommandLine -match "serve-windows-preview\.ps1"
    }
    return $true
}

function Remove-PidFile {
    if (Test-Path -LiteralPath $PidPath) {
        Remove-Item -LiteralPath $PidPath -Force
    }
}

function Stop-PreviewServer {
    $existingPid = Get-ManagedPid
    if ($null -eq $existingPid) {
        Remove-PidFile
        Write-Host "KODA SBOM Tracker Preview is not running."
        return
    }

    $process = Get-Process -Id $existingPid -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        Remove-PidFile
        Write-Host "Removed stale preview server state."
        return
    }
    if (-not (Test-ManagedProcess -ProcessId $existingPid)) {
        throw "Refusing to stop PID $existingPid because it is not the KODA preview server."
    }

    Stop-Process -Id $existingPid -Force
    Remove-PidFile
    Write-Host "KODA SBOM Tracker Preview stopped."
}

if ($Action -eq "Stop") {
    Stop-PreviewServer
    exit 0
}

$existingPid = Get-ManagedPid
if ($Action -eq "Status") {
    if ($null -ne $existingPid -and (Test-ManagedProcess -ProcessId $existingPid)) {
        Write-Host "KODA SBOM Tracker Preview is running (PID $existingPid)."
        exit 0
    }
    Write-Host "KODA SBOM Tracker Preview is not running."
    exit 1
}
if ($null -ne $existingPid -and (Test-ManagedProcess -ProcessId $existingPid)) {
    $url = "http://127.0.0.1:$Port/?page=dashboard"
    Write-Host "KODA SBOM Tracker Preview is already running (PID $existingPid): $url"
    if ($OpenBrowser) {
        Start-Process $url | Out-Null
    }
    exit 0
}
if ($null -ne $existingPid) {
    Remove-PidFile
}

if ([string]::IsNullOrWhiteSpace($WebRoot)) {
    $WebRoot = Join-Path $PSScriptRoot "..\web"
}
if (-not (Test-Path -LiteralPath $WebRoot -PathType Container)) {
    throw "Preview web directory not found: $WebRoot"
}
$WebRoot = (Resolve-Path -LiteralPath $WebRoot).Path.TrimEnd("\") + "\"
New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null

function Get-MimeType {
    param([Parameter(Mandatory = $true)][string]$Path)

    $mimeTypes = @{
        ".css" = "text/css; charset=utf-8"
        ".gif" = "image/gif"
        ".html" = "text/html; charset=utf-8"
        ".ico" = "image/x-icon"
        ".jpeg" = "image/jpeg"
        ".jpg" = "image/jpeg"
        ".js" = "text/javascript; charset=utf-8"
        ".json" = "application/json; charset=utf-8"
        ".map" = "application/json; charset=utf-8"
        ".png" = "image/png"
        ".svg" = "image/svg+xml"
        ".txt" = "text/plain; charset=utf-8"
        ".wasm" = "application/wasm"
        ".webp" = "image/webp"
        ".woff" = "font/woff"
        ".woff2" = "font/woff2"
    }
    $extension = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    if ($mimeTypes.ContainsKey($extension)) {
        return $mimeTypes[$extension]
    }
    return "application/octet-stream"
}

function Write-HttpResponse {
    param(
        [Parameter(Mandatory = $true)][System.Net.Sockets.NetworkStream]$Stream,
        [Parameter(Mandatory = $true)][int]$StatusCode,
        [Parameter(Mandatory = $true)][string]$Reason,
        [Parameter(Mandatory = $true)][string]$ContentType,
        [Parameter(Mandatory = $true)][byte[]]$Body,
        [switch]$HeadOnly
    )

    $header = "HTTP/1.1 $StatusCode $Reason`r`n" +
        "Content-Type: $ContentType`r`n" +
        "Content-Length: $($Body.Length)`r`n" +
        "Cache-Control: no-cache`r`n" +
        "Connection: close`r`n`r`n"
    $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($header)
    $Stream.Write($headerBytes, 0, $headerBytes.Length)
    if (-not $HeadOnly -and $Body.Length -gt 0) {
        $Stream.Write($Body, 0, $Body.Length)
    }
    $Stream.Flush()
}

function Get-PreviewFile {
    param([Parameter(Mandatory = $true)][string]$RequestPath)

    try {
        $decodedPath = [System.Uri]::UnescapeDataString($RequestPath)
    } catch {
        return @{ StatusCode = 400; Path = $null }
    }
    if ($decodedPath.IndexOf([char]0) -ge 0) {
        return @{ StatusCode = 400; Path = $null }
    }

    $relativePath = $decodedPath.TrimStart("/").Replace("/", "\")
    if ([string]::IsNullOrWhiteSpace($relativePath)) {
        $relativePath = "index.html"
    }
    try {
        $candidate = [System.IO.Path]::GetFullPath((Join-Path $WebRoot $relativePath))
    } catch {
        return @{ StatusCode = 403; Path = $null }
    }
    if (-not $candidate.StartsWith($WebRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        return @{ StatusCode = 403; Path = $null }
    }
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        return @{ StatusCode = 200; Path = $candidate }
    }
    if (-not [string]::IsNullOrWhiteSpace([System.IO.Path]::GetExtension($relativePath))) {
        return @{ StatusCode = 404; Path = $null }
    }

    $indexPath = Join-Path $WebRoot "index.html"
    if (Test-Path -LiteralPath $indexPath -PathType Leaf) {
        return @{ StatusCode = 200; Path = $indexPath }
    }
    return @{ StatusCode = 500; Path = $null }
}

function Write-PreviewLog {
    param([Parameter(Mandatory = $true)][string]$Message)
    try {
        Add-Content -LiteralPath $LogPath -Value ((Get-Date).ToString("s") + " " + $Message) -Encoding UTF8
    } catch {
        # Logging must not prevent the preview from shutting down.
    }
}

$listener = [System.Net.Sockets.TcpListener]::new(
    [System.Net.IPAddress]::Parse("127.0.0.1"),
    $Port
)
$pidWritten = $false
$url = "http://127.0.0.1:$Port/?page=dashboard"
try {
    try {
        $listener.Start()
    } catch {
        $message = "Unable to start the local preview server on port $Port. Check whether another application is using it."
        Write-PreviewLog "$message $($_.Exception.Message)"
        throw $message
    }

    Set-Content -LiteralPath $PidPath -Value $PID -Encoding ASCII
    $pidWritten = $true
    Write-Host "KODA SBOM Tracker Preview started: $url"
    Write-Host "Stop with: powershell -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`" -Action Stop"
    if ($OpenBrowser) {
        Start-Process $url | Out-Null
    }

    while ($listener.Server.IsBound) {
        $client = $null
        $reader = $null
        $responded = $false
        try {
            $client = $listener.AcceptTcpClient()
            $client.ReceiveTimeout = 5000
            $stream = $client.GetStream()
            $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::ASCII, $false, 4096, $true)
            $requestLine = $reader.ReadLine()
            if ([string]::IsNullOrWhiteSpace($requestLine)) {
                continue
            }
            $requestParts = $requestLine.Split(" ")
            if ($requestParts.Count -lt 2) {
                Write-HttpResponse -Stream $stream -StatusCode 400 -Reason "Bad Request" -ContentType "text/plain; charset=utf-8" -Body ([System.Text.Encoding]::UTF8.GetBytes("Bad Request"))
                $responded = $true
                continue
            }
            $method = $requestParts[0].ToUpperInvariant()
            $headOnly = $method -eq "HEAD"
            if ($method -ne "GET" -and -not $headOnly) {
                Write-HttpResponse -Stream $stream -StatusCode 405 -Reason "Method Not Allowed" -ContentType "text/plain; charset=utf-8" -Body ([System.Text.Encoding]::UTF8.GetBytes("Method Not Allowed"))
                $responded = $true
                continue
            }
            for ($headerIndex = 0; $headerIndex -lt 100; $headerIndex++) {
                $headerLine = $reader.ReadLine()
                if ($null -eq $headerLine -or $headerLine.Length -eq 0) {
                    break
                }
            }

            try {
                $requestUri = [System.Uri]::new("http://127.0.0.1$($requestParts[1])")
                $file = Get-PreviewFile -RequestPath $requestUri.AbsolutePath
            } catch {
                $file = @{ StatusCode = 400; Path = $null }
            }
            if ($file.StatusCode -eq 200) {
                $body = [System.IO.File]::ReadAllBytes($file.Path)
                Write-HttpResponse -Stream $stream -StatusCode 200 -Reason "OK" -ContentType (Get-MimeType -Path $file.Path) -Body $body -HeadOnly:$headOnly
                $responded = $true
            } elseif ($file.StatusCode -eq 403) {
                Write-HttpResponse -Stream $stream -StatusCode 403 -Reason "Forbidden" -ContentType "text/plain; charset=utf-8" -Body ([System.Text.Encoding]::UTF8.GetBytes("Forbidden")) -HeadOnly:$headOnly
                $responded = $true
            } elseif ($file.StatusCode -eq 404) {
                Write-HttpResponse -Stream $stream -StatusCode 404 -Reason "Not Found" -ContentType "text/plain; charset=utf-8" -Body ([System.Text.Encoding]::UTF8.GetBytes("Not Found")) -HeadOnly:$headOnly
                $responded = $true
            } elseif ($file.StatusCode -eq 500) {
                Write-HttpResponse -Stream $stream -StatusCode 500 -Reason "Internal Server Error" -ContentType "text/plain; charset=utf-8" -Body ([System.Text.Encoding]::UTF8.GetBytes("Internal Server Error")) -HeadOnly:$headOnly
                $responded = $true
            } else {
                Write-HttpResponse -Stream $stream -StatusCode 400 -Reason "Bad Request" -ContentType "text/plain; charset=utf-8" -Body ([System.Text.Encoding]::UTF8.GetBytes("Bad Request")) -HeadOnly:$headOnly
                $responded = $true
            }
        } catch {
            if (-not $responded -and $null -ne $client) {
                try {
                    $errorStream = $client.GetStream()
                    Write-HttpResponse -Stream $errorStream -StatusCode 500 -Reason "Internal Server Error" -ContentType "text/plain; charset=utf-8" -Body ([System.Text.Encoding]::UTF8.GetBytes("Internal Server Error"))
                } catch {
                    # The browser may have disconnected before the response was written.
                }
            }
        } finally {
            if ($null -ne $reader) {
                $reader.Dispose()
            }
            if ($null -ne $client) {
                $client.Close()
            }
        }
    }
} finally {
    if ($null -ne $listener) {
        $listener.Stop()
    }
    if ($pidWritten -and (Get-ManagedPid) -eq $PID) {
        Remove-PidFile
    }
}

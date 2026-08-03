function Initialize-KodaDockerCliPath {
    if (Get-Command docker.exe -ErrorAction SilentlyContinue) {
        return
    }

    $programFiles = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique
    foreach ($basePath in $programFiles) {
        $dockerPath = Join-Path $basePath "Docker\Docker\resources\bin\docker.exe"
        if (Test-Path -LiteralPath $dockerPath) {
            $env:Path = "$(Split-Path -Parent $dockerPath);$env:Path"
            return
        }
    }

    throw "Docker CLI를 찾을 수 없습니다. Docker Desktop을 설치하고 실행한 뒤 새 PowerShell에서 docker --version과 docker info를 확인하세요."
}

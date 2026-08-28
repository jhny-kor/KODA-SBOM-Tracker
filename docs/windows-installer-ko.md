# Windows 설치파일 가이드

Windows에서 KODA SBOM Tracker를 실행하는 방법은 셋이며, **기능 범위와 요구사항이 서로 다른
별개의 산출물**입니다. 목적에 맞는 하나를 고른 뒤 해당 절만 읽습니다.

## 어느 것을 쓸까

| | 전체 설치파일 | Preview 설치파일 | 개발용 미리보기 |
| --- | --- | --- | --- |
| 용도 | 실제 운영·검증 | 화면과 업로드만 확인 | 소스에서 화면 확인 |
| 산출물 | `KODA-SBOM-Tracker-Setup.exe` | `KODA-SBOM-Tracker-Preview-Setup.exe` | 없음(소스 실행) |
| 빌드 PC | Docker Desktop(Linux containers) + Inno Setup 6 | Node.js LTS + Inno Setup 6 | — |
| 대상 PC | Docker Desktop | 없음(Windows 10/11 기본 PowerShell) | Node.js LTS |
| 접속 주소 | `http://127.0.0.1:8088/?page=dashboard` | `http://127.0.0.1:5173/?page=dashboard` | `http://127.0.0.1:5173/?page=dashboard` |
| 취약점 분석 | Grype + Dependency-Track 전체 | 없음. SBOM 내장 레코드만 표시 | 없음. SBOM 내장 레코드만 표시 |
| 로그인·저장 | 로그인 있음, PostgreSQL 영구 저장 | 없음. 브라우저 메모리 | 없음. 브라우저 메모리 |
| 배포 범위 | **내부 반입 전용** | `legal` 포함 시 배포 가능 | — |
| 절 | [전체 설치파일](#전체-설치파일) | [Docker 없는 Windows 설치파일](#docker-없는-windows-설치파일) | [Docker 없는 개발용 UI 미리보기](#docker-없는-개발용-ui-미리보기) |

Docker Desktop 없이 전체 분석까지 수행하는 네이티브 단일 EXE는 지원 범위가 아닙니다.

## 전체 설치파일

Windows x64에서 Docker Desktop의 Linux 컨테이너로 전체 스택을 실행합니다. 설치파일은 React
포털만 담은 단일 EXE가 아니라 실행에 필요한 다음 이미지와 Compose 파일을 함께 담습니다.

- gateway, portal-web, portal-api, portal-worker
- PostgreSQL
- Dependency-Track backend/frontend
- Grype, CycloneDX CLI, Alpine 운영 이미지

이 전체 설치파일은 컨테이너 이미지 재배포를 포함하므로 **KODA 내부 반입 전용**입니다.
고객·협력사·계열사·공개 배포용으로 만들 수 없으며 `-DistributionScope External`은 빌드에서
거부됩니다. 외부 배포에는 별도의 대응 소스 제공 절차와 법무 승인이 필요합니다.

설치 후에는 `http://127.0.0.1:8088/?page=dashboard`를 브라우저로 엽니다.

### 빌드 PC 준비

Windows x64 빌드 PC에 다음을 설치합니다.

1. Docker Desktop을 설치하고 Linux containers 모드로 실행합니다.
2. Inno Setup 6을 설치합니다.
3. 저장소를 clone합니다.

Docker Desktop이 실행 중이고 `docker info`가 성공해야 합니다. 설치 직후 기존 PowerShell 창을
재사용하지 말고 새 창을 열어 다음을 먼저 확인합니다.

```powershell
docker --version
docker info
```

Inno Setup이 기본 경로가 아닌 곳에 있으면 `ISCC.exe` 경로를 직접 지정합니다.

### 설치파일 빌드

PowerShell에서 저장소 루트로 이동해 실행합니다.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\build-windows-installer.ps1
```

스크립트는 다음을 순서대로 수행합니다.

1. `portal-web`, `portal-api`, `portal-worker`를 `linux/amd64`로 빌드합니다.
2. digest가 고정된 외부 이미지를 `linux/amd64`로 반입합니다.
3. 모든 실행 이미지를 `.tar`로 저장하고 SHA-256 manifest를 만듭니다.
4. Compose, 운영 스크립트, 문서, 라이선스 고지와 `.env.example`을 staging합니다.
5. Inno Setup `ISCC.exe`로 `dist\windows\KODA-SBOM-Tracker-Setup.exe`를 생성합니다.

기본 설치 경로와 다른 Inno Setup 경로를 사용할 때:

```powershell
.\scripts\build-windows-installer.ps1 `
  -InnoSetupPath "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
```

이미지를 다시 빌드하지 않고 현재 Docker image를 패키징할 때:

```powershell
.\scripts\build-windows-installer.ps1 -SkipDockerBuild
```

출력 파일:

```text
dist\windows\KODA-SBOM-Tracker-Setup.exe
```

실제 `.exe` 생성은 Windows의 Docker Desktop과 Inno Setup이 필요합니다. macOS에서 할 수 있는
검증은 PowerShell 문법·파일 구성 확인까지이며, 최종 설치·기동 smoke test는 Windows에서
수행해야 합니다.

### 설치 및 최초 설정

1. 대상 Windows x64 PC에 Docker Desktop을 설치하고 실행합니다.
2. `KODA-SBOM-Tracker-Setup.exe`를 관리자 권한으로 실행합니다.
3. 설치 디렉터리의 `.env`를 관리자 권한 편집기로 실제 운영값으로 수정합니다.
4. 시작 메뉴의 `KODA SBOM Tracker`를 실행합니다.

`.env`에는 다음 값을 반드시 실제 값으로 바꿉니다.

- `POSTGRES_PASSWORD`
- `DTRACK_DB_PASSWORD`
- `TRACKER_DB_PASSWORD`
- `TRACKER_BOOTSTRAP_ADMIN_PASSWORD`
- `TRACKER_DEPENDENCY_TRACK_API_KEY`
- `TRACKER_DATABASE_URL`의 사용자·DB·비밀번호

Windows 로컬 실행에서는 다음 기본값을 유지할 수 있습니다.

```dotenv
PUBLIC_HTTP_PORT=8088
DTRACK_API_BASE_URL=http://localhost:8088/dependency-track
```

실제 비밀번호와 API 키는 설치파일이나 Git에 넣지 않습니다. 설치파일에는 `.env.example`만
포함되며, 설치 과정에서 그 파일을 `.env`로 복사합니다. 예시값이 남아 있으면 시작 스크립트가
실행을 거부합니다.

### 수동 기동·중지·상태 확인

설치 디렉터리에서 실행합니다.

```powershell
.\scripts\start-windows.ps1 -OpenDashboard
.\scripts\start-windows.ps1 -Action Status
.\scripts\start-windows.ps1 -Action Stop
```

`Start`는 다음을 확인한 뒤 Compose를 기동합니다.

- 첫 기동 시 설치파일에 포함된 Docker image tar를 `docker load`합니다. 이후에는 manifest
  marker가 같으면 재로드하지 않습니다.
- Docker Desktop daemon 연결
- Compose 설정
- gateway `/healthz`
- 포털 API `/api/v1/healthz`
- Dependency-Track `/dependency-track/`

`Stop`은 `docker compose down`만 실행하므로 PostgreSQL·Dependency-Track·SBOM artifact
named volume 데이터는 삭제하지 않습니다. 볼륨을 삭제하는 명령은 설치 스크립트에 포함하지
않습니다.

### 문제 해결

| 증상 | 조치 |
| --- | --- |
| `Docker CLI를 찾을 수 없습니다` | Docker Desktop을 설치·실행한 뒤 PowerShell을 새로 열고 `docker --version`을 확인합니다. 스크립트는 Docker Desktop의 표준 설치 경로도 자동으로 확인합니다. |
| `Docker Desktop이 실행 중이 아닙니다` | Docker Desktop을 시작하고 다시 실행합니다. |
| `예시 값입니다` | 설치 디렉터리 `.env`의 `change-me-*`와 API 키를 수정합니다. |
| 포트 충돌 | `.env`의 `PUBLIC_HTTP_PORT`를 사용하지 않는 포트로 바꾸고 다시 시작합니다. |
| 준비 시간 초과 | `docker compose ps`와 Docker Desktop의 컨테이너 로그를 확인합니다. |
| 재빌드가 필요 없는 반복 패키징 | `-SkipDockerBuild`를 사용합니다. 소스나 Dockerfile을 바꿨다면 기본 빌드로 다시 실행합니다. |

기동 후 발생하는 Dependency-Track 흰 화면·401·400·413 오류는
[폐쇄망 장애 대응](troubleshooting-ko.md)을 따릅니다.

## Docker 없는 Windows 설치파일

로그인 없이 SBOM 업로드와 웹 대시보드 화면만 확인하는 별도 설치파일입니다. 이 설치파일은
전체 Compose 스택과 다른 제품으로, 빌드 PC에서만 Node.js LTS와 Inno Setup 6이 필요하고
설치 대상 Windows PC에는 Docker Desktop·Node.js가 필요하지 않습니다.

### 빌드 PC 준비 및 빌드

Windows x64 빌드 PC에 다음을 설치합니다.

1. Node.js LTS를 설치합니다.
2. Inno Setup 6을 설치합니다.
3. 저장소를 clone합니다.

Docker Desktop은 설치하거나 실행할 필요가 없습니다. 저장소 루트에서 다음을 실행합니다.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\build-windows-preview-installer.ps1
```

출력 파일:

```text
dist\windows\KODA-SBOM-Tracker-Preview-Setup.exe
```

`node_modules`가 이미 준비된 반복 빌드는 npm 설치를 건너뛸 수 있습니다.

```powershell
.\scripts\build-windows-preview-installer.ps1 -SkipNpmInstall
```

Inno Setup을 기본 경로가 아닌 곳에 설치했거나 `ISCC.exe`를 찾지 못한다는 오류가 나오면
실제 파일 경로를 지정합니다. 64비트 Windows의 기본 경로는 보통 다음과 같습니다.

```powershell
Test-Path "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
.\scripts\build-windows-preview-installer.ps1 `
  -InnoSetupPath "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
```

첫 번째 명령이 `False`이면 Inno Setup 6을 다시 설치하거나 설치 폴더의 실제
`ISCC.exe` 경로를 `-InnoSetupPath`에 넣습니다.

### 대상 PC 설치 및 사용

1. `KODA-SBOM-Tracker-Preview-Setup.exe`를 실행합니다. 기본 설치는 현재 사용자 영역에
   이루어지므로 관리자 권한이 필요하지 않습니다.
2. 설치가 끝나면 시작 메뉴의 `KODA SBOM Tracker Preview`를 실행합니다.
3. 브라우저에서 `http://127.0.0.1:5173/?page=dashboard`가 열리면 `SBOM 업로드`를
   선택합니다.
4. CycloneDX JSON 또는 XML 파일을 올리고 생성된 `로컬 미리보기` 회차의 상세 화면에서
   구성요소·CVE 취약점·CVSS·KEV·제안 버전 표시를 확인합니다.

설치파일은 빌드된 정적 웹 파일과 Windows 10/11에 기본 포함된 Windows PowerShell 정적 서버만 포함합니다. 서버는
`127.0.0.1`에서만 동작하며 업로드된 SBOM과 결과는 브라우저 메모리에만 저장됩니다.
새로고침하면 회차가 사라지고, 설치 제거 시 로컬 서버도 중지됩니다. 파일 크기는 100 MiB
이하입니다.

설치 마법사에서 Apache-2.0 라이선스를 표시하며, 설치 폴더의 `legal` 디렉터리에 KODA 고지와
React, React DOM, Pretendard의 라이선스 전문을 함께 설치합니다. 이 디렉터리를 제거한 설치파일은
배포하지 않습니다.

이 경로는 화면·업로드·SBOM에 이미 포함된 취약점 표시를 확인하는 Preview입니다. Grype DB
조회, 실제 취약점 재분석, Dependency-Track 연동, 로그인, PostgreSQL, 정책 판정, 영구 저장은
수행하지 않습니다. 전체 분석 운영이 필요하면 위의 Docker 설치파일 또는 Linux 서버를
사용해야 합니다.

## Docker 없는 개발용 UI 미리보기

설치파일을 만들지 않고 소스에서 바로 화면을 확인할 때 사용하는 개발 실행 방식입니다.
이 경로에는 Docker Desktop과 Inno Setup이 필요하지 않지만, 실행하는 Windows에 Node.js LTS가
필요합니다.

PowerShell에서 저장소 루트로 이동해 실행합니다.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
Set-Location .\apps\web
npm ci
Set-Location ..\..
.\scripts\start-windows-preview.ps1 -OpenBrowser
```

브라우저를 직접 열 때는 `http://127.0.0.1:5173/?page=dashboard`로 접속합니다. 업로드 후
`SBOM 회차`에서 생성된 `로컬 미리보기` 회차를 열면 구성요소와 CVE로 연결되는 내장 취약점
레코드를 확인할 수 있습니다. 대시보드의 취약 구성요소 수는 취약점 개수가 아니라 CVE가
하나 이상 있는 고유 구성요소 수입니다. XML/JSON 모두 CycloneDX 형식만 지원하며 파일
크기는 100 MiB 이하입니다.

이 미리보기의 범위는 다음과 같습니다.

- 로그인, API 서버, Docker, PostgreSQL, Grype, Dependency-Track 없이 브라우저에서 동작합니다.
- CycloneDX의 구성요소와 SBOM 안에 이미 들어 있는 `vulnerabilities` 레코드를 표시합니다.
- 새로고침하면 업로드한 회차가 사라집니다. 로컬 브라우저 메모리에만 저장합니다.
- Grype DB 조회·실제 취약점 재분석·정책 판정·원본 파일 내려받기는 수행하지 않습니다.

standalone 정적 빌드가 필요한 경우에는 다음처럼 빌드한 뒤 `npm run preview`로 확인합니다.

```powershell
Set-Location .\apps\web
$env:VITE_STANDALONE_MODE = "true"
$env:VITE_DEMO_MODE = "false"
npm run build
npm run preview -- --host 127.0.0.1 --port 4173
```

이 경로와 Preview 설치파일은 현재 `KODA-SBOM-Tracker-Setup.exe`에 포함된 Docker Compose
설치파일과 별개입니다. Docker 없는 실제 취약점 분석 서버나 완전한 네이티브 EXE가 필요해지는
시점에는 Grype 실행 파일·DB·로컬 저장소를 포함한 별도 런타임을 추가해야 합니다.

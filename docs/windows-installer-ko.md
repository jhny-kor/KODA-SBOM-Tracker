# Windows 설치파일 가이드

## 범위

Windows x64에서 Docker Desktop의 Linux 컨테이너로 KODA SBOM Tracker 전체 스택을 실행합니다.
설치파일은 React 포털만 담은 단일 EXE가 아니라 다음 실행에 필요한 이미지와 Compose 파일을
함께 담습니다.

- gateway, portal-web, portal-api, portal-worker
- PostgreSQL
- Dependency-Track backend/frontend
- Grype, CycloneDX CLI, Alpine 운영 이미지

설치 후에는 `http://127.0.0.1:8088/?page=dashboard`를 브라우저로 엽니다. Docker Desktop 없이
실행하는 네이티브 단일 EXE 방식은 지원 범위가 아닙니다.

## 빌드 PC 준비

Windows x64 빌드 PC에 다음을 설치합니다.

1. Docker Desktop을 설치하고 Linux containers 모드로 실행합니다.
2. Inno Setup 6을 설치합니다.
3. 저장소를 clone합니다.

Docker Desktop이 실행 중이고 `docker info`가 성공해야 합니다. Inno Setup이 기본 경로가 아닌
곳에 있으면 `ISCC.exe` 경로를 직접 지정합니다.

## 설치파일 빌드

PowerShell에서 저장소 루트로 이동해 실행합니다.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\build-windows-installer.ps1
```

스크립트는 다음을 순서대로 수행합니다.

1. `portal-web`, `portal-api`, `portal-worker`를 `linux/amd64`로 빌드합니다.
2. digest가 고정된 외부 이미지를 `linux/amd64`로 반입합니다.
3. 모든 실행 이미지를 `.tar`로 저장하고 SHA-256 manifest를 만듭니다.
4. Compose, 운영 스크립트, 문서와 `.env.example`을 staging합니다.
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

## 설치 및 최초 설정

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
DTRACK_API_BASE_URL=http://localhost:8088/dependency-track/api
```

실제 비밀번호와 API 키는 설치파일이나 Git에 넣지 않습니다. 설치파일에는 `.env.example`만
포함되며, 설치 과정에서 그 파일을 `.env`로 복사합니다. 예시값이 남아 있으면 시작 스크립트가
실행을 거부합니다.

## 수동 기동·중지·상태 확인

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

## 문제 해결

- `Docker Desktop이 실행 중이 아닙니다`: Docker Desktop을 시작하고 다시 실행합니다.
- `예시 값입니다`: 설치 디렉터리 `.env`의 `change-me-*`와 API 키를 수정합니다.
- 포트 충돌: `.env`의 `PUBLIC_HTTP_PORT`를 사용하지 않는 포트로 바꾸고 다시 시작합니다.
- 준비 시간 초과: `docker compose ps`와 Docker Desktop의 컨테이너 로그를 확인합니다.
- 재빌드가 필요 없는 반복 패키징: `-SkipDockerBuild`를 사용합니다. 소스나 Dockerfile을
  바꿨다면 기본 빌드로 다시 실행합니다.

# KODA SBOM Tracker

이 저장소는 KODA용 한국어 SBOM 운영 포털입니다. React 포털, FastAPI API/worker, 공식 Dependency-Track `5.0.3` backend/frontend, PostgreSQL 분리 DB, gateway와 폐쇄망 번들·백업·복원·취약점 데이터 반입 도구를 포함합니다.

빠른 시작:

```bash
cp .env.example .env
docker compose build portal-web portal-api portal-worker
docker compose up -d
```

Windows x64에서 설치파일로 실행하려면 Docker Desktop(Linux containers)과 Inno Setup 6을
준비한 뒤 `.\scripts\build-windows-installer.ps1`를 실행합니다. 생성된
`dist\windows\KODA-SBOM-Tracker-Setup.exe`는 전체 Compose 스택을 설치하고 시작 메뉴에서
대시보드를 열 수 있게 합니다. 상세 절차는 [Windows 설치파일 가이드](docs/windows-installer-ko.md)를
참고합니다.

Docker 없이 Windows에 설치해 SBOM 업로드와 화면을 확인하려면 빌드 PC에서
`.\scripts\build-windows-preview-installer.ps1`를 실행합니다. 생성되는
`dist\windows\KODA-SBOM-Tracker-Preview-Setup.exe`는 대상 PC에서 Docker·Node.js 없이
PowerShell 정적 서버와 웹 대시보드를 실행합니다. CycloneDX JSON/XML의 구성요소와 파일에
내장된 취약점 레코드만 브라우저 메모리에서 표시하며, Grype·Dependency-Track 분석과 영구
저장은 수행하지 않습니다. 소스에서 바로 실행하는 개발용 경로는
`.\scripts\start-windows-preview.ps1 -OpenBrowser`이며, 상세 절차는
[Windows 설치파일 가이드](docs/windows-installer-ko.md)의 Docker 없는 Windows 설치파일 절을
참고합니다.

폐쇄망 Linux `x86_64` 서버에 반입할 때는 인터넷 연결 `linux/amd64` 빌드 PC에서
`./scripts/build-airgap-release.sh ./dist/koda-sbom-airgap.tar.gz`를 실행합니다.
이 단일 압축파일에는 현재 포털 소스, compose/deploy/운영 스크립트, 고정 이미지 tar와
SHA-256 manifest가 들어가며 실제 `.env`는 포함되지 않습니다. 상세 설치·기동은
[오프라인 번들 가이드](docs/offline-bundle-ko.md)를 따릅니다.

처음 기동하기 전에 `.env`의 모든 `change-me-*` 값과 공개 URL을 교체합니다.
Dependency-Track에서 전용 팀/API 키를 만든 뒤 BOM 업로드·프로젝트 생성·조회
권한만 부여하여 `TRACKER_DEPENDENCY_TRACK_API_KEY`에 넣습니다. 키는 브라우저로
전달되지 않습니다.

키 설정 후에는 `./scripts/verify-dtrack-connection.sh`로 v5 API와 최소 권한을
확인할 수 있습니다. 관리자 API 키를 별도로 가진 초기 설치는
`scripts/configure-dtrack-key.sh`로 전용 팀과 키를 자동 발급할 수 있습니다.

KODA 또는 CI에서 업로드:

```bash
export KODA_TRACKER_URL=http://tracker.internal
export KODA_TRACKER_TOKEN='관리자가 발급한 서비스 범위 토큰'
./scripts/upload-sbom.sh <service-id> <environment-id> 1.4.2 ./bom.cdx.json build-20260723-42
```

API 명세는 외부 gateway에 공개하지 않으며 `portal-api` 내부의 `/docs`에서
확인할 수 있습니다. 원본 SBOM은 SHA-256 콘텐츠 주소 저장소에 보존됩니다.
포털은 `/`, 공식 Dependency-Track UI는
`/dependency-track/`입니다.

KODA Linux 대시보드에서 결과 화면에 포털 링크를 넣을 때는
`KODA_SSBOM_TRACKER_URL=http://<tracker-host>:8088/?page=runs`를 사용합니다.
포털 회차 ID를 알고 있으면 `?page=runs&runId=<uuid>`를 붙여 해당 회차 상세가
자동으로 열립니다. 이 링크는 브라우저 세션을 우회하지 않으며, 로그인 후에만
회차가 조회됩니다.

취약점 데이터 bundle을 호스트에서 반입·롤백한 뒤 포털의 `취약점 데이터` 화면에서
`반입 상태 동기화`를 실행해야 DB 감사 이력과 활성 기준일이 갱신됩니다. 설정 화면에서는
관리자만 서비스 범위 API 토큰을 발급하고 폐기할 수 있으며 원문은 발급 시 한 번만
표시됩니다.

운영 문서:

- [운영 가이드](docs/operations-ko.md)
- [오프라인 번들 가이드](docs/offline-bundle-ko.md)
- [Windows 설치파일 가이드](docs/windows-installer-ko.md)

주의:

- `.env`에는 실제 비밀번호와 키를 넣고 Git에 커밋하지 않습니다.
- `portal-web`, `portal-api`, `portal-worker`는 모두 `apps/`의 실제 구현을 빌드합니다.
- 모든 서드파티 이미지는 digest까지 고정했습니다. 로컬 빌드 이미지도 오프라인 번들에서 `docker save` 결과와 SHA-256 manifest로 검증합니다.
- 운영 전 `TRACKER_SECURE_COOKIES=true`와 TLS 종료 프록시를 사용합니다.

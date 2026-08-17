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

취약점 데이터만 Windows에서 별도 생성하려면
`.\scripts\build-vuln-bundle.ps1`로 Grype DB·NVD·CISA KEV bundle ZIP을 만들 수
있습니다. ZIP은 서버에서 압축 해제·manifest 검증 후 `vuln-data` Docker named
volume에 반입하며, 상세 명령은 [오프라인 bundle 가이드](docs/offline-bundle-ko.md)의
Windows 절을 따릅니다.

처음 기동하기 전에 `.env`의 모든 `change-me-*` 값과 공개 URL을 교체합니다.
Dependency-Track에서 전용 팀/API 키를 만든 뒤 BOM 업로드·프로젝트 생성·조회
권한만 부여하여 `TRACKER_DEPENDENCY_TRACK_API_KEY`에 넣습니다. 키는 브라우저로
전달되지 않습니다. team 사용자 멤버가 0명이어도 API 키 인증에는 문제가 없으며,
현재 연결 검사는 `v1/team/self`가 반환한 team 권한을 확인합니다. 공개
`DTRACK_API_BASE_URL`에는 `/api`를 붙이지 않고 관리자 자동화 주소에만 붙입니다.

## 로그인과 권한

최초 Tracker 관리자는 `.env`의 `TRACKER_BOOTSTRAP_ADMIN_USERNAME`과
`TRACKER_BOOTSTRAP_ADMIN_PASSWORD`로 생성합니다. 이후 사용자는 설정 화면에서
관리자가 생성·활성화하며, `admin`, `manager`, `analyst`, `uploader`, `viewer`
역할별 권한은 화면의 역할 정책에서 조정할 수 있습니다. 역할 정책 변경과 사용자
활성화·비활성화는 감사 로그에 남고, 사용자·역할 관리 권한을 가진 마지막 활성
계정은 제거할 수 없습니다.

로그인 화면의 `LDAP 사용` 선택지는 향후 연동을 위한 UI이며 현재 선택하면
`501 ldap_not_configured`로 실패합니다. 따라서 현재 Tracker 로그인은 관리자가
미리 만든 로컬 계정만 지원합니다.

KODA Linux 통합본에서는 Tracker 로그인 세션을 gateway가 검증해 KODA에 신원만
전달합니다. KODA에 처음 접근한 사용자는 KODA에서 `pending` 상태가 되며 KODA
관리자가 별도로 승인하고 프로젝트 권한을 부여해야 합니다. 이 공유 로그인은 통합
suite의 동일 오리진 `/koda/` 경로에서만 적용되며, 이 저장소의 단독 Compose에는
KODA가 포함되지 않습니다. Dependency-Track UI 로그인도 Tracker 세션과 공유하지
않고 별도 계정·Team 권한을 사용합니다.

KODA와 Tracker에서 실행하는 로그아웃은 모두 현재 브라우저의 Tracker 세션을
폐기합니다. 따라서 어느 한쪽에서 로그아웃해도 양쪽 보호 화면은 다시 로그인이
필요합니다. 계정은 공유하지만 권한 정책은 공유하지 않습니다. Tracker 역할 정책과
KODA 프로젝트 역할은 각각의 관리 화면에서 별도로 설정합니다.

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

- [화면·기능 한눈에 보기](docs/koda-sbom-tracker-overview-ko.md)
- [운영 가이드](docs/operations-ko.md)
- [오프라인 번들 가이드](docs/offline-bundle-ko.md)
- [KODA 통합 인증·운영 계약](docs/koda-integration-ko.md)
- [폐쇄망 장애 대응](docs/troubleshooting-ko.md)
- [Windows 설치파일 가이드](docs/windows-installer-ko.md)
- [오픈소스 라이선스 정책](docs/open-source-compliance-ko.md)

## 라이선스와 배포 범위

KODA SBOM Tracker 자체 코드는 Apache License 2.0으로 배포합니다. 라이선스 전문과
저작권·서드파티 고지는 [LICENSE](LICENSE), [NOTICE](NOTICE),
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)에 있습니다. Docker 없는 Windows Preview는
설치 폴더의 `legal` 디렉터리에 이 파일들과 React·Pretendard 라이선스를 포함합니다.

컨테이너 이미지를 함께 묶는 폐쇄망·오프라인·전체 Windows 패키지는 내부 반입 전용입니다.
고객·협력사·계열사·공개 저장소 등 외부 배포는 대응 소스 제공 절차와 법무 검토가 승인되기
전까지 지원하지 않으며 빌드 스크립트가 외부 배포 범위를 거부합니다.

주의:

- `.env`에는 실제 비밀번호와 키를 넣고 Git에 커밋하지 않습니다.
- `portal-web`, `portal-api`, `portal-worker`는 모두 `apps/`의 실제 구현을 빌드합니다.
- 모든 서드파티 이미지는 digest까지 고정했습니다. 로컬 빌드 이미지도 오프라인 번들에서 `docker save` 결과와 SHA-256 manifest로 검증합니다.
- 운영 전 `TRACKER_ENVIRONMENT=production`, `TRACKER_SECURE_COOKIES=true`,
  `TRACKER_PUBLIC_ORIGIN=https://<동일-오리진-호스트>`와 TLS 종료 프록시를 사용합니다.

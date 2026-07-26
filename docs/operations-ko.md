# 운영 가이드

## 1. 구성

- `gateway`: 외부 진입점. `/` 는 포털, `/api` 는 포털 API, `/dependency-track` 는 공식 Dependency-Track UI/API로 프록시합니다.
- `portal-api`, `portal-worker`: `apps/api` 실제 이미지입니다.
- `portal-web`: React/Vite 포털을 정적 빌드하여 8080 포트에서 제공합니다.
- `postgres`: `dtrack`, `sbom_tracker` DB와 각 전용 계정을 초기화합니다.
- `dtrack-apiserver`, `dtrack-frontend`: 공식 Dependency-Track `5.0.3` 이미지입니다.

## 2. 초기 기동

```bash
cp .env.example .env
vi .env
docker compose build portal-web portal-api portal-worker
docker compose up -d
docker compose ps
```

필수 수정 항목:

- `POSTGRES_PASSWORD`
- `DTRACK_DB_PASSWORD`
- `TRACKER_DB_PASSWORD`
- `TRACKER_BOOTSTRAP_ADMIN_PASSWORD`
- `TRACKER_DEPENDENCY_TRACK_API_KEY`
- `DTRACK_API_BASE_URL`
- 필요 시 볼륨 이름과 외부 공개 포트
- TLS 사용 시 `TRACKER_SECURE_COOKIES=true`

Dependency-Track 초기 관리자 로그인 후 포털 전용 팀을 만들고 다음 최소 권한을
부여합니다.

- `BOM_UPLOAD`
- `PROJECT_CREATION_UPLOAD`
- `PORTFOLIO_MANAGEMENT_UPDATE` (정상 완료 회차의 latest 승격에만 사용)
- 프로젝트·메트릭·정책 위반 조회 권한

발급 키는 `TRACKER_DEPENDENCY_TRACK_API_KEY`에만 저장하며 frontend나 브라우저
환경변수로 전달하지 않습니다.

설정 후 실제 키·버전·팀 권한을 읽기 전용으로 확인합니다.

```bash
./scripts/verify-dtrack-connection.sh
```

실제 BOM 업로드·이벤트 token 추적·프로젝트 metric/policy 조회까지 확인하려면
승인된 테스트 환경에서 다음 선택적 live smoke test를 실행합니다. 테스트 프로젝트가
Dependency-Track에 남으므로 운영 프로젝트가 아닌 별도 인스턴스/이름을 사용합니다.

```bash
KODA_DTRACK_LIVE=1 \
KODA_DTRACK_LIVE_URL=http://127.0.0.1:8088/dependency-track \
KODA_DTRACK_LIVE_API_KEY='전용 팀 키' \
.venv/bin/pytest tests/integration/test_dtrack_live.py -q
```

관리자 API 키가 있는 초기 설치에서만 자동 팀/권한/키 발급 도구를 사용할 수
있습니다. 관리자 키는 셸 환경변수로만 전달하고 `.env`에는 저장하지 않습니다.
기존 키가 있는 팀은 자동 회전하지 않으므로 실수로 기존 연동을 끊지 않습니다.

```bash
export DTRACK_ADMIN_API_KEY='관리자 API 키'
export DTRACK_ADMIN_API_BASE_URL='http://127.0.0.1:8088/dependency-track/api'
./scripts/configure-dtrack-key.sh
docker compose up -d --force-recreate portal-api portal-worker
./scripts/verify-dtrack-connection.sh
```

## 3. 폐쇄망 기본 원칙

- backend 서비스는 `app` internal network에만 연결됩니다.
- 외부 노출 포트는 `gateway` 하나만 사용합니다.
- 취약점 데이터는 자동 다운로드하지 않고 별도 bundle 반입으로만 교체합니다.
- `.env`는 절대 저장소에 커밋하지 않습니다.

반입 후 관리자가 포털의 `취약점 데이터` 화면에서 `반입 상태 동기화`를 실행합니다.
이 작업은 `releases/<version>/metadata.env`와 manifest를 포털 DB에 불변 등록하고,
현재 `current` 링크와 일치하는 버전만 활성으로 기록합니다. 파일 반입·롤백은
호스트에서 `scripts/import-vuln-bundle.sh` 또는 `scripts/rollback-vuln-bundle.sh`로
수행한 뒤 다시 동기화합니다. 활성 bundle에는 선택적으로 `alias-index.json`과
`kev.json`(또는 `ALIAS_INDEX`, `KEV_CATALOG`로 지정한 파일)을 포함할 수 있으며,
분석 결과에는 CVE/GHSA canonical ID, alias, CISA KEV 여부와 기준일이 보존됩니다.

동일 작업을 자동화할 때는 관리자 세션의 CSRF 보호를 유지하면서
`POST /api/v1/vulnerability-data-bundles/sync`를 호출하고, 현재 파일시스템 버전의
기록 확인에는 `GET /api/v1/vulnerability-data-bundles`를 사용합니다.

## 4. 상태 확인

```bash
curl -fsS http://localhost:${PUBLIC_HTTP_PORT:-8088}/healthz
curl -fsS http://localhost:${PUBLIC_HTTP_PORT:-8088}/api/v1/healthz
curl -I http://localhost:${PUBLIC_HTTP_PORT:-8088}/dependency-track/
```

## 5. 백업과 복원

- 백업 생성: `./scripts/backup-system.sh`
- 백업 검증: `./scripts/verify-backup.sh ./backups/<timestamp>`
- 복원: `./scripts/restore-system.sh ./backups/<timestamp>`

백업 세트에는 다음이 포함됩니다.

- PostgreSQL globals SQL
- `dtrack`, `sbom_tracker` 논리 덤프
- `tracker-artifacts`, `dtrack-data`, `vuln-data` volume tarball
- compose/deploy 기준 설정
- SHA-256 manifest

## 6. 서비스 계약

- `portal-web`: 8080 포트에서 HTTP 응답
- `portal-api`: 8000 포트에서 `/health`, `/api/...`
- `portal-worker`: 현재 `koda-tracker-worker` 프로세스 기반 healthcheck
- `ARTIFACT_ROOT`, `VULN_DATA_ROOT`, `UPLOAD_MAX_BYTES` 환경변수는 유지 권장

## 7. KODA/CI 업로드

관리자가 서비스 범위 API 토큰을 발급한 다음 아래 보조 CLI를 사용합니다.

```bash
KODA_TRACKER_URL=http://tracker.internal \
KODA_TRACKER_TOKEN='서비스 범위 토큰' \
./scripts/upload-sbom.sh <service-id> <environment-id> <release> <sbom-file> <idempotency-key>
```

동일 `Idempotency-Key` 재전송은 같은 회차를 반환하고, 다른 키로 같은 파일을
올리면 blob은 중복 저장하지 않으면서 새 회차를 배정합니다.

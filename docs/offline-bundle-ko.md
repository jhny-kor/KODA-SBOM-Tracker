# 오프라인 번들 가이드

## 1. 목적

인터넷 연결이 가능한 x86_64 빌드 PC에서 다음을 미리 묶어 폐쇄망 서버로 반입합니다.

- Dependency-Track backend/frontend `5.0.3`
- PostgreSQL, nginx, 운영 스크립트용 Alpine
- 포털 web/API/worker 로컬 이미지
- Grype, CycloneDX CLI
- compose/deploy/scripts/docs 설정
- SHA-256 manifest

## 2. 생성

### 단일 폐쇄망 릴리스 압축파일(권장)

Docker Engine과 인터넷이 연결된 `linux/amd64` 빌드 PC에서 실행합니다. 포털 소스,
compose, 운영 스크립트, 10개 이상의 이미지 tar, manifest를 하나의 `tar.gz`로 묶습니다.
취약점 데이터 bundle은 선택적으로 함께 포함할 수 있습니다.

```bash
./scripts/build-airgap-release.sh ./dist/koda-sbom-airgap.tar.gz
# 선택: --vuln-bundle ./dist/vuln-bundle/<version>
```

폐쇄망 서버에서는 압축파일과 별도 운영 `.env`를 반입한 뒤 설치합니다. `.env`는
압축파일에 포함되지 않으며 `change-me-*` 값을 사용할 수 없습니다.

```bash
mkdir -p /tmp/koda-sbom-release
tar -xzf ./koda-sbom-airgap.tar.gz -C /tmp/koda-sbom-release
sudo /tmp/koda-sbom-release/scripts/install-airgap.sh ./koda-sbom-airgap.tar.gz /opt/koda-sbom \
  --env-file /tmp/koda-sbom.env
```

`/tmp/koda-sbom.env`는 반입 전에 `.env.example`을 복사해 실제 비밀번호·키·서버 주소로
수정한 파일입니다. 설치 스크립트가 이를 `/opt/koda-sbom/.env`로 복사합니다.

설치 후 재기동은 다음과 같습니다.

```bash
sudo /opt/koda-sbom/scripts/start-airgap.sh /opt/koda-sbom/.env
```

기본 웹 주소는 `http://<폐쇄망 서버>:8088/`이며, KODA 화면의 SBOM Tracker 버튼은
이 주소의 `/?page=runs`로 연결하면 로그인 후 회차 목록을 바로 엽니다.

압축파일의 해시와 manifest는 설치 전에 확인합니다.

```bash
sha256sum -c koda-sbom-airgap.tar.gz.sha256
./scripts/verify-airgap-release.sh ./koda-sbom-airgap.tar.gz
```

### 기존 디렉터리 번들

```bash
./scripts/build-offline-bundle.sh
```

출력:

- `dist/offline-bundle/<UTC timestamp>/images/*.tar`
- `metadata.env`
- `manifest.sha256`
- `config/`

## 3. 검증과 반입

```bash
./scripts/verify-offline-bundle.sh ./dist/offline-bundle/<timestamp>
./scripts/import-offline-bundle.sh ./dist/offline-bundle/<timestamp>
```

반입 후 `config/`를 운영 디렉터리로 복사하고 실제 비밀값을 넣은 `.env`를 준비합니다.
placeholder와 DB URL 불일치를 차단한 뒤, 빌드·pull 없는 모드로 기동합니다.

```bash
./scripts/preflight-airgap.sh /path/to/.env
docker compose --env-file /path/to/.env \
  -f compose.yaml -f compose.airgap.yaml \
  up -d --no-build --pull never
```

`DTRACK_API_BASE_URL`은 폐쇄망 서버에서 접근 가능한 gateway URL의 `/api` 주소여야
합니다(예: `http://sbom-server:8088/dependency-track/api`). `dtrack-apiserver`,
`localhost`, `127.0.0.1` 주소는 preflight에서 거부됩니다.

## 4. 취약점 데이터 반입 규칙

취약점 데이터 bundle은 별도입니다. 예시 구조:

```text
bundle/
  metadata.env
  manifest.sha256
  grype-db/6/             # GRYPE_DB_CACHE_DIR 바로 아래의 schema 디렉터리
  nvd/
  kev/
  alias-index.json       # 선택: CVE/GHSA alias 그룹
  kev.json               # 선택: CISA KEV catalog JSON
```

`metadata.env` 필수 값:

- `BUNDLE_VERSION`
- `DATASET_DATE`
- `GRYPE_DB_SCHEMA`
- `NVD_DATASET_DATE`, `KEV_DATASET_DATE` (각 데이터셋을 포함할 때 권장)
- `NVD_INDEX`, `ALIAS_INDEX`, `KEV_CATALOG` (기본 파일명 대신 다른 경로를 사용할 때)

인터넷 연결 빌드 PC에서 원본 feed를 먼저 검증한 뒤 bundle을 생성합니다. 이 명령은
네트워크를 사용하지 않으며, NVD 2.0 JSON/JSON.GZ feed는 alias와 설명·CVSS·CPE·참조
URL을 포함한 compact offline index로 정규화합니다. 원본 feed 전체를 폐쇄망에 복사하지
않아도 오프라인 분석 결과에서 NVD 근거를 확인할 수 있습니다.

```bash
./scripts/build-vuln-bundle.sh ./dist/vuln-bundle/<version> \
  --version <version> \
  --grype-db /path/to/grype-db \
  --data-date 2026-07-23 \
  --nvd-feed /path/to/nvdcve-2.0-2024.json.gz \
  --nvd-feed /path/to/nvdcve-2.0-2025.json.gz \
  --kev /path/to/known_exploited_vulnerabilities.json \
  --kev-date 2026-07-23
```

전체 NVD 범위를 반입할 때는 필요한 연도 feed와 `modified` feed를 모두 지정해야
합니다. 일부 연도만 지정한 bundle은 NVD 기준일을 전체 NVD 최신값으로 표시하지
않습니다. `nvd-alias-index.py`는 CVE와 NVD reference URL에 포함된 GHSA/CVE alias와
영문 설명, CVSS metric, CPE criteria, 참조 URL을 보존하고, 원본 feed는 빌드 PC에서
별도 보관합니다.

검증된 번들은 `vuln-data` Docker 볼륨의 `releases/`에 staging 후 이동되며,
`current` 심볼릭 링크만 원자적으로 전환됩니다. worker는
`current/grype-db`를 읽고 이전 버전은 `previous`로 즉시 롤백할 수 있습니다.

반입/검증/롤백:

```bash
./scripts/verify-vuln-bundle.sh ./bundle
./scripts/import-vuln-bundle.sh ./bundle
./scripts/rollback-vuln-bundle.sh
```

반입 또는 롤백 후 포털의 `취약점 데이터 → 반입 상태 동기화`를 실행합니다.
동기화 전에는 DB의 활성 상태를 바꾸지 않으며, 현재 `current` 링크와 다른
버전의 활성화 요청은 거부됩니다.

## 5. 주의

- manifest 검증 없이 `docker load` 나 취약점 데이터 교체를 진행하지 않습니다.
- 실제 운영 시에는 빌드 PC와 폐쇄망 서버 모두에서 결과 artifact의 해시를 다시 확인합니다.
- compose는 `linux/amd64` 기준으로 설계했습니다.

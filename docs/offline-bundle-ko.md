# 오프라인 번들 가이드

인터넷이 없는 서버에 Tracker를 설치·갱신하거나 취약점 데이터를 교체할 때 읽습니다.

## 어느 경로를 쓸까

| 하려는 일 | 경로 | 만드는 곳 | 절 |
| --- | --- | --- | --- |
| 폐쇄망에 처음 설치하거나 전체를 갱신 | 단일 릴리스 `tar.gz` | Linux `x86_64` + Docker | [2. 생성](#2-생성) |
| 이미지만 따로 반입 | 디렉터리 번들 | Linux `x86_64` + Docker | [기존 디렉터리 번들](#기존-디렉터리-번들) |
| Grype/NVD/KEV 데이터만 교체 | 취약점 bundle | Linux 또는 Windows PowerShell | [4. 취약점 데이터 반입 규칙](#4-취약점-데이터-반입-규칙) |

취약점 데이터만 바꿀 때는 이미지를 다시 설치하지 않습니다.

## 1. 목적

인터넷 연결이 가능한 x86_64 빌드 PC에서 다음을 미리 묶어 폐쇄망 서버로 반입합니다.

이 번들은 컨테이너 이미지 재배포를 포함하므로 **KODA 내부 폐쇄망 반입 전용**입니다.
고객·협력사·계열사·공개 배포는 대응 소스 제공 절차와 법무 검토가 승인되기 전까지 금지합니다.
`KODA_DISTRIBUTION_SCOPE=external`로 실행하면 생성 스크립트가 즉시 실패합니다.

- Dependency-Track backend/frontend `5.0.3`
- PostgreSQL, nginx, 운영 스크립트용 Alpine
- 포털 web/API/worker 로컬 이미지
- Grype, CycloneDX CLI
- compose/deploy/scripts/docs 설정
- `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md`
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

KODA와 Tracker를 같은 서버에 설치하는 최종 전달물은 KODA 저장소의
`platforms/linux/package-suite-offline.sh`가 이 Tracker 압축파일과 KODA Docker
압축파일을 다시 묶어 생성합니다. 통합본은 Tracker 계정·세션을 인증 원본으로
사용하고 `/koda/`를 같은 gateway에 추가합니다. Tracker 단독 압축파일과 통합
압축파일을 동시에 설치하지 말고 운영 형태에 맞는 하나를 선택합니다.

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

`DTRACK_API_BASE_URL`은 브라우저가 접근할 수 있는 Dependency-Track의 공개 base
주소여야 합니다(예: `http://sbom-server:8088/dependency-track`). 프론트엔드가
여기에 `/api`를 붙여 호출하므로 값을 `/dependency-track/api`로 넣으면
`/api/api/...`가 되어 화면이 비어 보일 수 있습니다. `dtrack-apiserver`,
`localhost`, `127.0.0.1` 주소는 preflight에서 거부됩니다. 관리자 자동화 스크립트는
`DTRACK_ADMIN_API_BASE_URL`에 `/api`가 포함된 주소를 사용합니다.

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

Tracker air-gap release의 `metadata.env`에는 `TRACKER_GIT_REVISION`과
`TRACKER_WORKTREE_DIRTY=false`가 추가로 기록됩니다. 기본 production 빌드는 Git
revision과 작업 트리가 깨끗해야 하며, 변경/미추적 파일이 있으면 중단됩니다. 개발용
번들이 꼭 필요할 때만 `TRACKER_RELEASE_MODE=development
KODA_RELEASE_INCLUDE_UNTRACKED=1`을 명시할 수 있습니다. 개발 번들은 production
반입물로 사용하지 않으며 verifier가 거부합니다.

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

### 4-1. Windows에서 취약점 bundle을 만들고 ZIP으로 반입하기

Windows x64의 PowerShell 5.1 또는 PowerShell 7에서
`scripts\build-vuln-bundle.ps1`를 실행할 수 있습니다. 이 스크립트는 네트워크로
데이터를 내려받지 않습니다. 인터넷 연결 환경에서 미리 준비·검증한 Grype DB,
NVD 2.0 feed 또는 compact NVD index, CISA KEV JSON을 입력으로 받아 동일한
`metadata.env`·`manifest.sha256` 형식의 bundle을 만들고 ZIP으로 압축합니다.

입력으로 사용할 Grype DB는 다음 중 하나여야 합니다.

```text
C:\KODA\grype-db\6\vulnerability.db
C:\KODA\grype-db\6\           # 위 schema 디렉터리를 직접 지정해도 됨
```

Grype DB를 새로 받는 경우에는 폐쇄망에 반입할 데이터 기준일에 맞춰 인터넷 연결
환경에서 준비하고, 실행 서버에 포함된 Grype 버전과 호환되는 DB인지 확인합니다.
현재 이미지에 고정된 Grype 버전은 `0.109.1`입니다. DB를 준비한 뒤
`grype-db\<schema>\vulnerability.db`가 실제로 존재하는지 확인하고, 그 상위
디렉터리를 `-GrypeDbPath`에 전달합니다. 이 PowerShell 스크립트는 DB나 NVD/KEV
데이터를 다운로드하지 않습니다.

PowerShell에서 저장소 루트로 이동한 뒤 실행합니다.

```powershell
Set-ExecutionPolicy -Scope Process Bypass

$nvdFeeds = @(
  "C:\KODA\feeds\nvdcve-2.0-2024.json.gz",
  "C:\KODA\feeds\nvdcve-2.0-2025.json.gz",
  "C:\KODA\feeds\nvdcve-2.0-modified.json.gz"
)

.\scripts\build-vuln-bundle.ps1 `
  -GrypeDbPath "C:\KODA\grype-db" `
  -DataDate "2026-08-06" `
  -Version "20260806" `
  -OutputArchive "C:\KODA\out\koda-vuln-bundle-20260806.zip" `
  -NvdFeed $nvdFeeds `
  -NvdDate "2026-08-06" `
  -KevCatalog "C:\KODA\feeds\known_exploited_vulnerabilities.json" `
  -KevDate "2026-08-06"
```

이미 compact NVD index가 있으면 `-NvdFeed` 대신 `-NvdIndex`를 사용합니다.
두 옵션은 동시에 사용할 수 없습니다. alias 파일이 별도로 있으면
`-AliasIndex C:\KODA\feeds\alias-index.json`을 추가합니다. 출력 ZIP이 이미
있을 때 교체하려면 마지막에 `-Force`를 추가합니다.

생성기는 다음을 자체 검증합니다.

- Grype DB에 `<schema>\vulnerability.db`가 있는지 확인
- NVD, alias, KEV JSON을 읽을 수 있는지 확인
- `metadata.env`의 기준일과 bundle 버전 생성
- bundle 전체 파일의 SHA-256 `manifest.sha256` 생성 및 재검증
- 압축 전 최종 디렉터리를 ZIP으로 생성

생성 후 Windows에서 전달 파일의 해시를 기록합니다.

```powershell
Get-FileHash `
  -LiteralPath "C:\KODA\out\koda-vuln-bundle-20260806.zip" `
  -Algorithm SHA256
```

#### 폐쇄망 서버에서 ZIP을 Docker volume으로 반입

취약점 DB를 portal-api 또는 portal-worker **이미지 안에 복사하지 않습니다.**
두 컨테이너가 공통으로 읽는 `vuln-data` named volume에 bundle을 넣고,
컨테이너에는 `/var/lib/sbom-tracker/vuln-data:ro`로 마운트합니다. 반입 스크립트는
임시 Alpine 컨테이너를 사용해 volume 내부의 `releases/<version>`과
`current` 심볼릭 링크를 원자적으로 갱신합니다. 따라서 API/worker 이미지를 다시
빌드할 필요가 없습니다.

1. ZIP과 이 저장소의 운영 스크립트를 서버에 전달합니다.

Windows PowerShell에서 OpenSSH `scp`를 사용할 때:

```powershell
scp "C:\KODA\out\koda-vuln-bundle-20260806.zip" `
  operator@tracker-server:/tmp/koda-vuln-bundle-20260806.zip
```

서버가 Linux라면 Windows의 `scp` 대신 승인된 USB·파일 반입 경로를 사용해도
됩니다. 서버에서 압축을 풀기 전에 Windows에서 기록한 SHA-256과 비교합니다.

```bash
sha256sum /tmp/koda-vuln-bundle-20260806.zip
```

2. 운영 디렉터리에서 ZIP을 별도 임시 디렉터리에 풉니다.

```bash
cd /opt/koda-sbom
test -f /tmp/koda-vuln-bundle-20260806.zip
command -v unzip >/dev/null

# 폐쇄망에서는 이 이미지가 이미 로컬에 있어야 합니다. pull하지 않습니다.
set -a
. /opt/koda-sbom/.env
set +a
docker image inspect "$ALPINE_BASE_IMAGE" >/dev/null

bundle_dir="$(mktemp -d /tmp/koda-vuln-bundle.XXXXXX)"
trap 'rm -rf "$bundle_dir"' EXIT
unzip -q /tmp/koda-vuln-bundle-20260806.zip -d "$bundle_dir"
test -f "$bundle_dir/metadata.env"
test -f "$bundle_dir/manifest.sha256"
```

3. 서버에서 bundle manifest를 먼저 검증한 뒤 Docker volume에 반입합니다.

```bash
./scripts/verify-vuln-bundle.sh "$bundle_dir"
ENV_FILE=/opt/koda-sbom/.env \
  ./scripts/import-vuln-bundle.sh "$bundle_dir"
```

`import-vuln-bundle.sh`는 `.env`의 `VULN_DATA_VOLUME_NAME`과
`ALPINE_BASE_IMAGE`를 사용합니다. 기본값이면 volume 이름은
`koda-sbom-vuln-data`입니다. Docker 권한이 없는 운영 계정은 승인된 방식으로
Docker 권한을 부여받아야 하며, 임의의 `docker cp`로 실행 중인 컨테이너의
파일을 덮어쓰지 않습니다. 운영 Compose가 사용하는 volume 이름과 `.env`의
`VULN_DATA_VOLUME_NAME`이 같은지도 확인합니다.

4. 반입 결과를 volume에서 확인합니다.

```bash
set -a
. /opt/koda-sbom/.env
set +a
docker volume inspect "$VULN_DATA_VOLUME_NAME" >/dev/null
docker run --rm \
  -v "${VULN_DATA_VOLUME_NAME}:/runtime:ro" \
  "${ALPINE_BASE_IMAGE}" \
  sh -ec 'test -L /runtime/current; \
    test -f /runtime/current/metadata.env; \
    test -f /runtime/current/manifest.sha256; \
    readlink /runtime/current'
```

5. 포털 관리자 화면에서 `취약점 데이터 → 반입 상태 동기화`를 실행합니다.
이 단계는 파일시스템의 bundle을 포털 DB 감사 이력과 기준일에 등록합니다.
새 bundle을 반입해도 기존 분석 결과가 자동 재계산되지는 않으므로, 필요한 기존
SBOM 회차에서 `새 분석 리비전`을 실행하거나 SBOM을 다시 업로드합니다.
재분석 결과의 원본 식별자는 그대로 보존되지만 화면·집계·회차 비교에는 CVE로 직접
또는 alias를 통해 연결되는 결과만 표시됩니다. CVSS는 NVD V4→V3→V2 순으로 선택하고,
CVE 기준일은 NVD 기준일을 우선합니다.

반입에 실패하면 `current` 링크가 바뀌지 않도록 설계되어 있습니다. 이전 bundle로
돌아갈 때는 다음 순서로 실행하고 다시 동기화합니다.

```bash
./scripts/rollback-vuln-bundle.sh
```

롤백만 할 때는 새 bundle 반입 명령을 다시 실행하지 말고 포털의
`취약점 데이터 → 반입 상태 동기화`만 실행합니다. 새 bundle을 반입하는 경우에만
다음 명령을 사용합니다.

```bash
ENV_FILE=/opt/koda-sbom/.env \
  ./scripts/import-vuln-bundle.sh "$bundle_dir"
```

전체 air-gap 릴리스 하나에 취약점 bundle을 포함하려면 Windows에서 만든 ZIP을
빌드 호스트에서 먼저 압축 해제한 디렉터리로 준비한 뒤, Linux/amd64 Docker 빌드
환경에서 다음처럼 `--vuln-bundle`을 사용합니다.

```bash
./scripts/build-airgap-release.sh \
  ./dist/koda-sbom-airgap.tar.gz \
  --vuln-bundle ./vuln-bundle/20260806
```

이 전체 릴리스 생성 경로는 컨테이너 이미지를 함께 묶으므로 Windows PowerShell
bundle 생성 경로와 달리 Linux/amd64 Docker 빌드 환경이 필요합니다.

## 5. 주의

- manifest 검증 없이 `docker load` 나 취약점 데이터 교체를 진행하지 않습니다.
- 실제 운영 시에는 빌드 PC와 폐쇄망 서버 모두에서 결과 artifact의 해시를 다시 확인합니다.
- compose는 `linux/amd64` 기준으로 설계했습니다.
- `DISTRIBUTION_SCOPE=internal-only` 표시와 법적 고지 파일이 없는 번들은 검증에서 거부합니다.

# Linux SBOM Tracker 설치본과 데이터 보존 갱신

이번 설치본은 라이브러리 보유 환경·릴리스·변경 이력, CVE 제품·버전 검색,
환경별 관리자 지정, SBOM 등록 정보 수정, 긴 텍스트 표시를 포함합니다.
대상은 `linux/amd64`이며 API·Web·Worker를 같은 빌드 태그로 제공합니다.

## 기존 데이터에 대한 영향

- 기존 PostgreSQL DB, SBOM artifact, 승인된 취약점 자료, 작업 스풀과 백업은 이름 있는 Docker 볼륨에 있습니다.
- 같은 설치 경로와 기존 서버 전용 `.env`를 사용하면 볼륨 이름과 DB 비밀번호·LDAP 암호화 키·검증 공개키 설정을 유지합니다.
- 현재 소스의 API가 기존 DB로 시작하면 `environment_administrators`, `run_component_corrections`, `run_manual_components` 테이블과 필요한 열을 추가합니다. 구성요소 수정·삭제·복원과 수동 추가에 사용하는 데이터이며, 업로드 원본과 분석 이력은 보존합니다.
- 이전 회차·보관 회차·분석·취약점·정책·계정·세션·토큰은 유지합니다. 새 환경 관리자 권한은 전체 관리자가 지정해야 생깁니다.
- 라이브러리 화면은 기존 회차를 조회합니다. CVE 검색은 현재 승인된 NVD 자료를 사용하며, 구형 자료에 없는 발행기관 정보는 새 자료 반입 후 확인할 수 있습니다.
- 이 애플리케이션 설치본은 취약점 자료를 자동 갱신하지 않습니다. 기존 승인 자료를 그대로 재사용합니다.

## 설치 및 갱신

새 설치에는 서버 전용 `.env`와 취약점 자료의 검증 공개키를 준비합니다.
기존 설치의 갱신에는 원래 사용하던 `.env`와 같은 설치 경로를 지정합니다.
운영 비밀값을 예시 파일의 값으로 바꾸지 않습니다.

배포 파일의 SHA-256과 별도로 제공된 검증 공개키로 서명을 확인합니다.
아래는 독립 Tracker 설치의 예시입니다.

```bash
sha256sum --check koda-sbom-tracker-linux-amd64.tar.gz.sha256
./scripts/verify-airgap-release.sh koda-sbom-tracker-linux-amd64.tar.gz \
  --public-key /etc/koda/trust/release-public.pem

./scripts/install-airgap.sh koda-sbom-tracker-linux-amd64.tar.gz /opt/koda-sbom \
  --env-file /opt/koda-sbom/.env \
  --public-key /etc/koda/trust/release-public.pem
```

실제 파일명은 제공된 배포 파일명을 사용합니다. 검증 키는 신뢰한 배포 경로에서 전달받아 확인합니다.
기존 설치 갱신 시 `--import-vuln-bundle`을 추가하지 않으면 승인 취약점 자료를 교체하지 않습니다.
실행 이미지 태그·digest와 상태는 `docker compose images`, `docker compose ps`로 확인합니다.

## 백업과 복구

갱신 전에 쓰기 작업을 중단하고 DB·SBOM artifact·취약점 자료를 백업합니다.
운영 `.env`, LDAP 암호화 키, 서명 검증 키와 TLS 파일도 별도의 접근 제한 백업에 보관합니다.
`scripts/backup-system.sh`의 `.env` 포함은 `INCLUDE_ENV_IN_BACKUP=1`일 때만 수행됩니다.
기존 백업 도구가 루트 `.env.example`이 없어 중단하면 이번 설치본의 수정된 `scripts/lib.sh`를 사용합니다.
이 버전은 설치본의 `config/.env.example` 경로도 지원합니다.

`scripts/verify-backup.sh`로 백업의 서명·manifest를 확인합니다.
`scripts/restore-system.sh`는 복구 대상 DB·artifact·취약점 자료를 백업으로 교체하므로
격리된 복구 대상에서 먼저 시험하고, 복원 후 기존 이미지와 설정으로 시작합니다.
새 테이블을 만드는 이번 갱신은 기존 스키마를 파괴적으로 변경하지 않습니다.

KODA 통합 Suite 설치에서는 Suite의 설정·gateway·KODA 데이터 경로까지 함께 보존해야 합니다.
독립 Tracker 설치기를 Suite 경로에 직접 실행하지 말고, 호환성 검사와 공통 이미지 태그를 사용하는
Suite 전달물의 `koda-suite patch --group portal-api-worker` 또는 전체 설치 경로를 사용합니다.
단독 Tracker 배포물은 KODA 자체 이미지나 통합 Suite 배포물을 대신하지 않습니다.

데이터 볼륨 삭제, 초기화 설치, `reset-install.sh`, `docker compose down -v`는 갱신 절차가 아닙니다.

## 새 설치의 취약점 자료 초기화

앱 설치·업데이트에는 취약점 자료 공개키 등록이 필요하지 않습니다.
`TRACKER_DATA_UPDATE_VERIFY_KEY_FILE`을 비워 두면 키 파일 bind 없이 기동하며,
기존 계정·LDAP 설정·점검 결과는 보존합니다. 자료 관리 화면에는 `unconfigured`가 표시되고
서명 검증이 필요한 자료 반입·적용은 사용할 수 없습니다. 서명 없는 자료를 자동 허용하지 않습니다.

신뢰한 공개키를 사용할 때만 `.env`의 `TRACKER_DATA_UPDATE_VERIFY_KEY_FILE`에 경로를 지정합니다.
상대 경로는 그 `.env` 파일 위치를 기준으로 해석합니다. 제공된 설치·시작·유지보수 스크립트는
`compose.data-key.yaml`을 선택적으로 추가하고, 키 경로가 잘못됐거나 개인키이면 중단합니다.
Compose를 직접 실행하는 경우에도 키 등록 후에만 `-f compose.data-key.yaml`을 추가해야 합니다.
이 파일은 키와 무관한 데이터 볼륨·토큰·LDAP 암호화 키를 바꾸지 않습니다.

취약점 자료를 포함한 새 설치에서 `--import-vuln-bundle`을 사용하려면 자료 디렉터리에
공식 EPSS를 포함하여 서명한 `unified-update.tar.gz`가 있어야 합니다.
`TRACKER_DATA_UPDATE_VERIFY_KEY_FILE`에는 그 파일을 검증할 신뢰한 공개키를 등록합니다.
개인 서명키는 설치 서버와 자료 파일에 포함하지 않습니다.

설치기는 실행 중인 API와 같은 데이터 갱신 이미지에서 기존 통합 파일 검증·적용 엔진을 사용합니다.
원본 서명·manifest를 검증하고 DB 참조자료까지 동기화한 뒤 승인된 활성 자료로 공개합니다.
구형 파일 복사 방식의 자료나 서명·등록 키가 없는 자료는 승인된 것으로 간주하지 않습니다.

자료를 포함하지 않은 애플리케이션 설치본도 설치할 수 있습니다. 이 경우 관리자가 서명한 통합 자료를
검증·적용하기 전까지 CVE 점검과 검색은 사용할 수 없으며, 서버의 기동 상태가 자료 승인을 뜻하지 않습니다.
이미 관리 상태가 있는 설치는 활성·삭제·삭제 진행 상태를 자동으로 바꾸지 않습니다.
반복 설치로 삭제한 자료를 복원하거나 기존 `current`를 교체하지 않으며, 이후 자료 변경은 관리자 화면에서 수행합니다.

## 전체 NVD 자료 처리

공식 NVD 전체 자료는 문법·서명·manifest 검증을 유지하면서 레코드 단위로 읽습니다.
CVE 조회와 기존 분석은 임시 SQLite 색인을 이용하며 전체 JSON 객체를 메모리에 보관하지 않습니다.
기본 캐시 위치는 기존 데이터 갱신 작업 경로입니다. 일반 분석 워커는 `TRACKER_NVD_CACHE_DIR`로
기존 RW artifact 볼륨의 전용 최상위 `.nvd-cache`를 사용하며, 데이터 갱신 작업 볼륨의 쓰기 권한은 받지 않습니다.
별도 실행에서는 이 선택 설정을 생략하거나 빈 값으로 두면 기존 캐시 위치를 유지합니다.
원본 자료와 버전 범위·적용 조건은 유지하고, 색인은 승인 원본·manifest·파일 identity에 연결합니다.
조회 중 원본이나 승인 근거가 바뀌면 결과를 제공하지 않습니다. 캐시 경로에는 색인을 생성할 여유 공간이 필요합니다.

`.nvd-cache`는 승인 원본으로 다시 만드는 파생 자료이며 SBOM 원본·분석 이력이 아닙니다.
artifact 백업은 이 최상위 전용 디렉터리만 제외하고 나머지 사용자 파일과 중첩 디렉터리는 보존합니다.
백업·복원 및 업그레이드 전후 artifact 보존 비교에서도 이 캐시만 분리합니다.
DB와 회차 원본·분석 결과의 보존·보관 정책은 그대로 적용되며, 캐시는 복원 후 첫 분석에서 다시 생성됩니다.

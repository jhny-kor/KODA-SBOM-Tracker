# 운영 가이드

기동·계정 초기화·백업·부분 교체 등 일상 운영 절차입니다. 오류 증상별 대응은
[폐쇄망 장애 대응](troubleshooting-ko.md), 폐쇄망 반입 절차는
[오프라인 번들 가이드](offline-bundle-ko.md)를 따릅니다.

## 1. 구성

| 서비스 | 역할 |
| --- | --- |
| `gateway` | 외부 진입점. `/`는 포털, `/api`는 포털 API, `/dependency-track`는 공식 Dependency-Track UI/API로 프록시 |
| `portal-web` | React/Vite 포털을 정적 빌드하여 8080 포트에서 제공 |
| `portal-api`, `portal-worker` | `apps/api` 실제 이미지 |
| `postgres` | `dtrack`, `sbom_tracker` DB와 각 전용 계정을 초기화 |
| `dtrack-apiserver`, `dtrack-frontend` | 공식 Dependency-Track `5.0.3` 이미지 |

## 2. 초기 기동

```bash
cp .env.example .env
vi .env
docker compose build portal-web portal-api portal-worker
docker compose up -d
docker compose ps
```

`.env` 필수 수정 항목:

| 항목 | 내용 |
| --- | --- |
| `POSTGRES_PASSWORD` | PostgreSQL superuser 비밀번호 |
| `DTRACK_DB_PASSWORD` | `dtrack` DB 계정 비밀번호 |
| `TRACKER_DB_PASSWORD` | `sbom_tracker` DB 계정 비밀번호 |
| `TRACKER_BOOTSTRAP_ADMIN_PASSWORD` | 최초 Tracker 관리자 비밀번호 |
| `TRACKER_LDAP_ENCRYPTION_KEY` | LDAP bind 비밀번호를 DB에 저장할 때 사용하는 Fernet 키 |
| `TRACKER_DEPENDENCY_TRACK_API_KEY` | Dependency-Track 전용 team API 키 |
| `DTRACK_API_BASE_URL` | 브라우저가 접근할 수 있는 공개 base 주소. `/api`를 붙이지 않음 |
| 볼륨 이름, 외부 공개 포트 | 필요할 때만 변경 |

운영 환경에서는 `TRACKER_ENVIRONMENT=production`, `TRACKER_SECURE_COOKIES=true`,
`TRACKER_PUBLIC_ORIGIN=https://<동일-오리진-호스트>`를 함께 설정합니다.

Dependency-Track 초기 관리자 로그인 후 포털 전용 팀을 만들고 다음 최소 권한을
부여합니다.

| 권한 | 용도 |
| --- | --- |
| `BOM_UPLOAD` | BOM 업로드 |
| `PROJECT_CREATION_UPLOAD` | 업로드 시 프로젝트 생성 |
| `PORTFOLIO_MANAGEMENT_UPDATE` | 정상 완료 회차의 latest 승격에만 사용 |
| `VIEW_PORTFOLIO` | 프로젝트·구성요소 조회 |
| `VIEW_VULNERABILITY` | 취약점 조회 |
| `VIEW_POLICY_VIOLATION` | 정책 위반 조회 |

발급 키는 `TRACKER_DEPENDENCY_TRACK_API_KEY`에만 저장하며 frontend나 브라우저
환경변수로 전달하지 않습니다.

### 2-1. 계정과 권한 초기화

최초 기동 시 `TRACKER_BOOTSTRAP_ADMIN_USERNAME` 사용자가 없고
`TRACKER_BOOTSTRAP_ADMIN_PASSWORD`가 설정되어 있으면 활성 `admin` 계정을 한 번
생성합니다. 로그인 후 설정 화면에서 다음 작업을 수행합니다.

1. 가입 또는 LDAP 로그인으로 생성된 승인 대기 계정의 역할을 확인하고 승인합니다.
2. 역할 정책에서 화면 접근 권한과 기능 제어 권한을 검토합니다.
3. 서비스 범위 API 토큰은 필요한 서비스에만 발급합니다. 원문 토큰은 발급 시 한
   번만 표시됩니다.

기본 역할은 `admin`, `manager`, `analyst`, `uploader`, `viewer`입니다. 실제 접근은
역할 이름을 직접 비교하지 않고 DB의 역할 정책 권한으로 판정합니다. 사용자 관리와
역할 정책 관리는 별도 권한이며, 관리자·매니저 계정 변경에는 `roles.manage`와
마지막 관리 계정 보호 규칙이 적용됩니다. 사용자 삭제는 세션을 먼저 폐기하고 과거
회차의 업로더 참조를 비운 뒤 계정 행을 제거합니다. 같은 로그인 ID로 다시 가입하면
새 내부 UUID를 사용합니다.

현재 인증 경계는 다음과 같습니다.

- Tracker 로컬 계정은 로그인 화면에서 가입을 신청하면 `viewer`·`승인 대기` 상태로
  생성됩니다. 관리자가 사용자 설정에서 역할을 확인하고 `승인`한 뒤에만
  로그인할 수 있습니다.
- 관리자는 설정의 `LDAP 로그인` 탭에서 LDAP 연결과 그룹-역할 매핑을 저장합니다. bind
  비밀번호는 `TRACKER_LDAP_ENCRYPTION_KEY`가 없으면 저장할 수 없고, 실제 연결은
  기본적으로 StartTLS/LDAPS와 인증서 검증을 사용합니다. 현재 AI 서버와 호환해야 할 때만
  설정 화면의 `LDAP 평문 (389)`을 선택할 수 있으며, 자격증명이 평문으로 전달될 수 있으므로
  내부망 한정으로 사용하고 가능한 한 StartTLS/LDAPS로 전환합니다.
- LDAP 자동 프로비저닝을 켜도 신규 LDAP 사용자는 항상 비활성 `승인 대기`로만
  생성됩니다. 인증 성공만으로 세션을 발급하지 않으며 관리자가 승인한 뒤 다시
  로그인해야 합니다.
- 통합 KODA suite는 Tracker의 HttpOnly 세션을 gateway에서 검증한 뒤 KODA에 UUID,
  표시 이름, 만료 시각만 전달합니다. Tracker 승인 계정은 KODA에도 자동 활성화되고
  KODA 관리자는 프로젝트 권한만 별도로 부여합니다.
- Dependency-Track UI는 별도 사용자·Team 권한을 사용합니다. 포털 backend 연동용
  API 키를 사용자 로그인이나 브라우저 SSO에 사용하지 않습니다. Dependency-Track
  자체 LDAP/OIDC가 필요한 경우에는 설치한 upstream 버전의 공식 설정으로 별도 구성합니다.

운영 세션은 HTTPS 동일 오리진을 전제로 합니다. `TRACKER_ENVIRONMENT=production`은
HTTPS `TRACKER_PUBLIC_ORIGIN`과 `TRACKER_SECURE_COOKIES=true`가 아니면 기동을
거부합니다. reverse proxy는 원래 Host와 HTTPS scheme을 보존해야 합니다.

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
권한이 이미 같은 경우 Dependency-Track의 `PUT v1/permission/team`은 `304`를
반환할 수 있으며 최신 스크립트는 이를 성공으로 처리합니다. team에 사용자 멤버가
0명이어도 API 키 인증에는 영향을 주지 않습니다.

```bash
export DTRACK_ADMIN_API_KEY='관리자 API 키'
export DTRACK_ADMIN_API_BASE_URL='http://127.0.0.1:8088/dependency-track/api'
./scripts/configure-dtrack-key.sh
docker compose up -d --force-recreate portal-api portal-worker
./scripts/verify-dtrack-connection.sh
```

### 계정·데이터 생명주기와 감사

- 서비스·환경 `삭제`는 `active=false`로 전환하는 논리 삭제입니다. 일반 목록과 새
  업로드 선택지에서는 숨기지만 과거 회차의 명칭은 보존합니다. 비활성 항목을 지정한
  새 업로드는 API가 거부합니다.
- 회차 `보관`은 `sbom.archive` 권한으로 상태를 바꿉니다. 회차 `영구 삭제`는 실제
  관리자이면서 `sbom.delete` 권한이 있을 때만 가능하며 완료·실패·보관 회차의 Tracker
  데이터와 로컬 원본만 제거합니다. 진행·대기 작업은 거부하고 Dependency-Track
  프로젝트는 삭제하지 않습니다.
- 감사 로그 조회와 CSV 다운로드는 실제 관리자이면서 `audit.view` 권한이 있어야
  합니다. `Excel 다운로드`는 현재 검색어를 적용한 전체 결과를 UTF-8 BOM CSV로
  내보내며 시각은 서울 시간, 위험한 셀 시작 문자는 수식으로 실행되지 않게 처리합니다.

### 2-2. KODA Suite 외부 TLS reverse proxy

통합 Suite의 gateway는 HTTP `8088`만 제공하고, 인증서 종료는 별도 OpenResty/Nginx
컨테이너 `nginx`가 담당합니다. 현재 운영 서버의 영속 설정은 다음 bind mount를
기준으로 합니다.

| 호스트 | 컨테이너 | 용도 |
| --- | --- | --- |
| `/data/docker_data/volumes/nginx/conf/nginx.conf` | `/usr/local/openresty/nginx/conf/nginx.conf` | Nginx main config |
| `/data/docker_data/volumes/nginx/conf.d` | `/etc/nginx/conf.d` | 선택적 fragment |
| `/data/docker_data/volumes/nginx/ssl` | `/etc/nginx/ssl` | 인증서·개인키 |

KODA vhost는 현재 main config의 `http {}` 안에 직접 두며, `server_name`은
`koda.ssis.or.kr`, backend는 `http://10.95.58.147:8088`로 지정합니다. 인증서와
개인키 원문은 문서·로그에 남기지 않습니다. `conf.d` 방식을 사용할 때는 main
config의 `http {}` 안에만 다음 include를 한 번 넣고, 같은 vhost를 main config와
중복해서 두지 않습니다.

```nginx
include /etc/nginx/conf.d/*.conf;
```

Suite 환경 파일(`~/koda-suite/tracker/.env`)에는 외부 origin을 맞춥니다.

```dotenv
GATEWAY_SERVER_NAME=koda.ssis.or.kr
GATEWAY_PUBLIC_SCHEME=https
TRACKER_PUBLIC_ORIGIN=https://koda.ssis.or.kr
TRACKER_SECURE_COOKIES=true
DTRACK_API_BASE_URL=https://koda.ssis.or.kr/dependency-track
DTRACK_ADMIN_API_BASE_URL=https://koda.ssis.or.kr/dependency-track/api
KODA_SSBOM_TRACKER_URL=https://koda.ssis.or.kr/
```

내부 gateway는 HTTP `:8080`에서 동작하므로 인증되지 않은 `/koda/` 요청의
`Location`을 `http://koda.ssis.or.kr:8080/koda/login`으로 만들 수 있습니다. 외부
TLS vhost에서 `/koda`의 슬래시와 이 redirect를 보정합니다.

```nginx
location = /koda {
    return 308 /koda/;
}

location / {
    proxy_pass http://10.95.58.147:8088;
    proxy_redirect http://koda.ssis.or.kr:8080/ https://koda.ssis.or.kr/;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Port 443;
}
```

`location = /koda`는 HTTPS `server` 블록의 기존 `location /`보다 앞에 두며,
기존 proxy 헤더·timeout 설정은 유지합니다. `nginx -t`와 reload 후 다음 응답의
`Location`에 `http://` 또는 `:8080`이 남지 않아야 합니다.

Tracker의 CSRF 토큰은 브라우저가 `X-CSRF-Token` 요청 헤더로 전송하며 쿠키가
아닙니다. 따라서 `proxy_set_header X-CSRF-Token $cookie_csrf_token;`를 추가하면
안 됩니다. 이 지시어는 브라우저의 토큰을 빈 쿠키 값으로 덮어써 SBOM 업로드를
403으로 만듭니다. 해당 지시어를 생략하면 Nginx가 원래 요청 헤더를 전달합니다.

```bash
docker exec nginx nginx -t && docker exec nginx nginx -s reload
curl --resolve koda.ssis.or.kr:443:10.95.58.147 -sSI \
  https://koda.ssis.or.kr/koda/
curl --resolve koda.ssis.or.kr:443:10.95.58.147 -fsS \
  https://koda.ssis.or.kr/koda/live
```

변경·컨테이너 교체 전후에는 마운트와 active config를 먼저 확인합니다. 상위
`~/koda-suite`에서 raw `docker compose`를 실행하지 말고 Suite wrapper를 사용합니다.

```bash
cd ~/koda-suite
./koda-suite status
./koda-suite start

docker inspect -f '{{range .Mounts}}{{println .Type .Source "->" .Destination "rw=" .RW}}{{end}}' nginx
docker exec nginx nginx -T 2>&1 | \
  grep -nE 'server_name koda\.ssis\.or\.kr|configuration file /etc/nginx/conf\.d/koda\.conf'
docker exec nginx nginx -t
docker exec nginx nginx -s reload

curl -fsS http://127.0.0.1:8088/healthz
curl --resolve koda.ssis.or.kr:443:10.95.58.147 \
  -fsS https://koda.ssis.or.kr/healthz
```

개별 파일을 `vi`로 저장하면 단일 파일 bind mount의 inode가 교체되어 컨테이너가
이전 파일을 계속 볼 수 있습니다. 저장 후 호스트·컨테이너 해시가 다르면 백업을
남기고 현재 mount inode에 내용을 동기화한 뒤 검사·reload합니다.

```bash
MAIN=/data/docker_data/volumes/nginx/conf/nginx.conf
sudo cp -a "$MAIN" "$MAIN.bak.$(date +%Y%m%d%H%M%S)"
docker exec -u 0 -i nginx sh -c \
  'cat > /usr/local/openresty/nginx/conf/nginx.conf' < "$MAIN"
sha256sum "$MAIN"
docker exec nginx sha256sum /usr/local/openresty/nginx/conf/nginx.conf
docker exec nginx nginx -t && docker exec nginx nginx -s reload
```

컨테이너를 재생성할 때도 위 세 bind mount를 같은 source/destination으로 보존합니다.
컨테이너 내부에만 복사한 인증서·설정은 교체 시 사라집니다. `docker compose down -v`
나 named volume 삭제는 이 절차에 필요하지 않습니다.

## 3. 폐쇄망 기본 원칙

- backend 서비스는 `app` internal network에만 연결됩니다.
- 외부 노출 포트는 `gateway` 하나만 사용합니다.
- 취약점 데이터는 자동 다운로드하지 않고 별도 bundle 반입으로만 교체합니다.
- `.env`는 절대 저장소에 커밋하지 않습니다.

KODA 통합본은 동일 오리진의 `/`와 `/koda/`를 사용합니다. Tracker의
`GET /api/v1/auth/session`은 gateway 내부 인증 확인용이며 쿠키 세션만 허용합니다.
gateway는 브라우저가 보낸 신원 헤더를 제거한 뒤 Tracker가 반환한 UUID·만료 시각·
표시 이름만 KODA에 새로 주입합니다. KODA와 Tracker의 로그아웃은
`POST /api/v1/auth/logout-current`로 현재 브라우저 세션 하나를 폐기합니다.
상세 경계와 장애 동작은 [KODA 통합 인증·운영 계약](koda-integration-ko.md)을
따릅니다.

반입 후 관리자가 포털의 `취약점 데이터` 화면에서 `반입 상태 동기화`를 실행합니다.
이 작업은 `releases/<version>/metadata.env`와 manifest를 포털 DB에 불변 등록하고,
현재 `current` 링크와 일치하는 버전만 활성으로 기록합니다. 파일 반입·롤백은
호스트에서 `scripts/import-vuln-bundle.sh` 또는 `scripts/rollback-vuln-bundle.sh`로
수행한 뒤 다시 동기화합니다. 활성 bundle에는 선택적으로 `alias-index.json`과
`kev.json`(또는 `ALIAS_INDEX`, `KEV_CATALOG`로 지정한 파일)을 포함할 수 있으며,
원본 분석 결과에는 CVE/GHSA 식별자와 alias, CISA KEV 여부와 기준일이 보존됩니다.
화면·집계·회차 비교에는 CVE로 직접 또는 alias를 통해 연결되는 결과만 사용하며,
CVE에 연결되지 않는 결과는 원본 분석 기록에서 삭제하지 않습니다. CVE 기준일은
NVD 기준일을 우선하고 없으면 분석 데이터 기준일을 사용합니다.

Windows에서 만든 `koda-vuln-bundle-<version>.zip`은 서버에서 먼저 임시
디렉터리에 압축 해제하고 `verify-vuln-bundle.sh`로 manifest를 확인한 뒤
`import-vuln-bundle.sh`로 `VULN_DATA_VOLUME_NAME` named volume에 반입합니다.
취약점 데이터는 API/worker 이미지에 굽지 않고 두 컨테이너가 읽는 volume에
마운트되므로 이미지 재빌드는 필요하지 않습니다. 전체 절차와 Docker volume
확인 명령은 [오프라인 bundle 가이드](offline-bundle-ko.md)의
`Windows에서 취약점 bundle을 만들고 ZIP으로 반입하기`를 따릅니다.

동일 작업을 자동화할 때는 관리자 세션의 CSRF 보호를 유지하면서
`POST /api/v1/vulnerability-data-bundles/sync`를 호출하고, 현재 파일시스템 버전의
기록 확인에는 `GET /api/v1/vulnerability-data-bundles`를 사용합니다.

## 4. 상태 확인

```bash
curl -fsS http://localhost:${PUBLIC_HTTP_PORT:-8088}/healthz
curl -fsS http://localhost:${PUBLIC_HTTP_PORT:-8088}/api/v1/healthz
curl -I http://localhost:${PUBLIC_HTTP_PORT:-8088}/dependency-track/
curl -fsS http://localhost:${PUBLIC_HTTP_PORT:-8088}/dependency-track/api/version
curl -fsS http://localhost:${PUBLIC_HTTP_PORT:-8088}/dependency-track/static/config.json \
  | python3 -m json.tool
```

gateway는 포털뿐 아니라 Dependency-Track frontend와 API readiness가 모두 정상인
경우에만 healthy가 됩니다. Dependency-Track API의 내부 readiness endpoint는
`/health/ready`입니다.
원격 브라우저를 사용하는 경우 `static/config.json`의 `API_BASE_URL`에
`localhost`, `127.0.0.1`, `dtrack-apiserver`가 없어야 합니다. 설치 중 발생한
흰 화면·401·304·400·413 오류는 [폐쇄망 장애 대응](troubleshooting-ko.md)을
따릅니다.

## 5. 백업과 복원

백업 시점의 `.env`, 이미지 버전, 릴리스 압축파일을 한 세트로 보관합니다. 이
스크립트는 `.env`를 기본적으로 포함하지 않으므로 비밀번호·API 키가 든 원본은
접근 제한된 암호화 매체에 별도 보관합니다. 꼭 같은 백업 세트에 넣어야 할 때만
`INCLUDE_ENV_IN_BACKUP=1`을 사용하고 백업 디렉터리 권한을 즉시 제한합니다.

일관된 백업을 위해 유지보수 창에 쓰기 서비스를 먼저 중지합니다. PostgreSQL은
백업 스크립트가 필요한 동안만 기동합니다.

```bash
ENV_FILE=/opt/koda-sbom/.env
docker compose --env-file "$ENV_FILE" -f compose.yaml -f compose.airgap.yaml \
  stop gateway portal-web portal-api portal-worker dtrack-frontend dtrack-apiserver

ENV_FILE="$ENV_FILE" BACKUP_ROOT=/media/koda-backup/tracker \
  ./scripts/backup-system.sh
ENV_FILE="$ENV_FILE" \
  ./scripts/verify-backup.sh /media/koda-backup/tracker/<출력된-UTC-시각>

./scripts/start-airgap.sh "$ENV_FILE"
```

백업 세트의 범위는 다음과 같습니다.

| 포함 | 포함되지 않음 |
| --- | --- |
| PostgreSQL globals SQL | 운영 `.env` (위의 명시적 옵션을 사용한 경우만 포함) |
| `dtrack`, `sbom_tracker` 논리 덤프 | 통합 Suite의 KODA 포털 SQLite·입력 파일 |
| `tracker-artifacts`, `dtrack-data`, `vuln-data` volume tarball | 호스트에 별도로 둔 원본 SBOM, 스캔 대상, KODA 보고서, TLS 인증서 |
| compose/deploy 기준 설정 | Docker 이미지 tar와 릴리스 압축파일 |
| SHA-256 manifest | |

복원은 현재 데이터를 교체하므로 검증된 백업과 그 백업을 만든 당시의 `.env` 및
호환 릴리스가 모두 준비된 경우에만 수행합니다. 현재 상태도 먼저 새 백업으로
보존하고, 백업 디렉터리를 검증한 다음 복원합니다.

```bash
ENV_FILE=/opt/koda-sbom/.env
BACKUP=/media/koda-backup/tracker/<UTC-시각>

ENV_FILE="$ENV_FILE" ./scripts/verify-backup.sh "$BACKUP"
ENV_FILE="$ENV_FILE" ./scripts/restore-system.sh "$BACKUP"
./scripts/start-airgap.sh "$ENV_FILE"
```

`restore-system.sh`는 Compose 서비스를 내리고 named volume과 두 DB를 교체한 뒤
PostgreSQL만 기동한 상태로 끝납니다. 따라서 마지막 `start-airgap.sh`와 상태 확인을
생략하면 안 됩니다. 다른 `COMPOSE_PROJECT_NAME`, DB 이름, volume 이름으로 만든
백업을 현재 `.env`에 임의 복원하지 않습니다.

## 6. 폐쇄망 부분 교체

- 포털·worker·Dependency-Track 이미지나 Compose를 바꿀 때는 개별 image tar를
  직접 덮어쓰지 않고 새 전체 Tracker 릴리스의 manifest를 검증한 뒤 기존 설치
  디렉터리에 `install-airgap.sh`를 다시 실행합니다. 통합 KODA Suite 운영 서버는
  이 단독 절차 대신 Suite 압축파일의 `koda-suite install`을 사용합니다.
- 계정·역할·회차·감사 기록은 `sbom_tracker` DB, 업로드 원문은
  `tracker-artifacts` volume에 있으므로 관리자 대량 변경 전 전체 백업을 만듭니다.
- Dependency-Track 프로젝트·정책은 `dtrack` DB와 `dtrack-data` volume에 있으므로
  같은 전체 백업으로 보호합니다.
- Grype/NVD/KEV만 바꿀 때는 이미지를 다시 설치하지 않고
  `verify-vuln-bundle.sh` → `import-vuln-bundle.sh` → 포털 동기화 순서로 반입합니다.
- `.env`, TLS 인증서, 외부 reverse proxy 설정은 릴리스에 포함되지 않습니다. 변경
  전 별도 백업하고 `preflight-airgap.sh`를 통과시킨 뒤 서비스를 재기동합니다.

업그레이드 기동 시 기존 DB에는 환경 활성 상태 컬럼과 관리자 역할의 `sbom.delete`
권한이 보강됩니다. 취약점 원본, 감사 로그와 Dependency-Track 데이터는 변환하지
않으므로 기동 전 `sbom_tracker` DB와 artifact volume을 함께 백업합니다.

Tracker 단독 설치를 같은 디렉터리에서 갱신하는 예시는 다음과 같습니다.

```bash
RELEASE=/media/koda-release/koda-sbom-airgap-<버전>.tar.gz
PREFIX=/opt/koda-sbom

"$PREFIX/scripts/verify-airgap-release.sh" "$RELEASE"
docker compose --project-directory "$PREFIX" --env-file "$PREFIX/.env" \
  -f "$PREFIX/compose.yaml" -f "$PREFIX/compose.airgap.yaml" stop
ENV_FILE="$PREFIX/.env" BACKUP_ROOT=/media/koda-backup/tracker \
  "$PREFIX/scripts/backup-system.sh"
ENV_FILE="$PREFIX/.env" \
  "$PREFIX/scripts/verify-backup.sh" /media/koda-backup/tracker/<출력된-UTC-시각>
"$PREFIX/scripts/install-airgap.sh" "$RELEASE" "$PREFIX" --env-file "$PREFIX/.env"
"$PREFIX/scripts/start-airgap.sh" "$PREFIX/.env"
```

새 버전 확인 전에는 이전 릴리스와 백업, 기존 Docker 이미지를 유지합니다. 문제가
있으면 호환되는 이전 릴리스를 다시 설치한 뒤 그 시점의 검증된 백업을 복원합니다.

## 7. 서비스 계약

- `portal-web`: 8080 포트에서 HTTP 응답
- `portal-api`: 8000 포트에서 `/health`, `/api/...`
- `portal-worker`: 현재 `koda-tracker-worker` 프로세스 기반 healthcheck
- `ARTIFACT_ROOT`, `VULN_DATA_ROOT`, `UPLOAD_MAX_BYTES` 환경변수는 유지 권장
- `GATEWAY_APP_IP`를 바꾸면 `TRACKER_TRUSTED_PROXY_CIDRS`도 같은 gateway 주소로
  바꿉니다. 신뢰 목록 밖의 요청이 보낸 `X-Forwarded-For`는 사용하지 않습니다.

## 8. KODA/CI 업로드

관리자가 서비스 범위 API 토큰을 발급한 다음 아래 보조 CLI를 사용합니다.

```bash
KODA_TRACKER_URL=http://tracker.internal \
KODA_TRACKER_TOKEN='서비스 범위 토큰' \
./scripts/upload-sbom.sh <service-id> <environment-id> <release> <sbom-file> <idempotency-key>
```

동일 `Idempotency-Key` 재전송은 같은 회차를 반환하고, 다른 키로 같은 파일을
올리면 blob은 중복 저장하지 않으면서 새 회차를 배정합니다.

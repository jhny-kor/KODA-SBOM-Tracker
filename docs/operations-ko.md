# 운영 가이드

기동·계정 초기화·백업·부분 교체 등 일상 운영 절차입니다. 오류 증상별 대응은
[폐쇄망 장애 대응](troubleshooting-ko.md), 폐쇄망 반입 절차는
[오프라인 번들 가이드](offline-bundle-ko.md)를 따릅니다.

## 1. 구성

| 서비스 | 역할 |
| --- | --- |
| `gateway` | 외부 진입점. `/`는 포털, `/api`는 포털 API로 프록시 |
| `portal-web` | React/Vite 포털을 정적 빌드하여 8080 포트에서 제공 |
| `portal-api`, `portal-worker` | `apps/api` 실제 이미지 |
| `postgres` | 계정·회차·정책·검토·알림을 보관하는 `sbom_tracker` DB와 전용 계정 초기화 |
| `portal-data-updater` | 오프라인 데이터 검증·활성화·롤백 전용 worker |
| `portal-metadata-collector` | 공식 패키지 저장소·관측 CVE의 EPSS 수집 |

## 2. 초기 기동

```bash
make env
vi .env
docker compose build portal-web portal-api portal-worker
docker compose up -d
docker compose ps
```

Python 의존성은 `apps/api/uv.lock`으로 관리하고 Docker는 여기서 내보낸
`apps/api/constraints.txt`를 사용합니다. 의존성을 변경하면 두 파일을 함께 갱신합니다.

```bash
uv lock --project apps/api
uv export --project apps/api --locked --extra postgres --no-dev --no-emit-project --no-hashes --output-file apps/api/constraints.txt
```

보안 갱신 이후 JSON 요청은 `Content-Type: application/json`을 명시해야 합니다.
파일 업로드에는 기존처럼 `multipart/form-data`를 사용합니다. 포털과 제공 CI 실행기는
각 형식에 맞는 헤더를 전송합니다.

`.env` 필수 수정 항목:

| 항목 | 내용 |
| --- | --- |
| `POSTGRES_PASSWORD` | PostgreSQL superuser 비밀번호 |
| `TRACKER_DB_PASSWORD` | `sbom_tracker` DB 계정 비밀번호 |
| `TRACKER_BOOTSTRAP_ADMIN_PASSWORD` | 최초 Tracker 관리자 비밀번호 |
| `TRACKER_LDAP_ENCRYPTION_KEY` | LDAP bind 비밀번호를 DB에 저장할 때 사용하는 Fernet 키 |
| `PUBLIC_HTTP_BIND` | 기본은 로컬 전용 `127.0.0.1`; 원격 공개 시 아래 HTTPS 조건 필수 |
| 볼륨 이름, 외부 공개 포트 | 필요할 때만 변경 |

`make env`는 데이터베이스·최초 관리자·LDAP 암호화 키를 생성하고 `.env`를 `0600`으로
저장합니다. 운영에서 `PUBLIC_HTTP_BIND`를 loopback 이외 주소로 바꿀 때는 외부 TLS
reverse proxy와 함께 `TRACKER_ENVIRONMENT=production`, `TRACKER_SECURE_COOKIES=true`,
`TRACKER_PUBLIC_ORIGIN=https://<동일-오리진-호스트>`를 모두 설정해야 합니다.

KODA가 Grype DB 분석 결과로 지표·정책을 계산합니다. **설정 → SBOM 정책**에서
규칙과 만료 예외를 변경하고, 기존 회차는 **새 분석 리비전**으로 재평가합니다. 분석마다
정책 버전·스냅샷·평가 상태·근거가 보존됩니다. 미평가/실패를 위반 0건으로 해석하지 않습니다.
초기 기본 정책은 Critical/High 및 KEV 위반, 미확인 라이선스 경고이며 조직의 금지
라이선스·구성요소 목록은 운영자가 설정합니다. Grype DB 반입·롤백은 기존대로 유지합니다.
KEV 정책을 켠 상태에서 CISA KEV 데이터가 없으면 비해당으로 통과시키지 않고 데이터
부족 경고를 기록합니다. 유효한 빈 KEV 목록과 데이터 미공급을 구분합니다. 예외 만료는
다음 분석에서 반영되며 과거 리비전의 판정은 바뀌지 않습니다.

정책의 **위반**은 준수 여부 판정이며, 분석 작업이 정상적으로 끝났다는 **완료** 상태와
별개입니다. 현재 정책 판정 자체가 외부 배포를 차단하지는 않습니다. 규칙에는 서비스·환경·
릴리스 범위를 지정할 수 있으며 범위를 비우면 전체 서비스에 적용됩니다. 라이선스는 선언된 식별자와 `AND`·`OR` 표현식으로 검사하고,
`WITH` 예외·사용자 정의·미확인 정보는 검토 대상으로 남깁니다. SPDX 전체 식별자 목록
검증이나 법적 호환성 판단은 제공하지 않습니다. 정책 결과가 100,000건을 넘으면 평가
실패로 표시하며 규칙 범위를 줄여 재분석해야 합니다.

### 2-1. 계정과 권한 초기화

최초 기동 시 `TRACKER_BOOTSTRAP_ADMIN_USERNAME` 사용자가 없고
`TRACKER_BOOTSTRAP_ADMIN_PASSWORD`가 설정되어 있으면 활성 `admin` 계정을 한 번
생성합니다. 빈 값·12자 미만·알려진 기본값은 기동 시 거부됩니다. 과거 기본 비밀번호로
생성된 계정은 `.env`에 새 강력한 값을 한 번 설정하고 재기동하면 자동으로 교체되며
감사 로그가 남습니다. 로그인 후 설정 화면에서 다음 작업을 수행합니다.

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

운영 세션은 HTTPS 동일 오리진을 전제로 합니다. `TRACKER_ENVIRONMENT=production`은
HTTPS `TRACKER_PUBLIC_ORIGIN`과 `TRACKER_SECURE_COOKIES=true`가 아니면 기동을
거부합니다. reverse proxy는 원래 Host와 HTTPS scheme을 보존해야 합니다.

기동 후 실제 관리자 로그인, 서비스·환경 조회, 테스트 SBOM 업로드와 Grype 분석을
확인합니다. 결과의 분석 상태·정책 평가 상태·정책 버전·데이터 기준일을 함께 확인해야
하며, health 응답 한 건만으로 전체 기능이 검증됐다고 판단하지 않습니다.

### 계정·데이터 생명주기와 감사

- 서비스·환경 `삭제`는 `active=false`로 전환하는 논리 삭제입니다. 일반 목록과 새
  업로드 선택지에서는 숨기지만 과거 회차의 명칭은 보존합니다. 비활성 항목을 지정한
  새 업로드는 API가 거부합니다.
- 회차 `보관`은 `sbom.archive` 권한으로 상태를 바꿉니다. 회차 `영구 삭제`는 실제
  관리자이면서 `sbom.delete` 권한이 있을 때만 가능하며 완료·실패·보관 회차의 Tracker
  데이터와 로컬 원본만 제거합니다. 진행·대기 작업은 거부하며 외부 백업은 제거하지 않습니다.
- 감사 로그 조회와 CSV 다운로드는 실제 관리자이면서 `audit.view` 권한이 있어야
  합니다. `Excel 다운로드`는 현재 검색어를 적용한 전체 결과를 UTF-8 BOM CSV로
  내보내며 시각은 서울 시간, 위험한 셀 시작 문자는 수식으로 실행되지 않게 처리합니다.

### 2-2. KODA Suite 외부 TLS reverse proxy

> 이 문서의 호스트명과 IP는 커밋될 때 자리표시자로 자동 치환됩니다. 작업 트리에는
> 실제 값이 그대로 남습니다. 새 클론에서는 `./scripts/setup-host-redact.sh`를 한 번
> 실행하고 `.hostmap`에 실제 값을 채웁니다. 원격 저장소에는 실제 값이 올라가지 않습니다.

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
docker compose ps
curl -fsS http://localhost:${PUBLIC_HTTP_PORT:-8088}/healthz
curl -fsS http://localhost:${PUBLIC_HTTP_PORT:-8088}/api/v1/healthz
docker compose exec -T portal-web nginx -t
docker compose exec -T portal-worker grype version
```

gateway·web·API·분석 worker·데이터 updater·PostgreSQL이 실행 중인지 확인합니다.
브라우저에서 로그인하고 저장된 회차의 CVE·정책 근거를 조회합니다. 새 분석 리비전이
완료돼도 데이터 부족 경고나 정책 위반이 있으면 별도 조치가 필요합니다. 흰 화면·인증·
업로드·Grype DB 오류는 [폐쇄망 장애 대응](troubleshooting-ko.md)을 따릅니다.

## 5. 백업과 복원

백업 시점의 `.env`, 이미지 버전, 릴리스 압축파일을 한 세트로 보관합니다. 이
스크립트는 `.env`를 기본적으로 포함하지 않으므로 비밀번호·API 키가 든 원본은
접근 제한된 암호화 매체에 별도 보관합니다. 꼭 같은 백업 세트에 넣어야 할 때만
`INCLUDE_ENV_IN_BACKUP=1`을 사용하고 백업 디렉터리 권한을 즉시 제한합니다.

일관된 백업을 위해 유지보수 창에 쓰기 서비스를 먼저 중지합니다. PostgreSQL은
백업 스크립트가 필요한 동안만 기동합니다.

```bash
ENV_FILE=/opt/koda-sbom/.env
BACKUP_SIGNING_KEY=/etc/koda/keys/backup-signing.pem
BACKUP_VERIFY_KEY=/etc/koda/trust/backup-public.pem
docker compose --env-file "$ENV_FILE" -f compose.yaml -f compose.airgap.yaml \
  stop gateway portal-web portal-api portal-worker portal-data-updater portal-metadata-collector portal-project-sync

ENV_FILE="$ENV_FILE" BACKUP_ROOT=/media/koda-backup/tracker \
  KODA_BACKUP_SIGNING_KEY="$BACKUP_SIGNING_KEY" \
  ./scripts/backup-system.sh
ENV_FILE="$ENV_FILE" \
  ./scripts/verify-backup.sh /media/koda-backup/tracker/<출력된-UTC-시각> \
  --public-key "$BACKUP_VERIFY_KEY"

./scripts/start-airgap.sh "$ENV_FILE"
```

백업 세트의 범위는 다음과 같습니다.

| 포함 | 포함되지 않음 |
| --- | --- |
| PostgreSQL globals SQL | 운영 `.env` (위의 명시적 옵션을 사용한 경우만 포함) |
| `sbom_tracker` 논리 덤프 | 통합 Suite의 KODA 포털 SQLite·입력 파일 |
| `tracker-artifacts`, `vuln-data` volume tarball | 호스트에 별도로 둔 원본 SBOM, 스캔 대상, KODA 보고서, TLS 인증서 |
| compose/deploy 기준 설정 | Docker 이미지 tar와 릴리스 압축파일 |
| SHA-256 manifest와 detached signature | 백업 서명 개인키·검증 공개키 |

백업용 RSA 키 쌍은 릴리스 키와 분리합니다. `KODA_BACKUP_SIGNING_KEY` 개인키는
백업 디렉터리 밖의 접근 제한 경로에 두며, 공개키도 백업 세트와 다른 신뢰 저장소에
보관합니다. 서명 파일은 manifest가 공격자에 의해 함께 교체되는 것을 차단합니다.

서명 없이 백업해야 하는 제한된 환경에서는 생성과 검증에 모두 명시적 플래그를
지정합니다. checksum과 metadata/tar 안전성 검사는 유지되지만 백업의 진위는
검증되지 않습니다.

```bash
ENV_FILE="$ENV_FILE" BACKUP_ROOT=/media/koda-backup/tracker \
  KODA_ALLOW_UNSIGNED_ARTIFACTS=1 ./scripts/backup-system.sh
ENV_FILE="$ENV_FILE" KODA_ALLOW_UNSIGNED_ARTIFACTS=1 \
  ./scripts/verify-backup.sh /media/koda-backup/tracker/<출력된-UTC-시각>
```

복원은 현재 데이터를 교체하므로 검증된 백업과 그 백업을 만든 당시의 `.env` 및
호환 릴리스가 모두 준비된 경우에만 수행합니다. 현재 상태도 먼저 새 백업으로
보존하고, 백업 디렉터리를 검증한 다음 복원합니다.

```bash
ENV_FILE=/opt/koda-sbom/.env
BACKUP=/media/koda-backup/tracker/<UTC-시각>

ENV_FILE="$ENV_FILE" ./scripts/verify-backup.sh "$BACKUP" \
  --public-key /etc/koda/trust/backup-public.pem
ENV_FILE="$ENV_FILE" ./scripts/restore-system.sh "$BACKUP" \
  --public-key /etc/koda/trust/backup-public.pem
./scripts/start-airgap.sh "$ENV_FILE"
```

무서명 백업 복원은 공개키 없이 다음과 같이 실행합니다.

```bash
ENV_FILE="$ENV_FILE" KODA_ALLOW_UNSIGNED_ARTIFACTS=1 \
  ./scripts/restore-system.sh "$BACKUP"
```

`restore-system.sh`는 백업을 권한 `0700` 임시 디렉터리에 복사한 다음 서명·manifest,
현재 환경의 project/DB/volume metadata와 tar 경로를 검증합니다. 검증이 모두 끝난
뒤에만 Compose 서비스를 내리고 named volume과 두 DB를 교체한 뒤
PostgreSQL만 기동한 상태로 끝납니다. 따라서 마지막 `start-airgap.sh`와 상태 확인을
생략하면 안 됩니다. 다른 `COMPOSE_PROJECT_NAME`, DB 이름, volume 이름으로 만든
백업을 현재 `.env`에 임의 복원하지 않습니다.

## 6. 폐쇄망 부분 교체

- 포털·worker·데이터 updater 이미지나 Compose를 바꿀 때는 개별 image tar를
  직접 덮어쓰지 않고 새 전체 Tracker 릴리스의 manifest를 검증한 뒤 기존 설치
  디렉터리에 `install-airgap.sh`를 다시 실행합니다. 통합 KODA Suite 운영 서버는
  이 단독 절차 대신 Suite 압축파일의 `koda-suite install`을 사용합니다.
- 계정·역할·회차·감사 기록은 `sbom_tracker` DB, 업로드 원문은
  `tracker-artifacts` volume에 있으므로 관리자 대량 변경 전 전체 백업을 만듭니다.
- 정책 버전·VEX 검토·알림·재분석 일정도 `sbom_tracker` DB에 포함됩니다.
- Grype/NVD/KEV만 바꿀 때는 이미지를 다시 설치하지 않고
  `verify-vuln-bundle.sh` → `import-vuln-bundle.sh` → 포털 동기화 순서로 반입합니다.
- `.env`, TLS 인증서, 외부 reverse proxy 설정은 릴리스에 포함되지 않습니다. 변경
  전 별도 백업하고 `preflight-airgap.sh`를 통과시킨 뒤 서비스를 재기동합니다.

업그레이드 기동 시 기존 DB에는 환경 활성 상태 컬럼과 관리자 역할의 `sbom.delete`
권한이 보강됩니다. 기존 취약점 원본과 감사 로그를 보존하므로 기동 전 `sbom_tracker`
DB와 artifact volume을 함께 백업합니다.

Tracker 단독 설치를 같은 디렉터리에서 갱신하는 예시는 다음과 같습니다.

```bash
RELEASE=/media/koda-release/koda-sbom-airgap-<버전>.tar.gz
PREFIX=/opt/koda-sbom
RELEASE_VERIFY_KEY=/etc/koda/trust/release-public.pem
BACKUP_SIGNING_KEY=/etc/koda/keys/backup-signing.pem
BACKUP_VERIFY_KEY=/etc/koda/trust/backup-public.pem

"$PREFIX/scripts/verify-airgap-release.sh" "$RELEASE" \
  --public-key "$RELEASE_VERIFY_KEY" --signature "${RELEASE}.sig"
docker compose --project-directory "$PREFIX" --env-file "$PREFIX/.env" \
  -f "$PREFIX/compose.yaml" -f "$PREFIX/compose.airgap.yaml" stop
ENV_FILE="$PREFIX/.env" BACKUP_ROOT=/media/koda-backup/tracker \
  KODA_BACKUP_SIGNING_KEY="$BACKUP_SIGNING_KEY" \
  "$PREFIX/scripts/backup-system.sh"
ENV_FILE="$PREFIX/.env" \
  "$PREFIX/scripts/verify-backup.sh" /media/koda-backup/tracker/<출력된-UTC-시각> \
  --public-key "$BACKUP_VERIFY_KEY"
"$PREFIX/scripts/install-airgap.sh" "$RELEASE" "$PREFIX" \
  --public-key "$RELEASE_VERIFY_KEY" --signature "${RELEASE}.sig" \
  --env-file "$PREFIX/.env"
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

### 기존 백업

현재 KODA 백업은 데이터베이스·artifact·취약점 자료를 함께 검증한 후 격리된 복원 대상에서 복구합니다. 다른 제품의 백업을 현재 DB로 직접 복원하지 않습니다.

## 고급 정책·VEX·자동 재분석

KODA API와 일반 분석 worker가 아래 기능을 직접 처리합니다. Grype DB와 선택적인 KEV/NVD 데이터는 기존처럼 사용하며, 외부 취약점 API를 호출하지 않습니다.

| 기능 | 실제 처리 방식 | 운영상 경계 |
| --- | --- | --- |
| 서비스별 정책 | 규칙마다 서비스 ID·환경 ID·릴리스 버전을 지정. 빈 목록은 전체, 여러 범위는 교집합 | 릴리스 버전은 정확한 문자열 일치. 프로젝트는 KODA 서비스이며 환경·릴리스를 별도로 선택 |
| CEL 고급 조건 | `cel-expr-python==0.1.3` 표준 런타임, 구성요소·취약점·프로젝트별 평가 | 파일·네트워크·Python 함수 호출 없음. 오류/미확인 필드를 자동으로 통과시키지 않음 |
| 검토 | 제출 → 독립 검토자의 승인/거절, 의견과 결정 이력 보존 | 작성자 자기 승인 금지. 승인·거절 후 변경하려면 새 검토 제출 |
| VEX | CycloneDX 1.6 내보내기, 1.6/1.7 가져오기 | 정확한 bom-ref·구성요소 버전·CVE 대상만 허용. 가져오기는 미승인 검토로 등록 |
| VEX 평가 | 서비스·환경·정확한 구성요소 버전·취약점 기준으로 최신 승인 적용 | `not_affected`, `false_positive`만 보안 규칙을 제외. 라이선스/구성요소/프로젝트 규칙은 유지 |
| 알림 | 결과 변경·분석/정책 실패·검토 요청/결정의 영구 보관함, 사용자별 읽음 | 동일 결과의 반복 분석은 조용히 유지. 이메일/Slack 전용 전송기는 포함하지 않음 |
| Webhook | HMAC SHA-256 서명, 영구 outbox, 지수 backoff 후 최대 5회, 최종 실패 수동 재시도 | 명시한 호스트만 허용. 수신자는 이벤트 ID로 중복 수신 방지 필요 |
| 전체 SBOM 재분석 | 기본 활성·매일 1회, 모든 보관 전 회차에 새 분석 리비전 추가 | 5분~7일 간격, 범위/최신 회차만 옵션. 원본 SBOM과 과거 분석은 유지 |
| 데이터 갱신 후 재분석 | 활성 데이터 번들의 버전+매니페스트 변경 감지 | 진행 중 변경은 후속 사이클 하나로 합침. 최초 worker 관측은 변경으로 취급하지 않음 |

### CEL 작성과 검증

설정 → SBOM 정책에서 규칙 종류를 CEL로 선택하고 대상과 범위를 지정합니다. 식이 `true`이면 해당 규칙의 위반이며 `false`이면 통과입니다. 화면에서 저장 전 컴파일 검증을 실행할 수 있습니다. `POST /api/v1/sbom-policies/validate` API에 `expression`, `target`, `runId`를 보내면 해당 실제 회차의 저장된 분석 결과로 미리 평가할 수 있습니다. 미리 평가는 저장된 분석을 변경하지 않습니다.

```cel
// 취약점 대상: KEV이며 수정 가능한 버전이 있고 CVSS 9 이상
vulnerability.kev && size(vulnerability.fixedIn) > 0 && vulnerability.cvssScore >= 9.0

// 구성요소 대상: SPDX 목록을 대상으로 한 임의 조건
component.licenses.exists(l, l.startsWith("GPL-"))

// 프로젝트 대상: 운영 환경의 특정 릴리스
project.slug == "payments" && environment.slug == "prod" && release.version == "1.0"
```

변수는 `project{id,slug,name}`, `environment{id,slug,name}`, `release{version}`, `run{id,source,roundNumber}`, `component`, `vulnerability`, `now`입니다. 취약점 severity는 Grype 원문의 대소문자를 유지하므로 실제 미리보기로 확인합니다. 구성요소는 이름·버전·purl·라이선스·properties, 취약점은 ID·심각도·CVSS·KEV·수정 버전을 제공합니다. 데이터가 없는 선택 필드는 `has(...)`로 확인합니다. `ageDays`·`latestVersion`·`versionDistance`는 SBOM의 명시적인 `koda:*` properties가 있을 때만 존재하며 외부 저장소 조회나 임의 추정으로 만들지 않습니다.

CEL은 별도 격리 프로세스에서 최대 10초 wall time/8초 CPU, Linux 주소 공간 512MiB, 입력 32MiB, 출력 4MiB, 100,000회 평가 한도를 적용합니다. 식은 8,192바이트까지이며 표준 CEL 매크로·정규식·시간 연산을 지원합니다. 한도 초과와 런타임 오류는 해당 분석의 정책 실패로 기록합니다. 운영 데이터가 크면 규칙 범위나 대상 수를 줄여 조정합니다.

### VEX 검토의 적용 시점

회차 상세 → VEX·검토에서 정확한 구성요소/CVE를 선택합니다. 영향 없음/오탐에는 설명과 CycloneDX 근거 코드가 필수입니다. 만료 시각을 지정할 수 있습니다. 승인 결정은 **다음 재분석**부터 새 리비전에 적용하며 과거 리비전은 다시 쓰지 않습니다. 원본 CVE와 Grype 결과는 보존하고 유효 취약점 수·제외 수·검토 근거를 별도로 표시합니다. 만료된 최신 승인이 이전 승인을 되살리지는 않습니다. `resolved` 상태 자체로 탐지 결과를 제거하지 않으며 실제 수정 버전의 새 SBOM으로 확인합니다.

### 재분석 대기열과 복구

설정 → 재분석 일정에서 주기·범위를 저장하거나 수동 사이클을 실행합니다. 설치 직후 첫 예약은 24시간 뒤입니다. 기본은 모든 저장된 보관 전 회차이며 최신 회차만 옵션을 켜면 릴리스별 마지막 보관 전 회차를 선택합니다. 비활성 카탈로그에 속하더라도 보관하지 않은 기록은 기본 전체 범위에 포함됩니다. 일정 비활성화는 앞으로의 자동 접수를 중지하며 이미 접수한 사이클은 끝까지 처리합니다.

사이클의 대상 목록과 회차별 대기·접수·완료·실패·건너뜀 상태는 DB에 저장됩니다. 대기열 용량이 부족하거나 해당 회차가 이미 실행 중이면 대기했다가 같은 사이클에서 접수합니다. 삭제/보관된 대상은 건너뜁니다. worker는 약 10초마다 진행을 확인하지만 실제 실행 시각은 다른 분석 시간에 따라 지연될 수 있습니다. 작업이 중단되면 15분 임대 만료 후 재접수하며 3번째 시도까지 실패하면 최종 실패로 표시합니다. 복수 worker는 DB 잠금과 활성 사이클 고유 키로 중복 접수를 방지합니다.

### Webhook 설정

`.env`에서 다음 값을 지정한 뒤 API와 일반 worker를 다시 생성합니다. 설정 화면은 활성 여부와 호스트 등 비밀값이 아닌 상태만 표시합니다.

```dotenv
TRACKER_NOTIFICATION_WEBHOOK_ENABLED=true
TRACKER_NOTIFICATION_WEBHOOK_URL=https://alerts.example.internal/koda
TRACKER_NOTIFICATION_ALLOWED_HOSTS=alerts.example.internal
TRACKER_NOTIFICATION_WEBHOOK_SECRET=<별도 생성한 충분히 긴 비밀키>
```

기본 Docker `app` 네트워크는 `internal: true`입니다. 같은 네트워크의 내부 수신기를 연결하거나 필요한 목적지로만 도달할 수 있는 별도 네트워크 구성을 운영자가 제공해야 합니다. URL 지정만으로 외부 통신이 열리지는 않습니다. HTTP는 명시적으로 허용한 내부 호스트에서만 사용할 수 있고, 리디렉션과 환경 proxy는 사용하지 않습니다. `X-KODA-Signature: sha256=<HMAC>`를 원본 요청 바이트로 검증하고 `Idempotency-Key`의 이벤트 ID를 중복 처리하지 않도록 저장합니다. 네트워크 오류에도 보관함 기록은 남습니다.

## 자체 프로젝트와 패키지 메타데이터

### 프로젝트 계층·태그·최신 버전

프로젝트 카탈로그에서 자체 프로젝트를 등록하고 계층·태그·최신 범위를 관리합니다.
부모는 같은 원본의 프로젝트 ID로 지정하며 순환 계층은 거절합니다. 최신 표시를 켜면 같은
원본·이름의 다른 버전 최신 표시는 해제합니다. 기존 회차를 연결하거나 같은 서비스·환경·버전의
업로드를 자동 대응시킵니다. 카탈로그 변경은 과거 SBOM·분석을 덮어쓰지 않습니다.

- `GET/POST /api/v1/project-catalog`, `PATCH /api/v1/project-catalog/{id}`
- `POST /api/v1/project-catalog/{id}/runs`: 기존 회차 연결
- 변경 시 `expectedRevision`을 보내며 충돌은 HTTP 409로 다시 조회합니다.
- 정책 `projectScope`는 `sourceId`, `projectIds`, `tags`, `includeChildren`, `onlyLatest`입니다.
  프로젝트 또는 태그가 맞는 집합에 적용하고, ID·태그를 모두 비우면 같은 원본 전체입니다.

### 최신 버전·출시일 자동 수집

`portal-metadata-collector`가 npm·PyPI·Maven·NuGet·Go·Cargo 공식 HTTPS API를 조회합니다.
신규 업로드뿐 아니라 기존 구성요소도 자동 백필하고 기본 24시간 캐시를 갱신합니다.
분석 API와 Grype worker는 외부 저장소를 호출하지 않고 캐시만 읽습니다.
수집기에만 별도 `metadata-egress` 네트워크를 연결하며 API·일반 worker는 내부망을 유지합니다.

```dotenv
TRACKER_PACKAGE_METADATA_ENABLED=true
TRACKER_PACKAGE_METADATA_TTL_SECONDS=86400
TRACKER_PACKAGE_METADATA_REQUEST_TIMEOUT_SECONDS=10
TRACKER_PACKAGE_METADATA_MIN_INTERVAL_SECONDS=1
TRACKER_PACKAGE_METADATA_MAX_ATTEMPTS=3
TRACKER_PACKAGE_METADATA_RETRY_SECONDS=60
```

회차 상세에서 최신 버전·현재/최신 공개 시각·출처·수집/만료 시각·필드별 미확인을 확인합니다.
패키지 관리 체계마다 '최신' 정의가 달라 npm의 latest 태그와 안정 버전, 배포 철회/미공개 여부 등을
구분해 기록합니다. 지원하지 않는 ecosystem과 잘못된 PURL은 명시적으로 표시합니다.
Maven은 공식 Central의 정확한 좌표별 색인 시각을 수집합니다. 색인에서 시각을 확인하지 못하면 해당 버전 POM의 Last-Modified를
**저장소 파일 시각(최초 출시일 미확정)**으로 표시합니다. 이를 최초 공개일로 보증하지 않습니다.
`versionDistance`는 지원하는 체계의 안정 릴리스 개수 차이이며 단위별 버전 차이가 아닙니다.
Maven은 ComparableVersion으로 정렬한 안정 릴리스 수, Go는 버전 목록과 최신 go.mod의 철회 범위를 반영한 안정 릴리스 수를 계산합니다. Go 시각은 공식 프로토콜이 제공하는 **소스 리비전 생성 시각**으로 표시하며 최초 저장소 공개일이라고 보증하지 않습니다.
`versionDistanceParts`와 `versionDistancePartsBasis`는 원본 방식의 단위 거리이며 기존 `versionDistance` 릴리스 개수와 분리합니다.

누락·만료·오류·null 필드는 CEL에 정상 최신 값으로 공급하지 않습니다.
관련 데이터를 사용하는 조건이 `has()`로 누락을 건너뛰더라도 데이터 부족 경고와
`policyDataComplete=false`를 기록합니다. 과거 리비전에는 사용한 메타데이터 증거를 보존합니다.

`GET /api/v1/package-metadata/status`, 회차별 `GET /api/v1/sbom-runs/{id}/package-metadata`,
수동 갱신 `POST /api/v1/sbom-runs/{id}/package-metadata/refresh`를 제공합니다.
폐쇄망은 수집을 끄고 `GET /api/v1/package-metadata/export?page=1&size=1000`으로 받은 캐시를
`POST /api/v1/package-metadata/import`로 반입합니다. 여러 페이지는 빠짐없이 반입해야 합니다.
반입 데이터의 원래 시각과 출처를 보존하며 오래된 자료를 새 수집으로 위장하지 않습니다.

### CWE·EPSS 데이터와 폐쇄망 반입

CWE는 실제 Grype 결과·반입 NVD·원본 분석의 구조화된 필드에서 읽습니다.
별도 수집기는 관측한 CVE만 FIRST 공식 API에 최대 40개씩 조회하며 모든 CVE의 벌크 복제에
API를 사용하지 않습니다. 출처·EPSS 점수·백분위·원본 기준일·관측/만료 시각을 보존합니다.
점수는 0~1의 유한수이고, 캐시 유효기간 24시간과 원본 기준일 최대 2일을 함께 확인합니다.
없음·실패·만료를 0점으로 바꾸지 않습니다. 승인된 VEX는 효과적인 정책 대상에서 제외합니다.

- `GET /api/v1/vulnerability-intelligence/status`
- `GET /api/v1/vulnerability-intelligence/export?page=1&size=1000`
- `POST /api/v1/vulnerability-intelligence/import` (설정의 EPSS 캐시 가져오기도 제공)

반입은 `koda-vulnerability-intelligence-v1` 형식, 원본 HTTPS 출처·기준일·관측/만료 시각이
필요합니다. 더 오래된 기준일·관측 자료가 최신 증거를 덮어쓰지 않습니다. 새 분석에서만 반영됩니다.
CWE·EPSS 또는 고급 helper가 필요한 데이터를 찾지 못하면 `policyDataComplete=false`와
억제할 수 없는 데이터 부족 경고를 남깁니다. 읽기 전용 수집기와 동기화 worker에만 별도 외부
네트워크를 연결하며 일반 분석 worker는 캐시·반입 DB만 사용합니다.

공급원 계약: [FIRST EPSS API](https://api.first.org/epss/),
[Maven Central 검색](https://central.sonatype.org/search/),
[Go module proxy](https://go.dev/ref/mod#goproxy-protocol),
[Go 철회 지시문](https://go.dev/ref/mod#retract).

동기화로 원본 분석·정책·계층·태그·최신 표시가 바뀌면 해당 회차의 Grype 재분석을 자동 접수합니다.
변경 없는 재수집은 작업을 추가하지 않습니다. 접수 요청은 DB에 보존되며, 대기열이 가득 차면
다음 tick에 재시도하고 실행 중 분석이 있으면 완료 뒤 새 분석을 실행합니다. 동기화 이력의
`nativeReanalysisRequested`·`nativeReanalysisEnqueued`로 접수량을 확인합니다. 과거 원본 분석은
보존하지만 재분석 대기·실행 상태를 표시하므로 이를 새 Grype 완료 결과로 간주하지 않습니다.
활성 원본의 명시적 재동기화는 자체 편집한 카탈로그를 원본 값으로 다시 맞춥니다.
자체 값을 계속 유지하려면 해당 원본 동기화를 비활성화합니다. 정책의 로컬 수정 충돌은 계속 차단합니다.

## Collection 집계와 사내 취약점 DB

설정의 **프로젝트 카탈로그**에서 부모 프로젝트의 Collection 방식을
선택하고 지표를 조회합니다. 일반 프로젝트는 `NONE`, Collection은 아래 방식을 사용합니다.

| 방식 | 선택 범위 |
| --- | --- |
| `AGGREGATE_DIRECT_CHILDREN` | 활성 직접 자식. 자식 Collection은 그 자식의 설정에 따라 재귀 집계 |
| `AGGREGATE_LATEST_VERSION_CHILDREN` | `isLatest=true`인 활성 직접 자식. 자동 버전 문자열 비교가 아니라 카탈로그 최신 표시 사용 |
| `AGGREGATE_DIRECT_CHILDREN_WITH_TAG` | 지정 태그가 있는 활성 직접 자식. 중첩 Collection의 자식은 자체 설정 적용 |
| `AGGREGATE_ALL_DESCENDANTS` | 활성 하위 일반 프로젝트 전체. 중간 일반 프로젝트도 포함하며 Collection 자신의 SBOM은 제외 |

집계는 프로젝트별 최신 비보관 회차 하나의 최신 완료 분석을 사용하며 동일 회차는 한 번만
합산합니다. Collection 자신의 SBOM은 합산하지 않습니다. 최신 회차가 미분석이면 더 오래된
회차의 성공을 대신 쓰지 않습니다. 해당 회차의 재분석 대기·실패 시 이전 완료 리비전은
`stale` 증거로 구분합니다. 누락·오래된 결과·정책 미평가 또는 정책 데이터 부족이 있으면 커버리지는 불완전합니다.
취약점 합계는 승인된 VEX 억제 후 발생 건수이며 고유 취약점 ID 수는 별도입니다.
구성요소는 프로젝트별 발생 건수여서 포트폴리오 고유 패키지 수와 다릅니다.

- `GET /api/v1/project-catalog/{id}/metrics`: 합계, 커버리지, 프로젝트별 회차·분석 증거.
- 카탈로그 생성/수정의 `collectionLogic`, `collectionTag`: 설정. 수정 시 `expectedRevision` 필요.
- 카탈로그 조회에는 `catalog.manage`, 변경에는 관리자 역할과 같은 권한·CSRF 검증이 필요합니다.

설정의 **사내 취약점 DB**에서 내부 ID(예: `KODA-2026-001`) 또는 CVE ID, 제목·설명,
심각도·CVSS·CWE·별칭·참고 URL, 영향 패키지와 수정 버전을 작성합니다. 조회는 관리자와
`metadata.view` 또는 `metadata.manage`, 작성은 관리자와 `metadata.manage`가 필요합니다. 초안은 분석에 사용하지 않고, 게시된 항목만 실제 Grype
분석 결과에 합칩니다. DB 조회·버전 매칭은 오프라인이며 참고 URL이나 패키지 코드를 실행하지 않습니다.

영향 패키지는 **버전·qualifier·subpath 없는 PURL**로 지정하고 정확한 버전을 나열하거나
범위를 지정합니다. `introduced`는 포함, `fixed`는 미포함, `lastAffected`는 포함이며
`fixed`와 `lastAffected`는 함께 지정하지 않습니다. Maven은 Maven ComparableVersion
정렬을, SemVer 범위는 정식 `x.y.z`를 사용합니다. prerelease·build metadata 등 다른 표기는
정확 버전 목록에 명시합니다. PyPI 등 범위 정렬을 지원하지 않는 생태계도 정확 버전 목록을
사용하며 임의의 문자열 순서로 취약 여부를 추정하지 않습니다. `fixedVersions`는 수정 권고이며
영향 판정은 `versions`/`ranges`로 결정합니다. 분석 입력의 qualifier/subpath는 패키지 식별에서
제외하며 사설 저장소 URL을 접속하지 않습니다. PURL의 버전과 구성요소 버전이 모순되면 일치로 처리하지 않습니다.

- `GET/POST /api/v1/private-vulnerabilities`: 페이지 목록 / 생성.
- `PUT /api/v1/private-vulnerabilities/{id}`: 전체 문서 수정. `expectedRevision` 필수, ID 변경 불가.
- `DELETE /api/v1/private-vulnerabilities/{id}?expectedRevision=N`: 물리 삭제 대신 철회.
- `GET /api/v1/private-vulnerabilities/{id}/history`: 페이지별 불변 작성 이력.

게시·게시 내용 변경·철회는 이전/현재 영향 버전에 해당하는 비보관 회차의 재분석 의도를
`portal-worker`가 실제 Grype 분석을 실행합니다. 큐가 가득 차거나 이미 분석 중이면 의도를
보존해 재시도합니다. `affectedRunsQueued`는 접수 수이며 완료 수가 아닙니다.
재분석 완료를 확인한 뒤 결과를 판단합니다. 철회는 새 결과에서 제외하며 이전 분석은 변경하지 않습니다.
각 분석의 `dataSources.privateVulnerabilityDb`는 게시 항목의 불변 작성 리비전과 해시를 보관합니다.
사내 DB 테이블은 기존 PostgreSQL 백업·복원 대상에 포함됩니다.

사내 내부 ID도 발견 화면·정책·VEX·회차 비교·Collection에 포함합니다. 사내 항목의 공개 CVE 별칭은 보존하되 내부 ID를 유지해
같은 공개 CVE 발견과 VEX 검토 대상을 구분합니다. Grype DB는 계속 사용하며 사내 DB가 이를 대체하지 않습니다.
검증 명령과 실제 결과는 [Docker 추가 검증](verification-collection-private-20261018-ko.md)을 참조합니다.

## SBOM 정규화 보정과 NuGet 수집기 업그레이드

정규화 v2는 JSON/XML 중첩 구성요소를 목록·지표·정책·메타데이터 접수·업로드 할당량에서
같은 범위로 계산합니다. npm scope를 패키지 버전과 구분하며 대소문자를 구분하는 생태계의
좌표도 보존합니다. Collection의 자동 회차 연결은 전체 원본 카탈로그에서 좌표가 유일할 때만
사용합니다. 소유가 모호하면 `ambiguousProjectCount`와 불완전 커버리지를 표시하며,
관리자가 카탈로그의 회차 연결 API로 정확한 소유를 지정해야 합니다.

기존 DB는 `run_normalizations` 테이블을 자동 생성합니다. 분석 worker는 이전 자료를 기본
10초마다 한 회차씩 보정하며, 분석 작업도 시작 전에 보정을 수행합니다. XML은 원본 파일의
SHA-256을 검증한 뒤 중첩 정보를 복구합니다. JSON은 보존한 계층에서 파생 행을 재생성합니다.
변경된 비보관 회차는 영속 큐로 새 Grype/정책 분석을 접수합니다. 보관 회차는 파생 목록만
보정하고 분석하지 않습니다. 원본 파일과 기존 분석 리비전·정책 스냅샷은 변경하지 않습니다.
이전 자료의 1차 순회가 끝나면 완료 표식을 저장해 전체 자료를 계속 재탐색하지 않습니다.
새 분석의 `dataSources.sbomNormalization.version=2`로 새 계산 근거를 구분합니다.
따라서 과거 잘못된 집계는 당시 분석 증거에 남고, 최신 분석에서 수정된 값을 제공합니다.

대량 초기 보정을 앞당기거나 실패 원인을 해결한 뒤 재시도하려면 worker가 실행 중이어도
다음 명령을 사용할 수 있습니다. 회차 잠금으로 같은 자료를 동시에 보정하지 않습니다.

```bash
docker compose exec portal-api python -m koda_tracker.sbom_normalization --limit 1000
docker compose exec portal-api python -m koda_tracker.sbom_normalization --limit 1000 --retry-failed
```

처리·변경·재분석 접수·실패 수를 확인하고 감사 로그의 `sbom.normalization_rebuild` /
`sbom.normalization_failed`를 확인합니다. 원본 누락·해시 불일치·잘못된 구조는 기존 파생
행을 보존한 채 실패로 기록합니다. 비보관 회차의 실패는 분석 실패 상태로 표시하며,
반복 실패로 worker를 막지 않도록 유지보수 루프에서는 자동 반복하지 않습니다.
일반 재분석 또는 `--retry-failed`로 복구를 다시 시도합니다.

NuGet은 공식 서비스 인덱스의 `RegistrationsBaseUrl/3.6.0`을 발견해 SemVer2 등록 정보를
읽습니다. 이전 8페이지 제한을 제거하고 전체 페이지를 순회합니다. 최대 4,096페이지/
100,000개 레코드·응답 크기·요청 시간의 안전 한도는 유지하며 초과/부분 실패를 성공으로
표시하지 않습니다. 현재 prerelease의 공개일도 수집하되 `latestVersion`은 listed 정식
버전을 선택합니다. 미리보기 버전을 정식 업그레이드 대상으로 잘못 권고하지 않습니다.

최초 `nuget-semver2-v1` 업그레이드 때 이전 공개 캐시 성공/영구 실패를 재접수하고 재시도
횟수를 초기화합니다. 이전 문서는 새 수집이 완료될 때까지 stale/pending 근거로 남습니다.
오프라인 반입 자료는 유지합니다. 폐쇄망의 구형 NuGet 캐시는 연결된 수집기에서 다시 내보내
반입해야 최신 SemVer2 자료로 바뀝니다.

## SBOM 품질 진단 운영

신규·재분석에서 품질 리비전을 자동 생성합니다. 초기에는 공통 경고 모드이며 프로젝트별 강제 기준을 설정할 수 있습니다. 기준 변경은 영향받는 비보관 회차 재분석을 접수하며 과거 결과를 보존합니다. 기존 회차는 재분석 또는 상세 화면의 품질 재진단으로 결과를 생성합니다. 수동 품질 재진단 뒤 CI를 실행하려면 분석도 실행해 같은 품질 근거를 사용해야 합니다.

조회·수정 권한, 기준과 문법 예시, 게이트 종료 코드와 기존 자료 한계는 [품질 운영 안내](sbom-quality-ko.md), 검증 결과는 [Docker 검증](verification-quality-20261018-ko.md)을 확인하세요.

가중 점수와 부모·태그 기준 상속은 [품질 운영 안내](sbom-quality-ko.md#가중-품질-점수)를 따릅니다. 기존 품질 리비전은 보존하며, 엔진 2 점수는 새 분석에서 생성합니다. 태그 동률·소유 모호함·부모 누락/순환은 설정을 수정한 뒤 자동 재분석 결과를 확인하세요. 검증 후 Docker 종료·빌드 캐시 정리 결과는 [추가 검증 기록](verification-quality-inheritance-20261018-ko.md)에 기록했습니다.

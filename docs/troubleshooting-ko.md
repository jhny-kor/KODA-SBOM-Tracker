# KODA SBOM Tracker 폐쇄망 장애 대응

이 문서는 Tracker 단독 설치와 KODA 통합 Suite에서 공통으로 발생한
Dependency-Track 화면·로그인·API 키·SBOM 업로드 오류를 다룹니다. 통합 Suite의
KODA 화면·계정 승인·압축파일·Docker 교체 문제는 KODA 저장소의
`platforms/linux/suite/TROUBLESHOOTING.ko.md`를 함께 확인합니다.

비밀번호와 API 키 원문은 명령 출력, 캡처와 로그에 남기지 않습니다.

## 증상별 찾아보기

| 증상 | 절 |
| --- | --- |
| 어디부터 볼지 모르겠다 | [1. 공통 상태 확인](#1-공통-상태-확인) |
| Dependency-Track이 흰 화면이다 | [2. Dependency-Track 화면은 뜨지만 흰 화면](#2-dependency-track-화면은-뜨지만-흰-화면) |
| Tracker 계정으로 Dependency-Track에 로그인되지 않는다 | [3. Dependency-Track 로그인 계정](#3-dependency-track-로그인-계정) |
| 어떤 키를 어디에 넣는지 모르겠다 | [4. Tracker 연동 API 키](#4-tracker-연동-api-키) |
| `HTTP 401 Unauthorized` | [5. `HTTP 401 Unauthorized`](#5-http-401-unauthorized) |
| `PUT v1/permission/team (HTTP 304)` | [6. `PUT v1/permission/team (HTTP 304)`](#6-put-v1permissionteam-http-304) |
| 분석은 됐는데 Dependency-Track이 `HTTP 400` | [7. 분석은 일부 성공했지만 Dependency-Track가 HTTP 400](#7-분석은-일부-성공했지만-dependency-track가-http-400) |
| 작은 파일인데 `413` | [8. 작은 파일인데 `413 Request Entity Too Large`](#8-작은-파일인데-413-request-entity-too-large) |
| 고친 UI가 화면에 안 나온다 | [9. 수정한 UI가 아니라 이전 화면](#9-수정한-ui가-아니라-이전-화면) |
| 브라우저가 `DNS_PROBE_FINISHED_NXDOMAIN` | [9-1. 외부 TLS 주소가 DNS에서 해석되지 않음](#9-1-외부-tls-주소가-dns에서-해석되지-않음) |
| Nginx 설정을 저장했는데 컨테이너에서 이전 파일을 읽는다 | [9-2. 단일 파일 bind mount가 이전 inode를 가리킴](#9-2-단일-파일-bind-mount가-이전-inode를-가리킴) |
| LDAP 인증은 성공했지만 로그인되지 않는다 | [9-6. 신규 LDAP 사용자가 승인 대기임](#9-6-신규-ldap-사용자가-승인-대기임) |
| 다 고쳤는데 정상인지 판단이 안 선다 | [10. 정상 완료 기준](#10-정상-완료-기준) |

## 0. 설치 형태에 맞는 compose 인자

이 문서의 `docker compose` 명령은 설치 형태에 따라 파일 인자가 다릅니다. 아래 값을
현재 셸에 먼저 설정하고, 이어지는 명령의 `$TRACKER_ROOT`와 `$COMPOSE_FILES`를 그대로
사용합니다.

```bash
# 단독 설치
TRACKER_ROOT=/opt/koda-sbom
COMPOSE_FILES=(-f compose.yaml -f compose.airgap.yaml)

# KODA 통합 Suite. compose.integration.yaml은 Suite 압축파일에만 들어 있습니다.
TRACKER_ROOT=/home/user0/koda-suite/tracker
COMPOSE_FILES=(-f compose.yaml -f compose.airgap.yaml -f compose.integration.yaml)
```

## 1. 공통 상태 확인

```bash
cd "$TRACKER_ROOT"

docker compose --env-file .env "${COMPOSE_FILES[@]}" ps

curl -fsS http://127.0.0.1:8088/healthz
curl -fsS http://127.0.0.1:8088/api/v1/healthz
curl -fsS http://127.0.0.1:8088/dependency-track/api/version
curl -fsS http://127.0.0.1:8088/dependency-track/static/config.json \
  | python3 -m json.tool
```

`static/config.json`의 `API_BASE_URL`은 원격 브라우저가 접근할 수 있는 서버
IP/FQDN이어야 합니다. 원격 PC에서 접속하는데 `localhost`, `127.0.0.1` 또는
`dtrack-apiserver`가 보이면 잘못된 설정입니다.

## 2. Dependency-Track 화면은 뜨지만 흰 화면

HTML 한 건만 200이어도 정상이라고 판단할 수 없습니다. 정적 설정과 실제 JS/CSS,
API 경로를 함께 확인합니다.

```bash
curl -I http://127.0.0.1:8088/dependency-track/
curl -I http://127.0.0.1:8088/dependency-track/static/config.json
```

`static/config.json`은 캐시하지 않도록 gateway가 `Cache-Control: no-store`를
추가합니다. 이 파일이 404이거나 이전 주소를 반환하면 최신 gateway를 사용하고
frontend와 gateway만 오프라인 모드로 재생성합니다.

```bash
docker compose --env-file .env "${COMPOSE_FILES[@]}" \
  up -d --no-build --pull never --force-recreate dtrack-frontend gateway
```

공개 URL 설정은 다음 계약을 지킵니다.

```dotenv
DTRACK_API_BASE_URL=http://<서버IP>:8088/dependency-track
DTRACK_ADMIN_API_BASE_URL=http://<서버IP>:8088/dependency-track/api
```

frontend 공개 base에는 `/api`를 붙이지 않고 관리자 자동화 base에만 붙입니다.
`DTRACK_BASE_PATH`는 `/dependency-track`처럼 끝 `/` 없이 유지합니다. compose가
Dependency-Track frontend에만 끝 `/`를 추가해 상대 JS/CSS가
`/dependency-track/...`에서 로드되도록 합니다. 이 값이 빠지면 HTML은 200이어도
브라우저가 JS를 `/js/...`에서 받아 흰 화면이 될 수 있습니다.
`<base href="/dependency-track/">`가 정상이어도 로그인 XHR이 `localhost`로 가면
원격 PC에서 `ERR_CONNECTION_REFUSED`가 발생합니다.

## 3. Dependency-Track 로그인 계정

Dependency-Track UI 계정은 Tracker 계정과 별도입니다. Tracker 또는 KODA에
로그인한 계정으로 Dependency-Track에 자동 로그인되지 않습니다. 최초
Dependency-Track 관리자 계정으로 로그인해 전용 automation team/API 키를
발급합니다.

## 4. Tracker 연동 API 키

`TRACKER_DEPENDENCY_TRACK_API_KEY`에는 Dependency-Track 전용 team API 키를
넣습니다. Tracker 서비스 토큰이나 사용자 비밀번호를 넣지 않습니다. 필요한 최소
권한은 다음 여섯 개입니다.

- `BOM_UPLOAD`
- `PROJECT_CREATION_UPLOAD`
- `PORTFOLIO_MANAGEMENT_UPDATE`
- `VIEW_PORTFOLIO`
- `VIEW_VULNERABILITY`
- `VIEW_POLICY_VIOLATION`

team의 사용자 멤버가 0명이어도 API 키 인증에는 문제가 없습니다. 키와 team 권한이
중요합니다. 현재 검증기는 `v1/team/self` 응답의 team 이름과 권한을 확인합니다.

```bash
./scripts/verify-dtrack-connection.sh
```

성공 기준은 `Dependency-Track connection OK`와 여섯 권한 목록입니다.

## 5. `HTTP 401 Unauthorized`

키가 틀렸거나 다른 Dependency-Track 인스턴스에서 발급됐거나, `.env` 변경 후
API/worker가 이전 환경값으로 실행 중인 경우입니다. 키 원문을 출력하지 말고 연결
검사 후 두 서비스만 재생성합니다.

```bash
docker compose --env-file .env "${COMPOSE_FILES[@]}" \
  up -d --no-build --pull never --force-recreate portal-api portal-worker

./scripts/verify-dtrack-connection.sh
```

## 6. `PUT v1/permission/team (HTTP 304)`

권한이 이미 같은 상태라는 응답입니다. 최신 `configure-dtrack-key.sh`는 이 304를
성공으로 처리합니다. 구형 스크립트가 실패로 처리하면 최신 Tracker 릴리스를
사용합니다. 관리자 키는 `.env`에 저장하지 않고 현재 셸에만 입력합니다.

```bash
read -rsp 'Dependency-Track 관리자 API 키: ' DTRACK_ADMIN_API_KEY; echo
export DTRACK_ADMIN_API_KEY
export DTRACK_ADMIN_API_BASE_URL=http://127.0.0.1:8088/dependency-track/api
DTRACK_TARGET_ENV_FILE=/home/user0/koda-suite/tracker/.env \
  ./scripts/configure-dtrack-key.sh
unset DTRACK_ADMIN_API_KEY
```

스크립트 완료 후 `portal-api`, `portal-worker`를 재생성하고 연결 검사를 다시
실행합니다. 기존 키가 있는 team의 키는 자동 회전하지 않습니다.

## 7. 분석은 일부 성공했지만 Dependency-Track가 HTTP 400

오프라인 Grype 분석은 완료됐지만 Dependency-Track가 BOM을 거부한 상태입니다.
최신 worker는 `Dependency-Track BOM 업로드 실패 (HTTP 400): ...` 형태로 서버가
반환한 검증 사유를 회차 오류에 보존합니다.

다음을 확인합니다.

- 최상위 `bomFormat`이 `CycloneDX`인지
- `specVersion`, `components`, `bom-ref`, PURL 등 필수 필드가 유효한지
- 실제 UTF-8 CycloneDX JSON/XML인지
- 설치된 Dependency-Track가 그 CycloneDX 버전을 지원하는지

`specVersion` 문자열만 1.7에서 1.6으로 바꾸지 않습니다. 1.7 전용 필드가 남아
잘못된 1.6 문서가 될 수 있습니다. 연결망 PC의 생성 도구에서 처음부터 1.6으로
출력하거나 CycloneDX 검증·변환 도구로 변환한 뒤 폐쇄망에 반입합니다. 원인을
고친 다음 회차 화면의 `DTrack 재시도`를 사용합니다.

## 8. 작은 파일인데 `413 Request Entity Too Large`

현재 Tracker API 파일 제한은 100MiB이고 gateway 요청 제한은 101MiB입니다. 3MiB
수준에서 413이면 대부분 구형 gateway 또는 앞단 TLS reverse proxy 제한입니다.

```bash
grep '^UPLOAD_MAX_BYTES=' .env
docker compose --env-file .env "${COMPOSE_FILES[@]}" \
  exec gateway nginx -T 2>/dev/null | grep client_max_body_size
```

정상값은 `UPLOAD_MAX_BYTES=104857600`, `client_max_body_size 101m;`입니다. API는
파일 자체를 100MiB로 제한하고 gateway의 추가 1MiB는 multipart 요청 정보를 수용합니다.
외부 Nginx·Apache·L7 장비가 있으면 그 제한도 101MiB 이상이어야 합니다.

## 9-1. 외부 TLS 주소가 DNS에서 해석되지 않음

`DNS_PROBE_FINISHED_NXDOMAIN`은 Docker·Nginx에 도달하기 전에 DNS가
`koda.ssis.or.kr` 레코드를 찾지 못했다는 뜻입니다. 서버에서 다음 명령으로
확인합니다.

```bash
nslookup koda.ssis.or.kr
```

사내 DNS의 `ssis.or.kr` zone에 다음 A 레코드를 추가합니다. 사설 IP이므로 외부
공개 DNS에 넣을지 여부는 네트워크 정책에 따릅니다.

```text
koda.ssis.or.kr.  A  10.95.58.147
```

DNS 반영 전 Windows 브라우저에서만 임시 확인할 때는 관리자 권한으로
`C:\Windows\System32\drivers\etc\hosts`에 다음 줄을 넣고 DNS 캐시를 비웁니다.

```text
10.95.58.147  koda.ssis.or.kr
```

```cmd
ipconfig /flushdns
```

`curl --resolve koda.ssis.or.kr:443:10.95.58.147 ...`는 DNS를 우회하는 테스트라서,
이 명령이 성공해도 브라우저의 DNS 레코드가 자동으로 만들어지는 것은 아닙니다.

## 9-2. 단일 파일 bind mount가 이전 inode를 가리킴

`nginx.conf`를 호스트에서 `vi`로 저장한 뒤에도 컨테이너에서 이전 내용이 보이면
먼저 source와 destination의 hash를 비교합니다.

```bash
MAIN=/data/docker_data/volumes/nginx/conf/nginx.conf
CONT=/usr/local/openresty/nginx/conf/nginx.conf

sha256sum "$MAIN"
docker exec nginx sha256sum "$CONT"
docker inspect -f \
  '{{range .Mounts}}{{println .Type .Source "->" .Destination "rw=" .RW}}{{end}}' nginx
```

단일 파일 bind mount에서 편집기가 inode를 교체하면 Docker가 이전 inode를 계속
볼 수 있습니다. 해시가 다를 때는 호스트 파일을 현재 mount inode에 동기화하고
검사·reload합니다.

```bash
sudo cp -a "$MAIN" "$MAIN.bak.$(date +%Y%m%d%H%M%S)"
docker exec -u 0 -i nginx sh -c \
  'cat > /usr/local/openresty/nginx/conf/nginx.conf' < "$MAIN"
docker exec nginx nginx -t
docker exec nginx nginx -T 2>&1 | grep -n 'server_name koda\.ssis\.or\.kr'
docker exec nginx nginx -s reload
```

컨테이너를 교체할 때는 `/data/docker_data/volumes/nginx/conf/nginx.conf`와
`conf.d`, `ssl`의 세 bind mount를 동일하게 유지합니다. 컨테이너 내부에만 복사한
설정·인증서는 교체 시 사라집니다.

## 9-3. `/koda/`가 `http://호스트:8080/koda/login`으로 redirect됨

`/koda/live`가 `{"status":"live"}`를 반환하면 KODA 경로와 프로세스는 정상이고,
내부 HTTP gateway가 자신의 `:8080` 기준으로 절대 redirect를 만든 상태입니다.
외부 TLS vhost의 HTTPS `server` 블록에 다음 두 규칙을 추가합니다.

```nginx
location = /koda { return 308 /koda/; }
location / {
    proxy_pass http://10.95.58.147:8088;
    proxy_redirect http://koda.ssis.or.kr:8080/ https://koda.ssis.or.kr/;
}
```

기존 `proxy_set_header`와 timeout 설정은 삭제하지 않습니다. `nginx -t` 후 reload하고,
`curl -sSI https://koda.ssis.or.kr/koda/`의 `Location`이 `https://koda.ssis.or.kr`
또는 상대 경로 `/koda/login`인지 확인합니다. `http://...:8080`이 남으면 실제 active
설정에 `proxy_redirect`가 포함됐는지 `nginx -T`로 확인합니다.

## 9-4. SBOM 업로드에서 `CSRF 토큰이 유효하지 않습니다`

외부 Nginx 설정에 다음 줄이 있으면 브라우저가 보낸 토큰이 사라집니다.

```nginx
proxy_set_header X-CSRF-Token $cookie_csrf_token;
```

Tracker는 CSRF 토큰을 쿠키가 아니라 `X-CSRF-Token` 요청 헤더로 받습니다. 위 줄을
삭제하고, 다른 `X-CSRF-Token` 재설정도 두지 않은 채 원래 헤더를 그대로 전달합니다.

```bash
docker exec nginx nginx -t && docker exec nginx nginx -s reload
docker exec nginx nginx -T 2>&1 | grep -n 'X-CSRF-Token'
```

마지막 명령에 결과가 없어야 합니다. 브라우저에서 강력 새로고침 후 다시 로그인하고
업로드합니다. 계속 403이면 여러 탭을 닫고 새 탭에서 로그인해 토큰을 재발급합니다.

## 9-5. CycloneDX 검증에서 `Unable to auto-detect input format`

업로드 파일은 서버에서 `koda-sbom-*` 확장자 없는 임시 파일로 저장됩니다. 구버전
Tracker API는 이 경로를 CycloneDX CLI에 그대로 넘겨 CLI가 형식을 자동 감지하지
못했습니다. 현재 API는 파일 내용을 판별한 뒤 `--input-format json` 또는
`--input-format xml`을 명시합니다.

실행 중인 API 이미지에 이 수정이 들어갔는지 확인합니다.

```bash
docker exec koda-sbom-portal-api sh -c \
  "grep -n 'input-format' /app/koda_tracker/main.py /app/koda_tracker/sbom.py"
```

출력이 없으면 `./koda-suite start`만 다시 실행해도 기존 이미지를 계속 사용하므로,
수정이 포함된 새 Suite 이미지/압축파일로 `portal-api`를 교체해야 합니다. 출력이
있는데도 실패하면 업로드 파일이 CycloneDX JSON/XML인지, 최상위 `bomFormat`이
`CycloneDX`인지, `specVersion`이 1.4~1.7인지 확인합니다. `package-lock.json`,
SPDX JSON, 일반 Syft JSON은 그대로 올리지 말고 CycloneDX JSON/XML로 변환합니다.

## 9-6. 신규 LDAP 사용자가 승인 대기임

LDAP 사용자 이름과 비밀번호가 맞아도 처음 인증한 계정은 즉시 로그인되지 않습니다.
자동 프로비저닝은 사용자를 비활성 `승인 대기` 상태로만 만들며 세션을 발급하지 않는
것이 정상 동작입니다. 관리자가 Tracker의 `설정 → 사용자 관리`에서 역할을 확인하고
승인한 뒤 사용자가 LDAP 로그인을 다시 시도합니다.

승인 전에 같은 계정으로 반복 로그인하거나 LDAP 기본 역할·그룹 매핑을 바꿔도 승인
절차를 건너뛰지 않습니다. 승인된 계정인데도 403이면 사용자 활성 상태와 LDAP subject
일치 여부를 감사 로그에서 확인합니다.

## 9. 수정한 UI가 아니라 이전 화면

브라우저 강력 새로고침 또는 시크릿 창에서 먼저 확인합니다. 계속 같으면 소스만
교체한 것이 아니라 현재 `portal-web` 이미지가 새로 빌드·반입됐는지 확인합니다.

```bash
docker inspect koda-sbom-portal-web \
  --format 'image={{.Image}} created={{.Created}}'
```

폐쇄망에서는 개별 파일을 컨테이너에 덮어쓰지 않습니다. 새 전체 Tracker 릴리스
manifest를 검증해 설치하거나, 통합 Suite라면 새 Suite 압축파일을 같은 prefix에
설치합니다. 새 설치 검증 전에는 DB·named volume과 이전 릴리스를 보존합니다.

## 10. 정상 완료 기준

- `/`, `/api/v1/healthz`, `/dependency-track/`이 정상 응답한다.
- `static/config.json`과 로그인 XHR에 `localhost`가 없다.
- `verify-dtrack-connection.sh`가 team과 여섯 권한을 확인한다.
- 테스트 CycloneDX SBOM 한 건이 오프라인 분석과 Dependency-Track 전송을 완료한다.
- 400/401 실패 시 회차 화면에 원인 상태가 남고, 수정 후 재시도가 성공한다.
- 운영 `.env`, 데이터 volume과 이전 릴리스는 검증 완료 전까지 보존한다.

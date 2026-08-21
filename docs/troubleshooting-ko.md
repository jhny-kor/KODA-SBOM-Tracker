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

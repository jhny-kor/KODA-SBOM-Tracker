# KODA SBOM Tracker 폐쇄망 장애 대응

이 문서는 KODA 자체 운영에서 발생하는 기동·로그인·SBOM 업로드·Grype DB·정책 평가
오류를 다룹니다. 통합 Suite의 KODA 화면·계정 승인·압축파일·Docker 교체 문제는
KODA 저장소의 `platforms/linux/suite/TROUBLESHOOTING.ko.md`를 함께 확인합니다.

비밀번호와 API 토큰 원문은 명령 출력, 캡처와 로그에 남기지 않습니다.

## 증상별 찾아보기

| 증상 | 절 |
| --- | --- |
| 어디부터 볼지 모르겠다 | [1. 공통 상태 확인](#1-공통-상태-확인) |
| Grype 분석이 실패하거나 DB를 찾지 못한다 | [2. Grype DB와 분석 실패](#2-grype-db와-분석-실패) |
| 정책이 미평가·실패·데이터 부족이다 | [3. 정책 평가 상태](#3-정책-평가-상태) |
| API가 `HTTP 401 Unauthorized`를 반환한다 | [4. 인증과 서비스 토큰](#4-인증과-서비스-토큰) |
| 작은 파일인데 `413` | [5. 작은 파일인데 413](#5-작은-파일인데-413-request-entity-too-large) |
| 고친 UI가 화면에 안 나온다 | [6. 수정한 UI가 아니라 이전 화면](#6-수정한-ui가-아니라-이전-화면) |
| 외부 주소가 DNS에서 해석되지 않는다 | [6-1. 외부 TLS 주소](#6-1-외부-tls-주소가-dns에서-해석되지-않음) |
| Nginx가 이전 bind mount 파일을 읽는다 | [6-2. 단일 파일 bind mount](#6-2-단일-파일-bind-mount가-이전-inode를-가리킴) |
| LDAP 인증 후 로그인되지 않는다 | [6-6. 신규 LDAP 사용자 승인](#6-6-신규-ldap-사용자가-승인-대기임) |
| 정상인지 판단이 안 선다 | [7. 정상 완료 기준](#7-정상-완료-기준) |

## 0. 설치 형태에 맞는 compose 인자

이 문서의 `docker compose` 명령은 설치 형태에 따라 파일 인자가 다릅니다. 아래 값을
현재 셸에 먼저 설정하고, 이어지는 명령의 `$TRACKER_ROOT`와 `$COMPOSE_FILES`를 그대로
사용합니다.

```bash
# 단독 설치
TRACKER_ROOT=/opt/koda-sbom
COMPOSE_FILES=(-f compose.yaml -f compose.airgap.yaml)

# KODA 통합 Suite. compose.integration.yaml은 Suite 압축파일에만 들어 있습니다.
TRACKER_ROOT=/opt/koda-suite/tracker
COMPOSE_FILES=(-f compose.yaml -f compose.airgap.yaml -f compose.integration.yaml)
```

KODA는 Grype DB 분석과 자체 정책 평가를 사용합니다. 정책이 **미평가**이면
분석 상태부터 확인하고, **실패**이면 Grype DB·정책 오류를 확인합니다. 단순 0건은
평가가 성공하고 필요한 데이터가 제공된 경우에만 정상 준수 결과로 해석합니다.

## 1. 공통 상태 확인

```bash
cd "$TRACKER_ROOT"
docker compose --env-file .env "${COMPOSE_FILES[@]}" ps
curl -fsS http://127.0.0.1:8088/healthz
curl -fsS http://127.0.0.1:8088/api/v1/healthz
docker compose --env-file .env "${COMPOSE_FILES[@]}" logs --tail 100 portal-api portal-worker portal-data-updater portal-metadata-collector portal-project-sync
```

gateway·web·API·분석 worker·데이터 updater·PostgreSQL을 각각 확인합니다. health 응답이
정상이어도 실제 로그인·업로드·분석이 되는지는 별도 확인합니다. 로그를 공유할 때는
호스트·토큰·쿠키·사용자 식별자 등 비밀·개인정보를 가립니다.

## 2. Grype DB와 분석 실패

회차 상세와 분석 리비전의 오류를 먼저 확인합니다. 실행 파일 누락, DB 경로·권한,
손상된 DB와 도구/DB 스키마 호환성은 서로 다른 문제입니다.

```bash
docker compose --env-file .env "${COMPOSE_FILES[@]}" exec -T portal-worker grype version
docker compose --env-file .env "${COMPOSE_FILES[@]}" exec -T portal-worker grype db status
```

폐쇄망 분석은 `GRYPE_DB_AUTO_UPDATE=false`로 실행됩니다.
**설정 → 취약점 데이터**에서 통합 자료 검증·적용 완료와 활성 릴리스·자료별 기준일을 확인한 뒤
회차 상세에서 **새 분석 리비전**을 실행합니다. [통합 취약점 자료 반입](unified-vulnerability-data-ko.md)

`NVD temporary index changed; retry from the approved release`는 승인 원본을 읽는 데
쓰는 임시 SQLite 색인의 파일 상태가 달라져 발생합니다. 활성 릴리스를 확인하고
**새 분석 리비전**을 한 번 실행한 뒤 **완료** 상태와 취약점·정책 평가 결과를 확인합니다.
같은 오류가 반복되면 분석 워커에서 `TRACKER_NVD_CACHE_DIR`의 쓰기 권한·디스크 여유와
백업·정리 작업의 실행 시간을 확인하고, 진행 중인 분석이 없는 시간에 분석 워커를 재시작한 뒤
다시 분석합니다. [전체 NVD 자료 처리](linux-tracker-update-ko.md#전체-nvd-자료-처리)

## 3. 정책 평가 상태

| 상태 | 확인과 조치 |
| --- | --- |
| 미평가 | Grype 분석 완료 여부와 대기/실행 작업을 확인. 실패 원인을 고친 뒤 새 분석 리비전 실행 |
| 평가 실패 | 저장된 오류에서 CEL 컴파일/실행, 입력·평가 한도, 데이터 형식을 확인. 자동 통과로 취급하지 않음 |
| 데이터 부족 경고 | KEV 등 필요한 데이터의 실제 공급 여부·출처·기준일 확인. 빈 정상 목록과 미공급을 구분 |
| 위반/경고 | 정책 버전·범위·구성요소·CVE·근거를 검토. 필요한 조치나 기한부 예외·VEX 검토 수행 |
| 정책 저장 충돌 409 | 다른 사용자가 변경한 최신 정책을 다시 불러와 병합. 오래된 버전을 덮어쓰지 않음 |

정책 변경과 예외 만료·승인된 VEX는 다음 분석에서 반영됩니다. 과거 리비전은 바뀌지
않습니다. 기본 자동 재분석 일정, 수동 사이클 또는 새 분석 리비전을 사용하고, 접수와
완료를 구분해 확인합니다. 보관된 회차는 다시 분석하지 않습니다.

## 4. 인증과 서비스 토큰

브라우저 로그인 전 세션 확인 `/api/v1/auth/me`의 401은 정상일 수 있습니다. 로그인
성공 뒤에도 401이면 세션 만료·쿠키 secure 설정·동일 오리진·로그아웃 여부를 확인합니다.
403은 역할 권한, 사용자 승인/활성 상태 또는 CSRF 검증을 확인합니다.

CI 업로드에는 설정에서 발급한 **서비스 범위 API 토큰**을 사용합니다. 사용자 비밀번호를
Bearer 토큰으로 보내지 않고, 토큰의 서비스와 업로드 대상 서비스가 일치하는지 확인합니다.
회전·폐기된 토큰은 다시 사용할 수 없습니다. 토큰 원문을 출력하지 않습니다.

## 5. 작은 파일인데 `413 Request Entity Too Large`

현재 Tracker API의 SBOM 파일 제한은 500MiB이고 gateway의 정확한 SBOM 업로드 경로는
multipart 여유를 포함해 501MiB입니다. 로그인·가입 등 일반 API 요청은 64KiB로
제한됩니다. 작은 SBOM에서 413이면 대부분 구형 gateway 또는 앞단 TLS reverse proxy
제한입니다.

```bash
grep '^UPLOAD_MAX_BYTES=' .env
docker compose --env-file .env "${COMPOSE_FILES[@]}" \
  exec gateway nginx -T 2>/dev/null | grep client_max_body_size
```

정상값은 `UPLOAD_MAX_BYTES=524288000`이며 nginx 출력에는 서버 기본
`client_max_body_size 64k;`와 `/api/v1/sbom-runs` 전용
`client_max_body_size 501m;`가 함께 표시됩니다. 추가 1MiB는 multipart 요청 정보를
수용합니다. 외부 Nginx·Apache·L7 장비가 있으면 SBOM 업로드 경로만 501MiB 이상으로
설정하고 인증·제어 경로에는 작은 기본 한도를 유지합니다.

## 6. 수정한 UI가 아니라 이전 화면

브라우저 강력 새로고침 또는 시크릿 창에서 먼저 확인합니다. 계속 같으면 소스만
교체한 것이 아니라 현재 `portal-web` 이미지가 새로 빌드·반입됐는지 확인합니다.

```bash
docker inspect koda-sbom-portal-web \
  --format 'image={{.Image}} created={{.Created}}'
```

폐쇄망에서는 개별 파일을 컨테이너에 덮어쓰지 않습니다. 새 전체 Tracker 릴리스
manifest를 검증해 설치하거나, 통합 Suite라면 새 Suite 압축파일을 같은 prefix에
설치합니다. 새 설치 검증 전에는 DB·named volume과 이전 릴리스를 보존합니다.

## 6-1. 외부 TLS 주소가 DNS에서 해석되지 않음

> 이 문서의 호스트명과 IP는 커밋 시 자리표시자로 치환됩니다. 설정 방법은
> [운영 가이드](operations-ko.md#2-2-koda-suite-외부-tls-reverse-proxy)에 있습니다.

`DNS_PROBE_FINISHED_NXDOMAIN`은 Docker·Nginx에 도달하기 전에 DNS가
`koda.example.internal` 레코드를 찾지 못했다는 뜻입니다. 서버에서 다음 명령으로
확인합니다.

```bash
nslookup koda.example.internal
```

사내 DNS의 `example.internal` zone에 다음 A 레코드를 추가합니다. 사설 IP이므로 외부
공개 DNS에 넣을지 여부는 네트워크 정책에 따릅니다.

```text
koda.example.internal.  A  10.0.0.10
```

DNS 반영 전 Windows 브라우저에서만 임시 확인할 때는 관리자 권한으로
`C:\Windows\System32\drivers\etc\hosts`에 다음 줄을 넣고 DNS 캐시를 비웁니다.

```text
10.0.0.10  koda.example.internal
```

```cmd
ipconfig /flushdns
```

`curl --resolve koda.example.internal:443:10.0.0.10 ...`는 DNS를 우회하는 테스트라서,
이 명령이 성공해도 브라우저의 DNS 레코드가 자동으로 만들어지는 것은 아닙니다.

## 6-2. 단일 파일 bind mount가 이전 inode를 가리킴

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

## 6-3. `/koda/`가 `http://호스트:8080/koda/login`으로 redirect됨

`/koda/live`가 `{"status":"live"}`를 반환하면 KODA 경로와 프로세스는 정상이고,
내부 HTTP gateway가 자신의 `:8080` 기준으로 절대 redirect를 만든 상태입니다.
외부 TLS vhost의 HTTPS `server` 블록에 다음 두 규칙을 추가합니다.

```nginx
location = /koda { return 308 /koda/; }
location / {
    proxy_pass http://10.0.0.10:8088;
    proxy_redirect http://koda.example.internal:8080/ https://koda.example.internal/;
}
```

기존 `proxy_set_header`와 timeout 설정은 삭제하지 않습니다. `nginx -t` 후 reload하고,
`curl -sSI https://koda.example.internal/koda/`의 `Location`이 `https://koda.example.internal`
또는 상대 경로 `/koda/login`인지 확인합니다. `http://...:8080`이 남으면 실제 active
설정에 `proxy_redirect`가 포함됐는지 `nginx -T`로 확인합니다.

## 6-4. SBOM 업로드에서 `CSRF 토큰이 유효하지 않습니다`

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

## 6-5. CycloneDX 검증에서 `Unable to auto-detect input format`

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
있는데도 실패하면 업로드한 CycloneDX JSON/XML의 `bomFormat`과 `specVersion`을
확인합니다. SPDX 2.3 JSON도 별도 지원 형식입니다. `package-lock.json`이나 Syft
전용 JSON은 생성 도구에서 지원 형식의 SBOM으로 내보냅니다.

등록은 됐지만 분석 리비전에 `sbom format not recognized`가 표시되면, 2절의
`grype version`으로 분석 워커의 버전을 확인합니다. Grype 0.109.1을 사용하는
워커에 CycloneDX 1.7을 등록했다면 생성 도구에서 CycloneDX 1.6 JSON으로 다시
내보내 등록합니다. [Grype 0.115.0의 CycloneDX 1.7 읽기 지원](https://github.com/anchore/grype/releases/tag/v0.115.0)

## 6-6. 신규 LDAP 사용자가 승인 대기임

LDAP 사용자 이름과 비밀번호가 맞아도 처음 인증한 계정은 즉시 로그인되지 않습니다.
자동 프로비저닝은 사용자를 비활성 `승인 대기` 상태로만 만들며 세션을 발급하지 않는
것이 정상 동작입니다. 관리자가 Tracker의 `설정 → 사용자 관리`에서 역할을 확인하고
승인한 뒤 사용자가 LDAP 로그인을 다시 시도합니다.

승인 전에 같은 계정으로 반복 로그인하거나 LDAP 기본 역할·그룹 매핑을 바꿔도 승인
절차를 건너뛰지 않습니다. 승인된 계정인데도 403이면 사용자 활성 상태와 LDAP subject
일치 여부를 감사 로그에서 확인합니다.

## 7. 정상 완료 기준

- `/`, `/api/v1/healthz`가 정상 응답한다.
- 테스트 CycloneDX SBOM 한 건이 Grype 분석·KODA 정책 평가를 완료하고 정책 버전과 지표가 남는다.
- 400/401 실패 시 회차 화면에 원인 상태가 남고, 수정 후 재시도가 성공한다.
- 운영 `.env`, 데이터 volume과 이전 릴리스는 검증 완료 전까지 보존한다.

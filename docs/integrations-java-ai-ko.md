# Tracker 외부 조회, Java/Maven 영향 검토 및 공통 AI

## 외부 사이트에서 Tracker 조회

1. Tracker의 **설정 → 연동 설정 → 외부 API 조회 토큰**에서 연동 시스템 이름, 서비스, 환경, 유효 기간을 선택합니다. 환경 전체는 해당 서비스의 모든 활성 환경입니다.
2. 발급 화면에서 `koda_read_` 토큰을 복사해 연동 사이트의 **서버 측 비밀 저장소**에 등록합니다. Tracker는 발급 이후 원문을 다시 표시하지 않습니다.
3. 연동 사이트의 백엔드가 Tracker HTTPS 게이트웨이에 `Authorization: Bearer <토큰>` 헤더로 요청합니다. 사용자 브라우저에는 연동 사이트 백엔드가 필요한 결과만 반환합니다.

기준 경로는 `/api/v1/integrations/external`입니다.

| 메서드와 경로 | 결과 |
| --- | --- |
| `GET /scope` | 토큰이 읽을 수 있는 서비스와 활성 환경 ID |
| `GET /runs` | 범위 안의 회차 목록과 분석 상태 |
| `GET /runs/{runId}` | 회차 식별자, 릴리스, 환경, 분석 상태 |
| `GET /runs/{runId}/components` | 구성요소 식별 상태, 그룹, 이름, 버전, PURL |
| `GET /runs/{runId}/findings` | CVE 또는 등록 취약점 식별자, 심각도, 구성요소, 버전과 수정 버전 |
| `GET /comparison?baseRunId=…&targetRunId=…` | 범위 안의 두 회차 비교 요약 |
| `GET /java-deployments` | 범위 안에서 등록한 Java 배포 기준 |
| `POST /upgrade-assessments` | Java/Maven 업그레이드 검토 계산 |

목록·구성요소·취약점 조회는 `page`(기본 1), `size`(기본 20, 최대 100)를 받습니다. 취약점 조회 응답의 `dataAvailable`, `analysisState`, `dataAsOf`를 함께 확인합니다. 분석이 끝나지 않았거나 자료가 없을 때 빈 결과를 취약점 0건으로 표시하지 않습니다.

```sh
# TRACKER_URL과 TRACKER_READ_TOKEN은 연동 서버의 보호된 설정에서 주입합니다.
curl --fail-with-body --silent --show-error \
  --header "Authorization: Bearer ${TRACKER_READ_TOKEN}" \
  "${TRACKER_URL}/api/v1/integrations/external/runs?page=1&size=20"
```

미인증·만료·폐기는 HTTP 401, 토큰 대상 서비스 또는 환경 비활성은 403, 범위 밖 회차는 404입니다. 외부 조회는 보관된 회차와 원본 SBOM, 증거 원문, 관리자 설정을 제공하지 않습니다. 토큰은 최장 90일로 발급할 수 있고 연동 화면에서 폐기합니다. 기존 SBOM 업로드와 KODA 자동 전송은 기존 서비스 토큰을 사용합니다.

## Java/Maven 업그레이드 검토

여러 후보의 조건 충족 최고 버전과 빌드·실행 이력을 보려면 [폐쇄망 후보 버전 일괄 검토](offline-upgrade-ko.md)를 사용하세요.

1. Tracker의 **SBOM 회차**에서 실제 배포에 사용한 회차를 열고 **Java/Maven 버전 영향 검토 → 현재 회차를 배포 기준으로 등록**을 엽니다. 서비스·환경은 해당 회차에서 가져옵니다. 관리자가 서버 별칭, 배포 Java 메이저 버전, OS와 아키텍처를 기록합니다. 같은 서비스·환경·서버 별칭에 저장하면 기존 배포 기준이 갱신됩니다.
2. **업그레이드 후보 검토**에서 배포 기준과 Maven PURL(예: `pkg:maven/org.apache.logging.log4j/log4j-core`)을 선택하거나 입력합니다. 후보 버전을 직접 넣거나 동일 서비스의 후보 빌드 SBOM 회차를 고릅니다.
3. 후보에 최소 Java 버전이 문서화되어 있으면 근거와 함께 입력합니다. 배포 Java보다 높은 경우 요구 버전 충돌이 표시됩니다. 두 SBOM이 있는 경우 구성요소의 관측 버전 집합을 비교하고, 분석 자료의 매니페스트 해시·분석기·정규화 버전이 확인될 때 공개 CVE 변화도 표시합니다.

검토는 선택한 패키지의 관측 의존 경로와 그 패키지를 사용하는 등록 배포 기준을 보여줍니다. SBOM 그래프에서 구성요소 사본마다 최단 경로 하나를 표시합니다. 운영체제와 아키텍처는 배포 문맥으로 기록합니다. 실제 Maven 재해석, ABI 검사, 서버 실행이나 배포는 수행하지 않습니다. 후보 버전만 직접 입력한 경우에는 후보 SBOM의 전이 의존성이나 CVE 변화를 계산할 근거가 없습니다. 매니페스트 해시를 저장하기 전에 수행한 분석은 동일 자료로 재분석해야 CVE 변화를 비교할 수 있습니다. 기존 결과 리비전은 보존됩니다.

외부 조회 API에서 같은 검토를 호출하려면 `GET /java-deployments`의 ID를 사용합니다. 예를 들어 다음 JSON을 `POST /upgrade-assessments`에 전송합니다.

```json
{
  "deploymentId": "<배포 기준 ID>",
  "coordinate": "pkg:maven/org.example/app-core",
  "candidateRunId": "<후보 회차 ID>",
  "minimumJavaMajor": 17,
  "requirementEvidence": "후보 릴리스 노트의 Java 요구사항"
}
```

`candidateRunId` 대신 `candidateVersion`을 보낼 수 있습니다. 외부 조회 토큰으로 계산하는 경우 기준 회차와 후보 회차가 모두 토큰 범위에 있어야 합니다. 응답의 `declared_conflict`는 입력한 최소 Java 요구 버전과의 충돌이고, `needs_verification`은 추가 검증이 필요한 상태입니다.

## KODA와 Tracker 공통 AI

1. Tracker의 **설정 → 공통 AI → 사내 AI 서버 주소**에 `https://ai-gateway.internal/v1`처럼 주소를 입력합니다. 사설망으로 해석되는 주소를 사용합니다. 인증 키를 사용하는 사내 서버에는 HTTPS와 Tracker 컨테이너가 신뢰하는 인증서가 필요합니다. 운영 env의 `TRACKER_AI_BASE_URL`은 처음 설정할 때 기본값으로 사용합니다.
2. 별도로 생성한 Fernet 암호화 키를 운영 env의 `TRACKER_AI_ENCRYPTION_KEY`에 보관합니다. 이 값은 AI 서버의 API 키와 별개입니다. 안전한 관리 세션에서 `python3 -c 'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())'`로 생성할 수 있습니다. 암호화 키는 보호된 설정과 함께 백업합니다.
3. Compose 기본 구성에서는 Tracker API만 전용 `<Compose 프로젝트명>-ai` 내부 네트워크에 연결됩니다. 같은 호스트에서는 승인된 모델 컨테이너 또는 TLS 프록시를 이 네트워크에 연결합니다. 모델이 다른 서버에 있으면 사내 방화벽으로 모델 주소와 포트만 허용한 프록시를 이 네트워크에 배치합니다. Tracker API 컨테이너에서 지정 호스트가 사설 주소로 해석되어야 합니다. 호스트의 `localhost`와 컨테이너의 `localhost`는 서로 다른 주소입니다.
4. 새 설정을 적용한 Tracker에서 **설정 → 공통 AI**를 엽니다. 서버에서 사용하는 모델 ID와 필요한 API 키를 저장하고 **저장된 설정으로 연결 시험**을 실행합니다. 저장된 API 키는 암호화되며 화면에는 등록 여부만 보입니다. 주소를 변경할 때 새 서버에 API 키가 필요하면 키를 다시 입력합니다.
5. Tracker는 **SBOM 회차 상세 → 사내 AI로 요약**, KODA는 **점검 결과 상세 → AI 요약 생성**에서 사용합니다. KODA는 기존 `KODA_TRACKER_URL`과 `KODA_TRACKER_PROVISIONING_TOKEN_FILE`로 Tracker를 호출합니다. KODA **관리자 설정 → 연동 설정**에서도 Tracker의 공통 AI 설정을 열 수 있습니다.

요약은 Tracker의 심각도별 건수와 최대 25개 CVE ID, KODA의 심각도별 건수와 최대 25개 규칙 ID를 사용합니다. AI 응답은 검토 참고용으로 화면에 표시합니다. 점검 결과와 정책 판정은 원래 분석기가 관리합니다.

### KODA 점검 항목별 AI 검토

KODA의 완료된 점검에서 소스코드 또는 라이브러리 발견을 선택하고 **AI 검토**를 실행합니다. 프로젝트의 `runs.ai_review` 권한이 필요합니다. KODA 서버가 기존 프로비저닝 토큰으로 Tracker의 `POST /api/v1/integrations/koda/ai-finding-review`를 호출합니다.

모델로 보내는 내용은 선택한 발견의 제한된 근거입니다. 소스코드 발견에는 수집된 코드 문맥과 추적 근거가 포함될 수 있고, 라이브러리 발견에는 패키지, 버전, 취약점 ID, 수정 버전과 의존 경로가 포함될 수 있습니다. KODA와 Tracker가 알려진 자격 증명 패턴을 가립니다. 비밀 탐지 항목은 Tracker가 규칙 ID와 심각도만 전달합니다. 소스 문맥을 처리할 수 있도록 승인된 사내 모델을 연결하세요.

응답에서 검토 분류, 판단 근거, 영향 범위, 권장 조치, 재점검 방법을 확인합니다. KODA 화면과 보고서에는 참고 의견으로 표시됩니다. 원본 발견의 탐지 결과, 심각도, Tracker 승인 기록은 각 제품의 기존 분석·검토 절차로 관리합니다.

### Tracker 결과 해설: 릴리스 브리핑, 후보 해설, CPE 식별 후보

세 기능 모두 Tracker가 계산한 결과를 사내 모델이 **설명**합니다. 심각도, 정책 결과, VEX 판정,
버전 선택과 저장된 SBOM·분석은 바꾸지 않습니다. 모델 응답은 정해진 JSON 형식만 받고, 형식이
맞지 않으면 화면에 표시하지 않고 오류(HTTP 502)로 처리합니다. 응답의 자격 증명 패턴은 가립니다.

| 기능 | 위치와 권한 | 모델로 보내는 내용 | 보내지 않는 내용 |
| --- | --- | --- | --- |
| 릴리스 브리핑 | **회차 비교 → 사내 AI 릴리스 브리핑** (`compare.view`) | 변경 건수, 정책 평가 상태, 신규·해소 취약점(KEV·심각도 순, 영역별 최대 30건), 구성요소 추가·제거·변경, 정책 변화(최대 20건) | SBOM 해시, 회차 ID, 원본 링크, 취약점 설명 원문 |
| 후보 해설 | **SBOM 회차 상세 → 폐쇄망 후보 버전 일괄 검토 → 결과 → 사내 AI로 해설** (`runs.view`) | 생태계, 패키지, 배포 OS·아키텍처·런타임 버전, 엔진이 고른 조건 충족·검증 최고 버전, 후보별 조건 상태·사유·빌드·실행 기록, 공식 자료 파일 종류와 출처 호스트 | 서버 별칭, 기록 출처, Python 환경 마커 |
| CPE 식별 후보 | **SBOM 회차 상세 → 구성요소 검사기 → CPE 식별 후보** (PURL 없는 구성요소, `runs.view`) | 구성요소 이름·그룹·버전·종류와 아래 규칙으로 찾은 후보 목록 | SBOM 원본, 다른 구성요소 |

- **릴리스 브리핑**은 새로 생긴 위험, 해소된 위험, 승인 전 확인 항목을 보여줍니다. 목록이 잘리면 화면에 안내가 나오므로 아래 탭에서 전체 변경을 확인합니다.
- **후보 해설**은 검토 엔진이 이미 고른 버전을 설명하도록 지시합니다. 후보별 설명 목록에서 반입 후보에 없거나 중복된 버전은 표시하지 않습니다. 요약과 확인 항목은 자유 문장이므로, 버전 선택은 언제나 위 검토 엔진 결과를 기준으로 합니다.
- **CPE 식별 후보**는 활성 승인 NVD 자료에서만 찾습니다. 구성요소 이름에서 `.so`, `.dll`, `.jar` 접미사, 끝의 버전(`-2.14.1` 등), `lib` 접두사를 뗀 이름과 그 단어로 NVD 설명을 최대 4번 검색합니다. 구분자를 뺀 이름이 NVD 제품명과 같으면 `정확`, 한쪽이 다른 쪽을 포함하면 `부분`으로 최대 8개를 고릅니다. 모델은 이 후보의 순위와 근거만 붙이며, 후보 밖의 제품을 제시하면 버립니다. 검색은 설명 문구가 일치하는 NVD 레코드를 검색어마다 최대 2,000건 확인하므로 흔한 이름은 후보가 누락될 수 있습니다. 동시에 두 건까지만 검색하며 그 이상은 잠시 후 다시 시도하라는 응답(HTTP 429)을 받습니다.
- CPE 후보는 분석에 자동 반영되지 않습니다. 확인한 CPE를 원본 CycloneDX 구성요소의 `cpe` 필드에 넣거나 KODA 수집 설정을 고친 뒤 SBOM을 다시 업로드하면 [오프라인 CPE 판정](offline-cpe-ko.md)에 사용됩니다. 버전에 CPE 이스케이프가 필요한 문자가 있으면 버전 자리는 `*`로 둡니다.

API는 화면과 같은 세션·CSRF 검사를 사용합니다.

| 메서드와 경로 | 본문 |
| --- | --- |
| `POST /api/v1/comparisons/ai-briefing` | `baseRunId`, `targetRunId`, 선택 `baseAnalysisId`, `targetAnalysisId` |
| `POST /api/v1/upgrade-batches/{runId}/{batchId}/ai-explanation` | 없음 |
| `POST /api/v1/ai/runs/{runId}/identity-suggestions` | `identityKey` (구성요소 조회 응답의 값) |

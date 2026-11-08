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

1. Tracker가 실행되는 호스트의 운영 env에 모델 주소를 넣습니다. 통합 설치에서는 `<설치 경로>/tracker/.env`를 사용합니다. 예시는 `TRACKER_AI_BASE_URL=https://ai-gateway.internal/v1`입니다. 인증 키를 사용하는 서버에는 HTTPS와 Tracker 컨테이너가 신뢰하는 인증서가 필요합니다.
2. 별도로 생성한 Fernet 암호화 키를 운영 env의 `TRACKER_AI_ENCRYPTION_KEY`에 보관합니다. 이 값은 AI 서버의 API 키와 별개입니다. 안전한 관리 세션에서 `python3 -c 'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())'`로 생성할 수 있습니다. 암호화 키는 보호된 설정과 함께 백업합니다.
3. Compose 기본 구성에서는 Tracker API만 전용 `<Compose 프로젝트명>-ai` 내부 네트워크에 연결됩니다. 같은 호스트에서는 승인된 모델 컨테이너 또는 TLS 프록시를 이 네트워크에 연결합니다. 모델이 다른 서버에 있으면 사내 방화벽으로 모델 주소와 포트만 허용한 프록시를 이 네트워크에 배치합니다. Tracker API 컨테이너에서 지정 호스트가 사설 주소로 해석되어야 합니다. 호스트의 `localhost`와 컨테이너의 `localhost`는 서로 다른 주소입니다.
4. 새 설정을 적용한 Tracker에서 **설정 → 공통 AI**를 엽니다. 서버에서 사용하는 모델 ID와 필요한 API 키를 저장하고 **저장된 설정으로 연결 시험**을 실행합니다. 저장된 API 키는 암호화되며 화면에는 등록 여부만 보입니다. 운영 주소를 변경하면 새 주소의 모델과 API 키를 다시 저장합니다.
5. Tracker는 **SBOM 회차 상세 → 사내 AI로 요약**, KODA는 **점검 결과 상세 → AI 요약 생성**에서 사용합니다. KODA는 기존 `KODA_TRACKER_URL`과 `KODA_TRACKER_PROVISIONING_TOKEN_FILE`로 Tracker를 호출합니다. KODA **관리자 설정 → 연동 설정**에서도 Tracker의 공통 AI 설정을 열 수 있습니다.

모델에 보내는 정보는 Tracker의 심각도별 건수와 최대 25개 CVE ID, KODA의 심각도별 건수와 최대 25개 규칙 ID로 제한합니다. AI 응답은 검토 참고용으로 화면에 표시합니다. 점검 결과나 정책 판정은 원래 분석기가 관리합니다.

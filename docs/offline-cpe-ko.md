# 폐쇄망 CPE 적용 조건 판정

Tracker는 기존 Grype 분석 뒤 CycloneDX 구성요소의 `cpe`에 명시된 CPE 2.3
식별자와 반입 NVD 적용 조건을 대조합니다. 패키지명으로 vendor/product를 추정하지
않습니다. Linux 배포판 패키지는 기존 Grype 결과와 공급업체 패치 판정을 유지합니다.

새 `scripts/nvd-alias-index.py`는 `configurations` 전체, 버전 포함/제외 경계,
AND/OR·negate, `vulnerable=false` 환경 조건과 CWE 근거를 보존합니다.
기존 `cpe` 문자열만 있는 번들은 설명용으로 읽히며 적용 조건을 임의 복원하지 않습니다.
새 번들은 기존 서명·manifest 검증과 반입 경로로 만드세요.

판정은 `koda-offline-cpe-v1`로 기록됩니다. CPE의 escape를 해석하며 정확한 제품을
대조합니다. 버전 범위는 숫자 점 구분 버전만 비교합니다. 벤더별 접미사·배포판
백포트·모호한 버전 비교, 제품 식별자 부족, 미확인 환경은 `unknown`입니다.
SBOM이 환경 전체를 증명한다고 가정하지 않으므로, 없는 환경 조건을 자동으로
거짓으로 간주하거나 negate로 뒤집어 취약성을 확정하지 않습니다.

발견에는 `sourceKind=nvd_cpe`, `cpeEvidence`와 데이터 기준일이 보존됩니다.
같은 CVE·구성요소·버전이 Grype에서 이미 발견되면 기존 수정 버전·심각도를 유지하고
CPE 근거를 추가합니다. 분석 리비전의 `dataSources.cpeApplicability`에 입력 수,
잘못된 CPE 수, 평가/미판정 수, 조건이 없는 과거 데이터 수와 커버리지가 남습니다.
`incomplete`, `unavailable`, `not_evaluated`는 안전 판정이 아닙니다.

공식 기준: [NVD CPE Match Criteria](https://nvd.nist.gov/developers/products),
[CPE 2.3 이름·매칭·적용 언어](https://nvd.nist.gov/general/faq-sections/cpe-faqs).

## 수집 범위와 구성요소별 대조 결과

**SBOM 회차 상세 → 오프라인 CPE 평가 범위**의 **SBOM 수집 범위**에서 KODA 수집기가 보고한
수집 대상, 지정 범위의 완료·부분 수집 상태, 수집 구성요소 수, 제외 디렉터리, 부분 수집 사유를 확인합니다.
CycloneDX와 SPDX 2.3의 KODA 수집 근거 중 형식과 개수 검사를 통과한 항목을 표시합니다.
근거가 없거나 형식이 잘못된 파일은 화면에 각각 미제공 또는 확인 불가로 표시됩니다.

**NVD 구성요소 대조 결과**에는 제출된 구성요소별 CPE 조건의 평가, 판정 보류, 미평가 개수와
사유가 나옵니다. 예를 들어 CPE나 구체 버전이 없으면 미평가이며, 환경 근거가 부족하면 판정을
보류할 수 있습니다. Grype의 PURL 기반 매칭 결과는 취약점 목록에서 확인합니다.

## IBM AIX Oracle Home 근거

KODA AIX 수집기의 CycloneDX 또는 SPDX 2.3에 Oracle 증적이 있으면, 해당 발견의
**Oracle Home 증거**에서 Home ID, 확인된 Release Update, RU 확인에 사용한 패치 ID,
OPatch 인벤토리 패치 ID, 근거 파일과 SHA-256을 확인할 수 있습니다.
같은 제품·버전의 Listener가 여러 Oracle Home에 있어도 Home별 CPE와 조건을 대조하고,
발견 및 VEX 근거를 Home에 연결합니다. Listener의 실행 파일이 관찰됐지만 버전을 확인하지
못하면 해당 Home의 Listener를 미평가로 표시합니다.

OPatch 패치 목록은 설치 인벤토리의 관측값입니다. 개별 CVE의 수정 패치 적용 여부는
**미확인**으로 표시하며, 원본 설치 증적과 Oracle 공지에서 적용 여부를 검토합니다.

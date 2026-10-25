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

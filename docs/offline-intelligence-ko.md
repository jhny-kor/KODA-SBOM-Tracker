# 폐쇄망 취약점 인텔리전스 운영

Tracker는 KODA 저장소와 별도 저장소로 유지합니다. 폐쇄망 분석은 반입한 Grype·NVD·KEV 자료와 선택적인 EPSS를 사용합니다. OSV API는 사용하지 않습니다.

## 외부 호출 경계

`TRACKER_OFFLINE_MODE=true`가 기본값입니다. 공개 패키지 저장소, FIRST EPSS 수집기, Webhook 전송을 실행 전에 차단합니다. 이전의 수집·연동 활성화 설정이 남아 있어도 이 경계를 우선합니다. 로컬 화면·DB·내부 인증은 계속 사용할 수 있습니다. 외부 네트워크를 차단하는 배포 네트워크 정책도 함께 적용하세요. 애플리케이션 경계가 운영체제 방화벽을 대신하지는 않습니다.

연결된 별도 수집 환경을 운영하는 경우에만 `TRACKER_OFFLINE_MODE=false`를 명시적으로 설정합니다. 폐쇄망 서버에서는 인터넷 수집을 켜지 않고 승인된 파일을 반입합니다.

## FIRST EPSS를 통합 반입 파일에 포함

외부 수집 환경에서 FIRST의 [공식 데이터 안내](https://www.first.org/epss/data.html)에 따라 일일 `epss_scores-current.csv.gz` 또는 해당 날짜의 CSV를 준비합니다. EPSS 원본을 Grype·NVD·KEV 및 보강 자료와 함께 `scripts/collect-unified-data.py`로 서명된 통합 `tar.gz` 한 파일로 만듭니다. 준비·수집 명령과 파일 배치는 [통합 취약점 자료 운영](unified-vulnerability-data-ko.md)을 따릅니다.

폐쇄망 홈페이지에서는 **설정 → 취약점 데이터 → 공개 참조 자료**에서 통합 파일을 업로드·검증한 뒤 별도로 적용합니다. EPSS CSV·캐시 JSON·참조 JSON을 따로 올리는 화면은 제공하지 않습니다. 개별 원본은 외부 수집 단계에서 통합 파일의 입력으로 사용합니다.

파일 형식은 FIRST 일일 파일 형식입니다.

```csv
#model_version:v2025.03.14,score_date:2026-10-19T00:00:00+0000
cve,epss,percentile
CVE-2021-44228,0.94,0.99
```

통합 파일 검증 시 EPSS CSV 전체의 형식과 점수 기준일을 확인합니다. 잘못된 행·중복 CVE·범위를 벗어난 점수·미래 날짜·손상된 압축 파일은 검증을 통과하지 못합니다. 파일 SHA-256·모델·기준일은 EPSS 근거로 보존하고, 통합 파일의 반입·적용은 감사 기록에 남깁니다. 파일 해시와 조직의 통합 파일 서명은 공급자 원본의 진위를 대신하지 않으므로 승인된 원본을 확보해야 합니다.

## 과거 점수와 정책 입력

반입 시각이 점수 기준일을 바꾸지 않습니다. 결과의 `epssObservedScore`, `epssObservedPercentile`, `epssObservedDate`와 `epssEvidence`에는 과거 점수를 보존합니다. 현재 정책에 사용할 수 있는 점수만 `epssScore`, `epssPercentile`, `epssDate`에 제공합니다. 오래되거나 미수집인 값을 0점으로 만들지 않습니다.

폐쇄망 정책의 허용 기준일 범위는 `TRACKER_EPSS_POLICY_MAX_AGE_DAYS`로 정하며 기본 7일, 허용 범위 0~365일입니다. `ageDays`, `maxAgeDays`, `policyEligible`를 근거에 기록합니다. 이 설정은 조직의 데이터 반입 주기와 위험 수용 정책에 맞춰 정하세요. 점수를 오래 사용할 수 있도록 설정해도 현재 FIRST 점수라는 보장은 생기지 않습니다. 온라인 수집 모드의 24시간 캐시 만료·최근 기준일 검사와 구분합니다.

반입 후 필요한 회차의 새 분석을 실행하면 새 점수 근거와 정책 결과가 새 분석 리비전에 기록됩니다. 과거 리비전의 정책 판정은 수정하지 않습니다. SSVC의 실제 악용 상태를 EPSS 확률만으로 자동 확정해서는 안 됩니다.

## 여러 공급원 통합 반입

`scripts/collect-offline-intelligence.py`는 외부 수집용 도구입니다. 실행 중인 Tracker가 이 도구를 호출하지 않습니다. 기본 동작은 승인된 로컬 원본 파일 정규화이며, 인터넷 다운로드는 연결망 수집 호스트에서 `--fetch`를 명시했을 때만 수행합니다. OSV는 수집 종류에 포함되지 않습니다.

| kind | 지원 원본과 경계 |
| --- | --- |
| `epss` | FIRST 모델·기준일 헤더를 포함한 일일 CSV 또는 gzip |
| `vulnrichment` | [CISA Vulnrichment](https://github.com/cisagov/vulnrichment)의 CVE5 CISA ADP `ssvc` options. 악용·자동화·기술 영향과 관측 시각·버전을 보존하며 수동 SSVC 결정을 자동 교체하지 않음 |
| `csaf` | [CSAF 2.0/2.1 JSON](https://docs.oasis-open.org/csaf/csaf/v2.1/csaf-v2.1.html). product ID에 연결된 명시적 PURL/CPE와 제품별 CVE 상태·조치 근거. 식별자가 없는 관계·범위는 미확정 |
| `vex` | [OpenVEX v0.2](https://github.com/openvex/spec) 또는 CycloneDX JSON VEX. 명시적 제품 식별자·CVE가 있는 문장. 복잡한 범위·하위 제품의 확장 해석은 지원하지 않으며 승인된 기존 VEX 검토 절차를 대신하지 않음 |
| `ubuntu-oval` | [Ubuntu OVAL](https://ubuntu.com/security/oval) XML, gzip/bzip2. 고정 이름 `dpkginfo_object`·고정 EVR state·AND/OR·negate subset. 변수, 다른 test/object, extend_definition 및 빈 조건은 `supported=false`; 정확한 Ubuntu 릴리스·패키지 인벤토리와 dpkg 비교가 없으면 unknown |
| `lifecycle` | [endoflife.date API v1](https://endoflife.date/docs/api/v1/) 단일 제품 상세 응답. product/cycle/identifiers/EOL/latest와 공급자 `generated_at`을 보존. 구형 `/api/product.json` 배열은 거절 |
| `cpe-dictionary` | NVD CPE API 2.0 `products` 응답 또는 CPE 2.3 dictionary XML. CPE 이름·ID·제목·폐기 상태 |
| `cpe-match` | NVD Match Criteria API 2.0 `matchStrings` 응답. criteria·matchCriteriaId·포함/제외 버전 경계·CPE 목록 |
| `cwe` | CWE Catalog XML의 Weakness. Category/View는 약점으로 가져오지 않음 |
| `spdx` | SPDX license-list-data의 `licenses.json` 및 `exceptions.json`. 라이선스·예외 ID, 폐기 여부·이름을 보존. 법적 호환성 판정은 수행하지 않음 |
| `package-metadata` | 기존 `koda-package-metadata-v1` 내보내기 JSON. PURL·현재 버전과 원래 관측·만료 시각을 보존 |

이 파서는 전체 CSAF/OVAL/CPE 표준 적합성 인증기가 아닙니다. 명시된 subset을 정규화하고 해석하지 못하는 조건은 unknown 근거로 보존합니다. 파일별 원본·정규화 결과 일치를 검증하므로 알 수 없는 조건을 임의로 영향 없음·수정 완료로 변환하지 않습니다.

승인된 로컬 파일의 최소 `spec.json` 예시입니다. `fetchedAt`은 원본을 수집한 실제 시각으로 바꾸세요. 원본에 발행 날짜가 있으면 공급자 날짜를 사용하며 spec에서 다른 날짜로 덮어쓸 수 없습니다. 공급자 날짜가 없는 자료에만 `dataDate`를 함께 지정하고 `dateBasis=operator`로 기록합니다.

```json
{
  "sources": [
    {
      "id": "epss-approved",
      "kind": "epss",
      "path": "epss_scores-current.csv.gz",
      "sourceUrl": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
      "fetchedAt": "2026-10-19T01:00:00Z",
      "maxAgeDays": 7
    },
    {
      "id": "python-lifecycle",
      "kind": "lifecycle",
      "path": "python-v1.json",
      "sourceUrl": "https://endoflife.date/api/v1/products/python/",
      "fetchedAt": "2026-10-19T01:00:00Z",
      "maxAgeDays": 30
    }
  ]
}
```

```bash
python3 scripts/collect-offline-intelligence.py \
  --spec /approved/spec.json --output /approved/normalized
```

출력 디렉터리는 새 경로여야 합니다. `intelligence.json`에는 `format=koda-offline-intelligence-v1`, `datasets[kind].sources/records`를 기록하며, 원본은 `intelligence-sources/<SHA-256>.bin`으로 보존합니다. sources에는 URL·실제 수집 시각·공급자 기준일·스키마·파일 크기·원본 해시·행 수·허용 기간을 기록합니다. EPSS에는 모델도 기록합니다. 원본 전체를 다시 파싱한 결과와 정규화 행이 다르면 검증·반입을 거절합니다.

관리자 JSON 반입용 파일은 `--inline`을 추가해 생성합니다. 이때 sources에 `rawBase64` 원본을 포함합니다. 원본 없이 만들어진 정규화 JSON만으로 공개 악용 사실이나 공급자 영향 없음 선언을 반입할 수 없습니다. 서버는 원본 해시·크기와 정규화 행의 재생성 결과를 검사합니다. 원본 해시 검증은 공급자 서명 인증이 아니므로 출처를 승인하는 반입 절차가 필요합니다.

연결망에서 직접 수집할 spec은 `path` 대신 `url`을 사용하고 `--fetch`를 명시합니다. 기본 허용 호스트는 CISA/CVE·SPDX의 승인된 raw GitHub 경로, FIRST, NVD, Canonical, CWE, endoflife.date입니다. 다른 공급자는 `--allow-host security.vendor.example`처럼 운영자가 공개 HTTPS 호스트를 명시해야 합니다. 인증정보가 들어간 URL·프록시 환경 사용은 차단하며, 리다이렉트는 각 대상의 HTTPS·허용 호스트를 검사해 최대 5회만 허용하고 경로를 기록합니다. 인증이 필요한 공급원은 승인된 외부 도구로 확보한 뒤 로컬 파일로 정규화하세요.

NVD CPE API의 여러 페이지는 해당 source에 `"paginate": true, "maxPages": 10`을 지정합니다. 페이지 사이 6.5초 간격을 두며 모든 페이지 원본과 실제 URL을 보존합니다. 허용 페이지 수 안에 끝나지 않으면 결과를 게시하지 않습니다. 제품·CVE로 범위를 좁힌 API 조회에 사용하세요. 원본 한 파일/압축 해제 128MiB, 전체 원본 512MiB, 최대 4,096개 공급원·총 100만 행으로 제한합니다. 이 범위를 넘는 전체 CPE Match 대형 덤프는 지원하지 않습니다. 작은 제품별 반입 묶음으로 나누세요.

## 기존 취약점 데이터 번들에 포함

기존 Grype/NVD/KEV 번들에 선택적 파일을 추가할 수 있습니다.

```bash
bash scripts/build-vuln-bundle.sh /delivery/vuln-bundle \
  --grype-db /approved/grype-db --data-date 2026-10-19 \
  --nvd-index /approved/nvd.json --kev /approved/kev.json \
  --epss /approved/epss_scores-current.csv.gz \
  --intelligence-index /approved/normalized/intelligence.json
```

`EPSS_SNAPSHOT`·`INTELLIGENCE_INDEX`와 각각의 해시를 metadata.env에 추가하고 정규화 원본도 기존 manifest에 포함합니다. 기존 릴리스 서명·독립 공개키·반입 검증 절차는 유지하세요. 추가 데이터 때문에 무서명 허용을 자동 활성화하지 않습니다.

독립 `vuln-data` 갱신 패키지는 기존 `scripts/build-data-update.py`를 사용합니다. source 디렉터리의 `nvd.json`·`kev.json`과 선택적 `epss.csv`/`epss.csv.gz`, `intelligence.json`·`intelligence-sources/`를 함께 패키징합니다. 원본 없이 index만 복사하면 검증에서 중단됩니다. 검증된 새 복합 릴리스로 전환할 때 모든 파일이 함께 이동하며 롤백도 같은 원본·기준일·해시를 복원합니다. 선택적 자료가 없는 새 취약점 데이터로 교체하면 이전 자료·메타데이터도 제거하므로 오래된 자료를 새 데이터처럼 이어받지 않습니다.


## 통합 참조 자료와 영향·대응 화면

**설정 → 취약점 데이터 → 공개 참조 자료**에서 서명된 통합 `tar.gz`를 검증·적용합니다. `collect-offline-intelligence.py`가 만든 정규화 JSON과 원본 sidecar는 외부 수집 단계의 자료이며, 최종 통합 파일에 포함해 반입합니다. 파일명만 바꾸거나 정규화 레코드만 직접 편집한 자료는 원본 대조에서 거부됩니다.

**자료 현황·영향** 하위 탭에서는 실제 소스별 기준일·유효기간·상태·원본 SHA-256, 변경 불가 반입 이력과 검증 원본 다운로드, 서비스·환경·릴리스별 영향·대응 현황을 확인합니다. **패키지 버전·출시일 관측 현황 (고급)**을 펼치면 기존 캐시의 관측 상태·유효기간과 버전 정보를 확인할 수 있습니다. 이 화면의 조회·관리 권한은 기존 메타데이터 권한을 유지합니다.

공개 참조 자료 화면의 **자료 종류별 입력 예시**는 형식과 활용을 설명하는 가상 샘플입니다. 실제 반입 상태와 점검결과는 위 현황 화면과 각 회차의 분석 리비전에서 확인합니다. 반입한 자료를 새 분석에서 사용해도 원본 SBOM과 과거 분석 근거는 보존합니다. 적용·삭제와 보존 범위는 [통합 취약점 자료 운영](unified-vulnerability-data-ko.md)을 확인하세요.

지원하는 자료 종류는 EPSS, CISA Vulnrichment, CSAF, OpenVEX/CycloneDX VEX, Ubuntu OVAL, 수명주기, CPE 사전·match 문자열, CWE, SPDX 라이선스 사전, 패키지 메타데이터입니다. 원본 소스의 기준일과 수집일은 구분합니다. 수명주기는 명시한 PURL 또는 CPE와 cycle이 일치하는 경우만 연결합니다. 최신 버전 정보는 정확한 PURL/버전과 일치하고 소스가 신선하며 값이 합의된 경우에만 정책 입력으로 보완합니다. 소스의 주간 유효기간은 기존 온라인 캐시의 24시간 만료와 별도입니다.

점검 상세에는 구성요소 수명주기·라이선스·CPE·패키지 근거와 취약점별 공급자 VEX 충돌, CWE 설명, SSVC 추천 입력을 표시합니다. 신선한 Vulnrichment의 exploitation/automatable과 KEV를 참고하며 시스템 노출·업무 영향은 담당자가 입력합니다. 자료가 없거나 만료된 경우 악용 없음이나 Defer로 추정하지 않습니다. 공급자 VEX는 기존 Grype/CPE 탐지를 자동 억제하지 않고 심각도를 변경하지 않습니다. 분석 당시 matched evidence와 source manifest를 저장하고 현재 자료가 다른 경우 과거 근거임을 표시합니다. SSVC 판단은 append-only 이력이며 반입으로 재분석 대기 또는 근거 변경 시 재평가가 필요합니다.

대응 기록은 점검·정확한 구성요소 버전·canonical 취약점에 묶고 담당자와 근거를 필수로 저장합니다. 위험 수용에는 미래 재검토 기한이 필요합니다. `mitigated`는 담당자의 조치 기록이며 해결 검증을 뜻하지 않습니다. 해결 검증은 새 점검으로 수행합니다. 현황 집계는 보관되지 않은 릴리스별 최신 점검을 사용하고 현재 페이지의 상태별 탐지 건수와 기한 경과를 표시합니다. 전체 릴리스 수와 반환 범위를 표시하고 이전·다음 페이지로 전체를 조회합니다. 분석 리비전이 바뀌거나 기한이 경과한 기존 기록은 review_required로 집계합니다. 대응 상태는 이 점검에 국한되며 새 점검으로 자동 복사하지 않습니다.

### Ubuntu OVAL의 제한

범용 OVAL 엔진은 포함하지 않습니다. exact Ubuntu 플랫폼과 `pkg:deb/ubuntu/...?...distro=ubuntu-22.04` 형태의 패키지 목록이 있고, 파서가 지원하는 dpkginfo test·state·AND/OR 조건인 경우에만 로컬 `dpkg --compare-versions`로 review-only 평가합니다. dpkg가 없는 macOS, 미지원 release/criteria/test/state, 불완전한 패키지 목록, 제한 초과는 `unknown`입니다. 공식 Ubuntu 파일에는 미지원 조건이 포함될 수 있으므로 이 결과를 Ubuntu 전체 취약점 점검 완료로 해석하지 않습니다. 결과는 `affected_review`, `not_affected_review`, `unknown`이며 기존 탐지 판정에 반영하지 않습니다.

# KODA 자체 운영과 외부 플랫폼의 남은 차이

2026-10-18의 코드와 격리 Docker 검증 기준입니다. **KODA의 주요 SBOM·Grype·정책·VEX 흐름을
자체 처리하는 것과 Dependency-Track 제품 전체를 대체하는 것은 다릅니다. 미구현 기능은 남아 있습니다.**
대부분은 예전 KODA의 자체 입력 화면이 아니라 외부 시스템 열기 링크에서 사용하던 기능입니다.
부모 Collection 집계와 사내 취약점 작성·관리는 자체 구현을 추가했습니다.
구체적인 집계 단위와 영향 버전 지원 범위는 [추가 검증 기록](verification-collection-private-20261018-ko.md)을 따릅니다.

## 미구현 기능

| 기능 | 현재 KODA 범위 | 확인 근거 |
| --- | --- | --- |
| 추가 취약점 분석기·계정 직접 연동 | Grype 실행, 반입한 NVD/KEV, FIRST EPSS 제공. OSS Index·Snyk·Trivy·VulnDB의 별도 분석기 설정/실행은 없음 | [분석 서비스](../apps/api/koda_tracker/services.py). Grype DB에 들어 있는 공급원 데이터와 직접 분석기 연동은 구분 |
| 사설·인증 저장소와 추가 생태계 자동 수집 | 공개 npm·PyPI·Maven·NuGet·Go·Cargo와 오프라인 캐시 반입 제공. 사설 Artifactory/Nexus 계정, Composer·RubyGems·Hex·CPAN 수집기 없음 | [수집기와 허용 공급원](../apps/api/koda_tracker/package_metadata.py) |
| Email·Slack·Teams·Mattermost·Jira 전용 알림 전송기·템플릿 | 보관함·서명 Webhook·재시도 제공. 외부 중계는 가능하지만 내장 전송기는 없음 | [알림 전송](../apps/api/koda_tracker/workflows.py)·[설정](../apps/api/koda_tracker/config.py) |
| OIDC SSO·팀별 프로젝트 ACL·팀 단위 API 키 | 로컬/LDAP, 역할 권한과 서비스 범위 API 토큰 제공 | [인증 API](../apps/api/koda_tracker/main.py)·[계정 모델](../apps/api/koda_tracker/models.py). 조직 팀/프로젝트 ACL 모델·OIDC 콜백 없음 |
| 포트폴리오 전역 고유 구성요소/CVE 영향·일괄 감사·의존성 그래프 화면 | 회차 검색·회차별 발견/정책·범위 있는 VEX 재사용 제공. 의존성 데이터는 정책에 사용하지만 그래프 화면 없음 | [화면](../apps/web/src/App.tsx), [정책](../apps/api/koda_tracker/policies.py), [VEX](../apps/api/koda_tracker/workflows.py) |
| 새 KODA 분석의 VDR·FPF 표준 내보내기 | 원본 SBOM·CycloneDX VEX·감사 CSV 제공. FPF는 이관 입력으로 읽지만 새 결과 exporter 없음 | [이관 입력](../apps/api/koda_tracker/migration.py), [내보내기](../apps/api/koda_tracker/workflows.py) |
| DefectDojo·Fortify SSC·ThreadFix·Kenna 전용 결과 발행 | 일반 Webhook/API로 외부 중계 가능. 제품별 발행 모듈·설정은 없음 | [알림 채널 구현](../apps/api/koda_tracker/workflows.py) |

## 부분 지원·이관 범위 제한

| 항목 | 경계 |
| --- | --- |
| 이관 대상 | 프로젝트·SBOM·발견·분석·검토·위반·정책·라이선스/그룹 중심. 새 사내 DB 작성·관리는 자체 기능이며 원본의 사내 취약점 작성 DB 전체 자동이관은 별도. 사용자·팀·ACL·알림 설정·분석기 자격증명·사설 저장소 설정의 전체 DB 자동이관은 아님 |
| 분석 공급원과 결과 | Grype와 다른 분석기/DB의 CVE 집합·심각도·수정 제안은 다를 수 있음. 같은 기준일의 건수만으로 동등성을 판단하지 않음 |
| 비CVE advisory 표시 | 사내 DB에서 게시한 내부 ID는 회차 발견·정책·VEX·Collection 집계에 포함. 그 밖의 공개 공급원 결과는 CVE 또는 CVE alias 중심이며 모든 비CVE advisory의 포트폴리오 전역 검색은 제공하지 않음 ([표시 projection](../apps/api/koda_tracker/vulnerability.py)) |
| 정책 위반 표시 단위 | KODA 결과는 정책·구성요소·버전·선택적 취약점 기준으로 중복 제거. 원본의 조건별 위반 행 수와 같지 않을 수 있음. 구버전 ALL 판정은 원시 개수 의미를 보존하되 원본 조건 행은 이관 증거로 보관 |
| 출시일·버전 거리 | Maven 색인 시각·Go 리비전 생성 시각을 구분. 공급원이 제공하지 않는 최초 공개일이나 사설 버전 목록을 임의 생성하지 않음 |
| 풍부한 CycloneDX 구조 | 원본 파일 보존. XML CPE·SWID는 이번에 정규화 보완. JSON/XML 중첩 구성요소의 목록·지표·정책·할당량 정규화는 추가 검증에서 보완. services·일부 풍부한 메타데이터의 전체 정규화/전용 화면은 제한됨 |
| 비정상 원본 조건 | 원본에서 null 버전/조건 때문에 예외가 발생하는 구성은 명시적 차단·실패로 처리. 버전별로 등록되지 않은 조건은 임의 재해석하지 않음 |

## 구현 여부와 다른 검증 경계

실제 조직 LDAP 서버, Windows 설치, 폐쇄망 복원, 운영 자료 전체 이관, 대규모 부하·보존 기간은
이번 샘플 Docker 검증 범위 밖입니다. 이들은 코드 미구현과 구분해 대상 환경에서 검증해야 합니다.

주요 자체 흐름의 구현·검증은 [기능 표](feature-coverage-ko.md),
[고급 기능](verification-complete-20261018-ko.md), [Java 정규식](verification-java-regex-20261018-ko.md),
[구버전 리터럴](verification-literal-20261018-ko.md)을 참조합니다.

원본 제품 비교 기준은 공식 [Collection Projects](https://docs.dependencytrack.org/usage/collection-projects/),
[Notifications](https://docs.dependencytrack.org/integrations/notifications/),
[Repositories](https://docs.dependencytrack.org/datasources/repositories/),
[File Formats](https://docs.dependencytrack.org/integrations/file-formats/),
[전체 기능 목록](https://docs.dependencytrack.org/)입니다. 원본의 모든 플러그인·향후 버전까지
완전한 동등성이 검증됐다고 주장하지 않습니다.

2026-10-18 추가 정확성 점검에서 발견한 중첩·npm scope·Collection 원본 모호함·NuGet 문제는
[수정 및 Docker 검증](verification-sbom-corrections-20261018-ko.md)에 정리했습니다. 이 수정이
위 미구현 기능 전체를 구현했다는 의미는 아닙니다.

SBOM 품질 진단·프로젝트별 기준·CEL 연계·CI 게이트는 [사용 안내](sbom-quality-ko.md)와 [추가 실제 검증](verification-quality-20261018-ko.md)에 정리했습니다. 품질 점수·부모/태그 기준 상속은 [후속 구현·검증](verification-quality-inheritance-20261018-ko.md)에 반영했습니다. 외부 CI 보호 규칙 자동 설정은 포함하지 않습니다.

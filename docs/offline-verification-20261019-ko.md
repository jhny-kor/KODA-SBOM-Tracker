# SSVC·CPE·EPSS 폐쇄망 검증 — 2026-10-19

현재 소스를 Linux amd64 Python 3.12 검증 컨테이너에 읽기 전용으로 연결하고
`--network none`으로 실행했습니다. KODA 저장소는 별도로 유지했습니다.

| 검증 | 결과 |
| --- | --- |
| backend 전체 | 713 passed, 22 skipped |
| 최종 SSVC·CPE·EPSS·차단 경로 | Linux 37 passed, 1 skipped / 호스트 38 passed |
| 프런트엔드 전체 | 116 passed |
| TypeScript·Vite production build | 통과 |
| ESLint | 오류 없음, 기존 App.tsx onSync 의존성 경고 1개 |
| API wheel | 생성 성공, SSVC 결정표·출처·라이선스·CPE/EPSS 모듈 포함 |
| 두 gateway Nginx 구문 검사 | 네트워크 차단 상태에서 모두 통과 |
| Compose 격리·제외 계약 | 호스트 Docker Compose config 검증 통과 |
| Python 컴파일·shell 구문·diff 공백·새 문서 링크 | 통과 |

전체 backend의 생략 22개는 JDK 컴파일러 필요 19개, 컨테이너 내부 Docker Compose CLI
필요 2개, PowerShell 필요 1개입니다. 별도 컴파일이 필요 없는 Java 정규식 정책 회귀는
기존 Linux Java 런타임과 컴파일 matcher로 검증했습니다.

기능 검증에는 공식 SSVC 72개 조합, 인증·권한·CSRF·감사·이력·재평가, 비PURL 구성요소,
CPE 논리 조건·버전 경계·복잡도 제한·불완전 커버리지, 10,005건 EPSS 실제 multipart 반입과
배치 갱신, 중복·손상·날짜·압축 제한·원자성·정책 최신성, 기존 외부 호출 설정이 남아도
차단되는지 확인하는 테스트가 포함됩니다.

운영 안내: [SSVC](ssvc-offline-ko.md), [CPE](offline-cpe-ko.md),
[EPSS 반입과 외부 호출 차단](offline-intelligence-ko.md).

기존 미커밋 변경은 보존했습니다. 운영 데이터·서버는 변경하지 않았으며 최종 Linux
묶음 재생성·실제 LDAP/GitLab·운영 SBOM 규모의 적용 검증은 별도입니다. OSV 직접 조회를 사용하지 않습니다.

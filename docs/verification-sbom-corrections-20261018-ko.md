# SBOM 정확성 오류 3건·NuGet 수집 제한 수정 검증

2026-10-18 격리 Docker 샘플 검증입니다. Dependency-Track 없이 기존 8개 자체 서비스를
사용하며 실제 Grype 0.109.1 / 2026-10-10 DB 분석과 실제 공개 NuGet API를 사용했습니다.

## 수정과 재현

| 대상 | 수정 전 재현 | 수정 후 동작 |
| --- | --- | --- |
| 중첩 JSON/XML | MIT 부모·GPL 자식 2개를 1개로 집계, 자식 라이선스 위반 누락. XML 자식은 정규화에서 소실 | 공통 반복 순회로 자식 포함. 목록·지표·정책·메타데이터 접수·할당량에 동일한 범위 사용 |
| npm scope | `@angular/core`, `@types/node`가 모두 `purl:pkg:npm/`으로 변환 | 디코딩 전에 마지막 경로 뒤의 버전 구분자 제거. scope/패키지 보존, 교체는 삭제+추가, 같은 패키지 버전 변경은 변경으로 구분 |
| Collection 원본 모호함 | 다른 원본에 같은 좌표가 있어도 미연결 회차를 자동 합산하고 완료 표시 | 전체 카탈로그에서 유일성을 확인. 모호하면 합산 제외·`ambiguous`·불완전 커버리지. 명시적 회차 연결 우선, 다른 소유자 회차 제외 |
| NuGet | 구형 SemVer1 등록 주소·8페이지 제한 | 서비스 인덱스의 SemVer2 등록 API 3.6 발견, 모든 페이지 처리. 실패·안전 한도 초과에 부분 성공 금지 |

수정 전 중첩/npm 회귀 5건, Collection 신규 4건, NuGet 신규 9건의 실패를 확인한 뒤
구현을 수정했습니다. 추가 경계·깊은 순회·대소문자·버전/qualifier·영구 실패 캐시·
동시 작업·과거 분석 보존·복구 중 실패 원자성에 대한 회귀 사례도 포함합니다.

## 실제 업그레이드 검증

이전 Docker 이미지에 JSON/XML 중첩 SBOM과 서로 다른 scoped npm 패키지 회차를
먼저 넣었습니다. 원래 JSON/XML의 구성요소 수는 각각 1개였습니다. 새 이미지를
기존 PostgreSQL 볼륨에 적용한 뒤 기존 자료의 정규화·새 분석을 검증했습니다.

| 실제 확인 | 결과 |
| --- | --- |
| 기존 JSON/XML 복구 | 각각 구성요소 2개, GPL 자식의 금지 라이선스 정책 위반 생성 |
| 원본·과거 증거 | 원본 다운로드 SHA-256 동일, 기존 분석 문서 전체 동일. 새 계산은 새 분석 리비전에 기록 |
| scoped npm 회차 비교 | Angular 패키지에서 types 패키지로 교체하면 추가 1·삭제 1, 단순 버전 변경으로 오인하지 않음 |
| 교차 원본 Collection | 모호한 회차는 구성요소 0건·모호함 1건·불완전. 연결 지정 후 선택된 Collection만 구성요소 1건 |
| NuGet Serilog 2.0.0 | 실제 10페이지·601버전 수집. 관측 최신 정식 4.4.0, 현재 버전 공개일 수집 |
| NuGet Microsoft.Extensions.DependencyInjection 11.0.0-rc.2.26504.105 | SemVer2 prerelease 공개일 2026-10-13 조회. 최신 선택은 정식 10.0.13으로 유지, 3페이지·181버전 |
| 구형 영구 실패 캐시 | 이전 이미지의 Serilog 캐시에 8페이지 초과 실패·3회 소진 상태를 만들어 둠. 업그레이드 후 재접수·실수집 성공 |
| 기존 자료 일괄 보정 | 초기 일괄 실행 50회차 처리·15회차 변경·재분석 15건 접수·실패 0. 일반 worker의 순차 보정과 병행 |

신규 SBOM만 고친 결과가 아닙니다. XML은 원본 해시 확인 후 복구하고 기존 파생 행을
재생성합니다. 보관 회차는 목록만 보정하며 재분석하지 않습니다. 과거 리비전은 당시
계산 증거로 유지합니다. 복구 중 실패는 savepoint로 롤백해 기존 구성요소가 사라지지
않으며 실패 상태·감사 기록을 남깁니다. 반복 실행은 정규화 버전과 완료 표식으로 건너뜁니다.

전용 Docker 검증 스크립트의 **15개 항목이 통과**했습니다. NuGet 최신 버전과 전체 건수는
그 시점의 실제 API 관측이며 이후 공급원 갱신에 따라 바뀔 수 있습니다.

```bash
# 이전 버전의 격리 테스트 스택에서 샘플 준비
python3 scripts/verify-sbom-corrections-runtime.py seed \
  --env-file runtime/native-verification-20261017/.env \
  --output-dir output/sbom-corrections-20261018
# 새 이미지 적용 후
python3 -m koda_tracker.sbom_normalization --limit 1000  # 컨테이너 안에서 실행
python3 scripts/verify-sbom-corrections-runtime.py verify \
  --env-file runtime/native-verification-20261017/.env \
  --output-dir output/sbom-corrections-20261018
```

샘플 seed 단계는 해당 서비스에만 적용되는 GPL 정책을 추가합니다. verify는 종료 시 원래
정책을 새 버전으로 복원합니다. 운영 자료에 실행하지 말고 격리된 검증 스택을 사용합니다.
보고서는 `output/sbom-corrections-20261018/runtime-report.json`,
`normalization-upgrade.json`에 보관하며 자격증명·테스트 결과는 Git에 포함하지 않습니다.

## 회귀·기존 흐름·화면 확인

전체 백엔드 **628개**, 웹 **84개** 테스트가 통과했습니다. Docker 웹 빌드(typecheck 포함)와
lint 오류 0건을 확인했습니다. 기존 `App.tsx`의 `onSync` 의존성 경고 1건은 남아 있습니다.

Chrome/Playwright로 실제 gateway 화면의 Collection 소유 모호함·불완전 커버리지 표시를
1440×1000 / 390×844에서 확인하고, 중첩 회차 상세에서 자식 GPL 구성요소와 구성요소 2개·
정책 위반 1건을 확인했습니다. 화면 흐름 3개 통과, 페이지/콘솔 오류 및 예상치 않은 HTTP
오류 0건, 문서 가로 넘침 없음입니다. Browser 플러그인이 없어 설치된 Playwright를 사용했습니다.
증거는 로컬 `/tmp/koda-sbom-corrections-ui-report.json`과 해당 스크린샷에 보관했습니다.

정규화 명령 재실행은 처리·변경·접수·실패 모두 0건으로 반복 작업이 없음을 확인했습니다.

최종 이미지에서 기존 native 통합 검증도 **34개 항목 통과**했습니다. 실제 Grype DB 분석,
정책·예외, 과거 스냅샷, 회차 비교, 권한·서비스 토큰, 감사 CSV, 보관 회차의 재분석 거부를
확인했습니다. 결과는 `output/sbom-corrections-20261018/native/runtime-report.json`에 보관했습니다.

전체 Docker 서비스 8개를 재시작한 뒤 기동 완료를 확인했습니다. 다시 API로 JSON/XML의
구성요소 2개, 원본 SHA-256·과거 분석 보존, Collection의 모호함 1건·불완전 표시,
Dependency-Track 비활성 상태가 유지됨을 확인했습니다. 정규화 재실행도 모두 0건입니다.
재시작 증거는 `output/sbom-corrections-20261018/restart-proof.json`에 보관했습니다.

## 한계와 후속 제안

NuGet 안전 한도(4,096페이지·100,000레코드·응답 크기·시간)는 남으며 초과 시 명시적 실패로
처리합니다. prerelease의 자료 수집과 최신 정식 선택은 구분합니다. 사설 NuGet 저장소
인증이나 다른 추가 생태계 수집을 이번에 구현한 것은 아닙니다.
기존 오프라인 반입 캐시는 유지하므로 연결된 환경에서 새 수집기로 생성해 재반입해야 합니다.

원본 누락·해시 불일치·구조 오류는 복구를 중단합니다. 과거 잘못된 분석을 덮어써 숨기지
않습니다. 유지보수 실행·실패 재시도 절차는 [운영 가이드](operations-ko.md#sbom-정규화-보정과-nuget-수집기-업그레이드)를 따릅니다.
대규모 운영 부하·실제 LDAP·Windows 설치·폐쇄망 전체 복원은 이번 검증 범위 밖입니다.

품질 진단은 아직 구현 전이며 [설계 제안](sbom-quality-proposal-ko.md)에 단계별로 정리했습니다.
전체 미구현 기능은 [별도 표](native-parity-audit-ko.md)에 유지합니다.

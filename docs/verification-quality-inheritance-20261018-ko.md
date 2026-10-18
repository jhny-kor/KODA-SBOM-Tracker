# 가중 품질 점수와 부모·태그 상속 검증 — 2026-10-18

## 적용 내용

기존 품질 진단에 영역별 가중 점수와 선택적 최소 점수를 추가했습니다. 프로젝트 직접 기준,
현재 태그, 부모 직접/태그, 공통 기준 순서로 프로필을 선택합니다. 평가 당시 기준·상속 경로·
영역별 분자/분모·가중치·기여도·엔진 버전을 리비전에 보존합니다. 과거 점수를 덮어쓰지 않습니다.
전체 공식 품질 인증이나 외부 플랫폼 제품 전체와의 동등성을 주장하는 기능은 아닙니다.

## 실제 Docker 인수

환경은 Mac의 격리 Compose `koda-native-verify-20261017`, gateway `http://127.0.0.1:18088`입니다.
API·worker·web을 새 이미지로 실행했으며 Dependency-Track은 비활성입니다.
실제 Grype 실행 파일·기존 반입 DB·CEL 런타임·PostgreSQL·CI 명령을 사용했습니다.

`scripts/verify-quality-inheritance-runtime.py`의 **24개 항목이 통과**했습니다.

| 사례 | 실제 관측 |
| --- | --- |
| 부모 직접 기준 | 자식 SBOM에 부모의 최소 95점 기준 적용 |
| 기본 점수 | 구성요소 해시만 없는 샘플은 90점. 영역별 분자/분모와 무결성 기여도 0 제공 |
| CI 점수 차단 | 90점 < 최소 95점으로 `quality_score_below_minimum` |
| 부모 태그 | 부모의 직접 기준 해제 후 부모 태그 기준이 자식에게 상속 |
| 자식 태그 | 카탈로그 태그 수정 후 자동 재분석·자식 태그 기준 우선 적용 |
| 태그 충돌 | 같은 우선순위의 2개 규칙은 진단 실패·점수 null·CI 차단 |
| 우선순위 조정 | 높은 숫자의 규칙을 선택하고 자동 재분석으로 정상 복구 |
| 직접 설정 | 자식의 직접 기준이 자식 태그·부모보다 우선 |
| 가중치 변경 | 무결성 가중치를 0으로 옮기면 같은 샘플이 100점. 누락 이슈는 보존 |
| 필수 오류 | 관계 가중치 0·큰 오류 허용치·100점이어도 끊어진 참조는 fail·CI 차단 |
| 증거 보존 | 최초 90점과 부모 기준 리비전 전체 JSON을 그대로 재조회 |
| 범위·목록 | 다른 원본의 같은 태그가 침범하지 않으며 태그 목록은 원본별·최신 버전별 페이지 조회 |
| 동시 변경 | PostgreSQL 트랜잭션 잠금을 실제로 잡은 동안 프로필/태그 변경 HTTP 요청 모두 대기. 해제 후 최종 기준으로 자동 재분석 수렴 |
| CEL | 실제 미리보기에서 전체 점수와 영역 점수 조건 일치 |
| 완전한 다음 회차 | 100점, 직전 회차의 실제 점수와 비교한 개선량 기록 |
| 실제 CI 실행기 | 자격 충족 샘플 종료 0, 구조 오류 샘플 종료 1 |

```bash
python3 scripts/verify-quality-inheritance-runtime.py \
  --env-file runtime/native-verification-20261017/.env \
  --output-dir output/quality-inheritance-20261018/final
```

스크립트는 격리 테스트 스택에서 실행합니다. 샘플 프로젝트/태그/품질 기준을 만들고,
사용한 임시 CI 토큰은 폐기합니다. 최종 결과는 로컬
`output/quality-inheritance-20261018/final/runtime-report.json`에 보관했습니다.
자격증명과 실행 출력은 Git에 포함하지 않습니다.

## 기존 기능과 추가 오류 점검

전체 백엔드 **698개**, 웹 **103개** 테스트가 통과했습니다. Docker 웹 build/typecheck,
Python 구문 검사와 diff 검사를 통과했습니다. lint 오류 0건이며 기존 App의 `onSync`
의존성 경고 1건과 의존 라이브러리 deprecation 경고는 남아 있습니다.

기존 품질 Docker 검증 **18개**도 재통과했습니다. JSON/XML 점수·요약 일치, 중첩 경로,
기준 변경·과거 증거·CSV/JSON·CEL·CI를 재확인했습니다.
기존 native 통합 **34개**도 재통과했습니다. 실제 취약 패키지의 Grype 발견, 정책·예외,
과거 분석, 비교·검색·감사 CSV·권한·서비스 토큰·보관 흐름을 확인했습니다.
결과는 `quality-regression/runtime-report.json`, `native/runtime-report.json`에 보관했습니다.

| 추가로 발견·수정한 사례 | 조치 |
| --- | --- |
| 반복 의존성 행이나 여러 이슈로 점수 왜곡 | 참조·감점 단위를 중복 제거 |
| 비활성 카탈로그가 모든 기존 품질 진단을 실패시킴 | 카탈로그 활성 여부와 SBOM 보관을 분리 |
| 부모·자식/태그 동시 변경이 최종 재분석을 놓칠 수 있음 | PostgreSQL 공통 트랜잭션 잠금으로 변경과 접수 순서 직렬화 |
| 긴 상속 경로가 CEL 구성요소 활성화마다 복제됨 | 전체 근거는 분석에 보관하고 CEL에는 스칼라·영역 점수와 축약 기준 전달 |
| 상속 기준 편집 시 부모를 잘못 수정할 수 있음 | 회차 소유 자식 ID와 적용 기준 제공자 ID 분리 |
| 콜론 포함 원본/태그 편집 대상 충돌 | 문자열 연결 대신 구조화한 범위 키 사용 |

## 실제 화면

Chrome/Playwright로 회차 상세 → 점수·영역 기여도 → 과거 부모 기준 → 자식 상속 전환 →
태그 우선순위·최소 점수 저장 → 구조 오류 차단 표시를 확인했습니다. Browser 플러그인이
없어 설치된 Playwright를 사용했습니다. 1440×1000과 390×844에서 **9개 흐름 통과**,
페이지·콘솔 오류 및 예상하지 않은 HTTP 오류 0건, 모바일 문서 가로 넘침 없음입니다.
페이지 URL·KODA 제목·비어 있지 않은 내용·오류 오버레이 없음도 확인했습니다.
가중치 합계 99일 때 저장이 막히고 100으로 복구하면 저장되는 실제 조작을 포함합니다.
로컬 `/tmp/koda-quality-weights-ui-report.json`과 스크린샷에 증거를 보관했습니다.

## 재시작·소스 대조·Docker 정리

최종 API와 worker의 7개 변경 모듈 SHA-256이 작업 소스와 일치했습니다.
전체 Docker 서비스 8개를 재시작한 뒤 90점·100점·구조 오류 샘플의 품질 리비전 전체 JSON,
현재 상속 기준과 CI 응답을 재시작 전후로 비교했습니다. 전부 동일했고 점수 자격 충족은
통과, 구조 오류는 차단을 유지했습니다. 증거는 로컬 `restart-before.json`, `restart-proof.json`,
`deployed-source-sha256.json`입니다.

검증이 끝난 뒤 요청대로 다음 순서로 정리했습니다.

1. 검증 Compose 컨테이너 전체 중지, 실행 중 컨테이너 0개 확인
2. `docker builder prune -af`로 빌드 캐시 삭제: Docker 보고값 **8.515GB** 회수
3. `docker system df`에서 빌드 캐시 **0건·0B** 확인
4. `docker desktop stop --timeout 60` 성공 후 daemon 접속 불가·Desktop/backend 프로세스 없음 확인

이미지와 데이터 볼륨은 삭제하지 않았습니다. 정리 증거는 로컬
`output/quality-inheritance-20261018/docker-cleanup.json`에 보관했습니다.

## 운영 경계

최소 점수와 가중치로 공식 인증·실제 패키지 무결성·라이선스 법률상 호환성을 보증하지
않습니다. 상속은 프로필 전체 선택이며 필드별 혼합 상속은 아닙니다. 구형 엔진의 미산정
결과는 보존하고 새 분석에서 점수를 계산합니다. CI는 구형 엔진·구형 기준·불일치 근거를
차단하므로 업그레이드 뒤 사용 회차는 재분석해야 합니다.
실제 조직 CI 보호 규칙·LDAP·Windows 설치·폐쇄망 전체 복원·대규모 부하는 검증 범위 밖입니다.
[운영 안내](sbom-quality-ko.md)를 참고하세요.


## GitLab 보안 검사 대응과 재검증

가중 점수 구현 커밋의 최초 GitLab push는 서버 pre-receive 보안 검사에서 거부됐습니다.
기존 잠금 파일의 취약 의존성이 원인이었으며, 검사를 우회하지 않고 다음과 같이 갱신했습니다.

| 패키지 | 이전 | 갱신 |
| --- | --- | --- |
| cryptography | 45.0.6 | 50.0.2 |
| python-multipart | 0.0.20 | 0.0.32 |
| FastAPI | 0.116.1 | 0.135.4 |
| Starlette(전이) | 0.47.3 | 1.8.0 |
| pytest(테스트) | 8.4.1 | 9.0.3 |
| brace-expansion(웹 전이) | 1.1.18 / 2.1.4 | 1.1.21 / 2.1.7 |
| source-map-js(웹 전이) | 1.2.1 | 1.2.2 |

Python 전체 잠금 패키지는 `pip-audit` PyPI·OSV 양쪽에서 각각 44개·취약점 0건,
웹은 `npm audit` 취약점 0건입니다. 이전 Python 감사의 39개 advisory 결과는 중복 식별자를
포함하므로 고유 취약점 39개를 뜻하지 않습니다. 감사 결과는 조회 시점에 한정됩니다.
[cryptography 배포 정보](https://pypi.org/project/cryptography/),
[python-multipart 배포 정보](https://pypi.org/project/python-multipart/)와 패키지 잠금 파일을 참고하세요.

Docker가 갱신한 전이 의존성도 고정 설치하도록 `uv.lock`에서 내보낸
`apps/api/constraints.txt`를 `pip install -c`에 적용했습니다. API·worker·web을 모두 새로
빌드했고 API 실제 설치 버전 네 가지가 위 표와 일치하며 `pip check`도 통과했습니다.
백엔드 698개와 웹 103개, 타입 검사·웹 빌드가 재통과했습니다. lint 오류는 0건이며 기존
App의 `onSync` 경고 1건이 남아 있습니다. 갱신한 Python 환경의 deprecation 경고는 3건입니다.

동작 변화: FastAPI의 보안 기본값에 따라 JSON 본문에는 `Content-Type: application/json`을
명시해야 합니다. 포털·제공 CI 실행기는 이를 사용하며 파일 업로드는 multipart를 유지합니다.


보안 갱신 후 실제 Docker 검증도 다시 통과했습니다.

- 가중 점수·상속 24개: `security-final/runtime-report.json`
- 기존 품질 18개: `security-quality-regression/runtime-report.json`
- 기존 native/Grype 통합 34개: `security-native/runtime-report.json`
- 실제 Chrome 화면 9개: 페이지 오류·예상 밖 HTTP 오류 0건, 데스크톱/모바일 확인
- 전체 서비스 재시작 전후 점수·품질 리비전·현재 기준·CI 판정 JSON 동일:
  `security-restart-before.json`, `security-restart-proof.json`
- API·worker 실제 의존성 버전: `security-installed-dependencies.json`

위 JSON은 `output/quality-inheritance-20261018/` 아래의 로컬 검증 증거입니다.
API·worker 실행 로그에 traceback/ERROR/CRITICAL은 없었습니다. 이 검증은 샘플과
회귀 테스트 범위의 결과이며 모든 운영 환경에서 오류가 없다는 보장은 아닙니다.


재검증 후에도 모든 컨테이너를 중지하고 빌드 캐시를 다시 삭제했습니다. 이번 추가 회수량은
Docker 보고값 **2.94GB**, 최종 빌드 캐시는 **0건·0B**입니다. Docker Desktop 종료 명령이
성공했고 daemon 접속 불가·Desktop/backend 프로세스 없음도 확인했습니다. 이미지·데이터
볼륨은 보존했습니다. 최종 정리 증거는 로컬 `security-docker-cleanup.json`입니다.

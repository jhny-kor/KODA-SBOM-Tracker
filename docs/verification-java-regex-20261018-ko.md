# Java 정규식 호환 추가 인수 — 2026-10-18

Java Matcher 기반 원본 조건을 KODA 안에서 평가하도록 구현했습니다. 운영 데이터가 없는
격리 Docker 프로젝트 `koda-native-verify-20261017`과 별도 4.13.4 샘플 원본을 사용했습니다.
일반 실행에는 원본 서버가 필요하지 않으며 Grype와 기존 DB는 계속 사용합니다.

## 구현

| 대상 | 처리 |
| --- | --- |
| PURL·CPE·SWID | Java 21 `java.util.regex.Pattern`으로 실제 평가. 원본 wildcard 치환·앞뒤 보완·전체 일치 보존 |
| Java 전용 문법 | 양/음 lookbehind, 번호·이름 역참조, 문자 클래스 교집합/차집합, Unicode, 인라인 플래그, 인용, atomic group·possessive quantifier |
| 좌표 | group·name·version별 `NO_MATCH` 반전 후 AND. ASCII trim·null·빈 문자열, 정규식 버전과 비교 버전 분리 |
| CEL 연결 | 선언형 `JAVA_REGEX` helper의 boolean 결과만 표준 CEL에 전달. 조건·dialect·Java major·격리 여부는 정책/분석 증거에 보존 |
| 배포 | digest를 고정한 Temurin Java 21 JRE와 빌드 시 컴파일한 고정 adapter 포함. 호스트 Java·원본 서비스 불필요 |
| 실패 처리 | 문법 오류는 이관/저장 전에 차단. JVM 오류·시간/메모리/입출력 한도 초과는 정책 실패로 기록 |

원본 5.x의 표준 RE2 조건 경로는 유지합니다. 사용자 정규식은 Java 소스 코드·클래스 이름·
실행 옵션으로 사용하지 않으며, 별도 프로세스의 stdin으로 문자열 데이터만 전달합니다.
실행 환경에는 DB 암호·원본 API 키 등 부모 프로세스의 환경변수를 전달하지 않습니다.

## 실제 검증

- 백엔드 **484개 통과**. 실제 JDK 테스트 30개와 이관·정책 통합 검사 29개 포함.
- 실제 원본 4.13.4 서버에 구성요소 3개와 정책 19종을 만들고 원본 PolicyEngine 판정을 확인했습니다.
- API·worker 이미지를 새로 빌드했고 실행 API의 변경 모듈 해시가 소스와 일치했습니다.
- Linux Docker의 비권한 사용자·읽기 전용 파일시스템·네트워크 없음 조건에서 Java lookbehind 실행 성공.
- Mac 테스트와 Docker에 포함된 JRE는 Temurin **21.0.12.1+1**입니다.

- 실제 Docker 통합 **33개**, Java 런타임 장애·복구 **2개**, 기존 기능 회귀 **34개** 검사 통과.
- 원본 정책 19종의 기대 판정과 **정책·구성요소 결과 22쌍 전체**가 KODA와 일치했습니다.
- 원본을 정지한 상태에서 실제 Grype `0.109.1`과 `2026-10-10` DB(스키마 `6.1.10`)로
  **CVE 12건** 및 Java 정책 결과를 산출했습니다.
- 잘못된 Java 문법은 전체 이관을 차단했습니다. JVM을 사용할 수 없게 한 재분석은
  Grype 완료·정책 실패(`policyStatus=error`)·위반 목록 0개를 명확히 구분했습니다.
  정상 worker 재분석에서는 Java 정책 판정이 복구됐습니다.
- 최종 이미지로 **8개 서비스 전체 stop/up** 후 보존·해시·소스 종료·재분석 등 **10개** 검사 통과.
  재기동 뒤 새 Grype 리비전에서도 원본 결과 22쌍이 정확히 일치했습니다. 패키지 버전이
  원본 5.x의 RE2 경로를 바꾸지 않는지, 좌표 비교의 원문 공백이 유지되는지도 실제 이미지에서 확인했습니다.
- 재분석은 새 리비전을 만들고 과거 정책 스냅샷·원본 파일 해시를 보존했습니다.
  worker 재기동 후에도 저장 결과가 유지됐습니다.

## 한도와 버전 경계

Java 패턴은 2,048자, 종류 200개, 대상 문자열 64KiB, 평가 100,000회,
배치 입력 4MiB·출력 1MiB 한도입니다. 프로세스마다 wall time 6초·CPU 5초·heap 64MiB·
stack 256KiB·Linux 주소 공간 2GiB·FD 64개를 제한합니다. 과도한 역추적을 포함해
평가를 끝내지 못하면 불일치·정상 통과로 바꾸지 않습니다.

Java Matcher 동작은 4.8~4.13 계열의 확인한 구현을 기준으로 하며 실제 API 인수는 **4.13.4**입니다.
4.0~4.7은 후속 구현의 별도 리터럴 경로로 자동이관합니다. [리터럴 인수 기록](verification-literal-20261018-ko.md)을 참조하세요.
모든 운영 데이터에 대한 무제한 동등성을 주장하지 않습니다.

## 재현

폐기 가능한 샘플 원본 전용입니다. 원본 API에 프로젝트·SBOM·정책을 생성하고 검증 중 KODA
정책을 일시 변경합니다. 실행 중인 샘플 4.13.4 API 서버와 준비된 KODA가 필요합니다. 종료 시 기존 KODA 정책을 복구하고 샘플 원본을 정지합니다.
인증 파일은 `baseUrl`·`apiKey`를 포함하며 비공개로 보관합니다.

```bash
python scripts/verify-java-regex-runtime.py \
  --env-file <격리된-테스트.env> \
  --source-auth-file <비공개-원본인증.json> \
  --fixture-file <샘플기록.json> \
  --output <결과.json>
```

로컬 증거·인증·fixture는 `output/java-regex-verification-20261018/`와
`runtime/java-regex-verification-20261018/`에 보관하고 Git에 포함하지 않았습니다. 주요 결과는
`report.json`·`error-path-proof.json`·`final-image-proof.json`·`native-regression/runtime-report.json`입니다.
수집 시각·버전 거리·전체 재분석·VEX 등 앞선 검증은
[고급 기능 인수 기록](verification-complete-20261018-ko.md)을 참조합니다.
Java 문법 기준은 [Java 21 Pattern 명세](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/regex/Pattern.html)입니다.

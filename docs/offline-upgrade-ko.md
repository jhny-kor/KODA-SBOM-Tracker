# 폐쇄망 후보 버전 일괄 검토

## 화면에서 사용하는 순서

1. 실제 배포에 사용한 SBOM과 후보 SBOM을 Tracker의 **같은 서비스·환경**에 반입합니다. 후보별로 대상 패키지의 버전이 하나씩 확인되어야 합니다.
2. 배포 기준 SBOM 상세를 엽니다. Java/Maven은 **Java/Maven 버전 영향 검토**에서 현재 회차를 배포 기준으로 등록합니다.
3. **폐쇄망 후보 버전 일괄 검토**를 열고 기술을 선택해 JSON 양식을 받습니다. 같은 화면에서 후보 회차 ID와 SBOM SHA-256을 확인할 수 있습니다.
4. 양식에 패키지 PURL, 배포 서버 정보, 후보 버전, 후보별 해석 또는 ELF 근거를 채웁니다. 빌드나 실행을 검증했다면 실제 기록을 별도 필드에 추가합니다.
5. **반입하고 일괄 검토**를 누릅니다. 조건 충족 최고 버전, 빌드·실행 모두 통과한 최고 버전, 버전별 충돌 사유가 각각 표시됩니다. 같은 내용의 재반입은 같은 기록을 엽니다. 자료를 추가한 반입은 새 기록으로 남습니다.

한 파일에 후보를 최대 40개, JSON 크기를 1 MiB까지 넣을 수 있습니다. 조건을 충족한 최고 버전은 **이 파일에서 검토한 후보**를 기준으로 계산합니다. 후보 중간에 충돌이나 미확인이 있으면 해당 행을 그대로 표시합니다. SBOM 및 원본 검증 자료는 비교에 사용한 시점의 사본을 보관하세요.

후보 표의 **공식 출처·근거** 열은 반입 자료에서 후보 SBOM의 패키지·버전과 일치하는
선언을 보여줍니다. **선언 근거 보기**와 **원본과 검증 해시**를 열어 기관이 공개한
자료를 확인합니다. 조건 판정은 이 검토에 제출한 해석·ELF 근거를 사용하며,
빌드와 실행은 각각의 검증 기록을 사용합니다. [공식 호환성 자료 반입](official-compatibility-data-ko.md)

## Java/Maven 후보 근거 만들기

같은 Java 버전으로 실행되는 격리된 CI에서 **후보를 적용한 애플리케이션 모듈 전체**의 런타임 의존성을 해석합니다. Maven 플러그인과 후보 라이브러리 및 전이 의존성은 로컬 Maven 저장소에 준비합니다.

```bash
mvn -o org.apache.maven.plugins:maven-dependency-plugin:3.11.0:tree \
  -Dscope=runtime -DoutputType=json -DoutputFile=dependency-tree.json

python3 scripts/project-maven-upgrade-report.py dependency-tree.json \
  --source ci-offline-28 --maven-version 3.9.11 --java-major 11 \
  --minimum-java-major 11 --java-requirement-evidence java-baseline-audit-28 \
  > maven-evidence.json
```

최소 Java 버전은 후보 의존성 조합의 요구사항을 확인한 자료를 사용합니다. 성공한 Maven 트리의 버전 집합이 후보 SBOM의 Maven 구성요소와 일치하고, 배포 Java 버전이 요구사항을 충족할 때 조건 충족으로 표시합니다. 대상 후보가 다른 버전으로 해석되거나 Java 최소 요구사항이 배포 Java보다 높으면 충돌을 표시합니다.

Maven이 명시적인 제약 충돌로 실패하면 후보의 `evidence`에 `kind: "maven"`, `outcome: "conflict"`, `source`, `javaMajor`, `reasons`를 기록합니다. 필요한 POM·JAR·플러그인이 로컬 저장소에 없으면 `outcome: "incomplete"`로 기록합니다. 해석 실패로 후보 SBOM을 만들 수 없으면 해당 행의 `sbom`을 비워 둡니다. [Maven dependency:tree JSON](https://maven.apache.org/plugins/maven-dependency-plugin/examples/tree-mojo.html)

## Python 후보 근거 만들기

배포와 같은 Python 구현체·전체 버전·OS·아키텍처의 격리된 실행기에서 후보를 고정한 **애플리케이션 전체** 요구사항을 사용합니다. 반입한 wheel 모음을 대상으로 아래처럼 해석 결과를 생성합니다.

```bash
python -m pip --isolated --disable-pip-version-check install \
  --dry-run --ignore-installed --no-index --only-binary=:all: \
  --find-links /wheelhouse --report pip-plan.json \
  -r application-candidate-requirements.txt

python3 scripts/project-python-upgrade-report.py pip-plan.json --source ci-python-28 \
  > python-evidence.json
```

`platform`에 `pythonVersion`(예: `3.11.9`), `pythonImplementation`(예: `cpython`), `pythonSysPlatform`(예: `linux`)을 채웁니다. 배포의 pip 환경 마커가 있으면 `pythonEnvironment`에 함께 기록해 대조할 수 있습니다. 한 가상환경의 전체 Python 패키지 이름과 버전이 후보 SBOM과 일치해야 조건 충족으로 집계합니다. wheel이 빠진 경우는 미확인으로 기록합니다. Python 확장 모듈이 사용하는 네이티브 공유 라이브러리는 C/ELF 근거로 별도 검토할 수 있습니다. [pip 모의 설치 보고서](https://pip.pypa.io/en/stable/cli/pip_install/)

## Linux C/ELF 후보 근거 만들기

Linux 검증 환경에서 실제 소비 실행 파일, 배포 기준 공유 라이브러리, 후보 공유 라이브러리를 대상으로 정적 근거를 수집합니다.

```bash
python3 scripts/elf-upgrade-evidence.py \
  --consumer ./bin/application \
  --baseline-library ./before/libwidget.so.1 \
  --candidate-library ./candidate/libwidget.so.1 \
  --complete > elf-evidence.json
```

파일 옵션은 반복할 수 있습니다. 지정한 교체 범위를 실행 파일과 라이브러리가 모두 덮을 때 `--complete`를 사용합니다. 일부 근거만 수집한 경우에는 해당 옵션을 빼면 미확인으로 검토합니다. `platform.nativePlatform`은 `linux`를 사용합니다.

검토 범위는 x86_64·AArch64의 동적 링크 근거, SONAME, 요구 심볼과 심볼 버전입니다. 플러그인 동적 로딩, 정적 링크, 타입 배치 수준의 ABI, 실제 구동은 별도 시험 범위입니다. 최고 버전은 전체 RPM EVR, DEB 버전, 또는 일반 패키지의 숫자 점 표기 버전에서 계산합니다. 정렬 규칙을 지원하지 않는 후보는 판정 행은 표시하고, 최고 버전 계산은 제한될 수 있습니다. RPM PURL의 epoch는 버전에 적용하며 패키지 좌표에는 배포판·아키텍처 조건을 유지합니다. [GNU readelf](https://sourceware.org/binutils/docs/binutils/readelf.html), [RPM 버전](https://rpm.org/docs/4.20.x/manual/spec.html), [Debian 버전](https://www.debian.org/doc/debian-policy/ch-controlfields.html#version)

## 반입 문서 예시

파일 생성 도구가 출력한 JSON 객체를 해당 후보의 `evidence`에 넣습니다. 아래 해시와 ID는 형식 예시입니다. 실제 회차·아티팩트의 값을 사용합니다.

```json
{
  "schemaVersion": 1,
  "ecosystem": "maven",
  "coordinate": "pkg:maven/org.example/core",
  "baseline": {
    "runId": "BASE-RUN-ID",
    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "deploymentId": "JAVA-DEPLOYMENT-ID",
  "platform": {
    "server": "운영 WAS 1",
    "os": "Oracle Linux 8.2",
    "architecture": "x86_64",
    "source": "배포 이미지 정보",
    "javaMajor": 11
  },
  "candidates": [
    {
      "version": "2.8",
      "sbom": {
        "runId": "CANDIDATE-RUN-ID",
        "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      },
      "evidence": {
        "kind": "maven",
        "source": "ci-offline-28",
        "outcome": "resolved",
        "javaMajor": 11,
        "minimumJavaMajor": 11,
        "javaRequirementEvidence": "java-baseline-audit-28",
        "mavenVersion": "3.9.11",
        "reportSha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "selected": [{"coordinate": "pkg:maven/org.example/core", "version": "2.8"}]
      },
      "artifactSha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      "build": {
        "status": "passed",
        "reference": "ci-offline-28-build",
        "artifactSha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "os": "Oracle Linux 8.2",
        "architecture": "x86_64",
        "javaMajor": 11
      },
      "runtime": {
        "status": "failed",
        "reference": "ci-offline-28-smoke",
        "artifactSha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "os": "Oracle Linux 8.2",
        "architecture": "x86_64",
        "javaMajor": 11
      }
    },
    {"version": "2.9"}
  ]
}
```

Python과 C는 `ecosystem`에 각각 `python`, `elf`를 사용하고 `deploymentId`는 생략합니다. 빌드·실행은 각각 `passed` 또는 `failed`와 격리 CI의 기록 식별자를 넣습니다. Python은 해당 검증 항목에 배포 기준과 같은 `pythonVersion`을 넣습니다. 검증을 수행하지 않았거나 결과를 반입하지 않은 항목은 생략하면 화면에 **기록 없음**으로 표시됩니다. Tracker는 반입한 기록을 후보 SBOM 버전, 대상 환경 및 산출물 해시와 대조해 표시합니다. 빌드와 실행은 별도 검증 환경에서 수행합니다.

사용자 세션 API는 `GET /api/v1/upgrade-batches/{runId}/context`, `POST /api/v1/upgrade-batches/import`, `GET /api/v1/upgrade-batches/{runId}`, `GET /api/v1/upgrade-batches/{runId}/{batchId}`입니다. 반입에는 회차 조회 및 카탈로그 관리 권한과 CSRF 토큰이 필요합니다.

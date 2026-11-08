# 공식 호환성 자료 수집과 반입

**설정 → 공식 호환성 자료**에서 Java/Maven, Python, Linux C 자료를 하나의 `tar.gz`로 반입합니다. 폐쇄망 Tracker는 압축 내부의 목록, 고정된 공식 URL, 원본 크기와 SHA-256을 대조하고 패키지 선언을 추출합니다. 원본 압축과 반입 이력은 Tracker에서 확인할 수 있습니다.

## 지정 출처

| 자료 | 화면에 표시되는 기관과 저장소 | 원본에서 추출하는 내용 |
| --- | --- | --- |
| Java/Maven | Sonatype · Maven Central | 버전별 POM의 컴파일러 속성, 직접·관리 의존성, 상위 POM 좌표 |
| Python | Python Software Foundation · PyPI | 공식 릴리스 JSON에 기재된 wheel URL과 SHA-256, wheel의 `Requires-Python`·`Requires-Dist`·플랫폼 태그 |
| Linux C | Oracle · Oracle Linux Yum Server | Oracle Linux BaseOS/AppStream RPM 헤더의 패키지 EVR·아키텍처·`Provides`·`Requires`와 공유 라이브러리 심볼 버전 선언 |

## 기관별 공개 카탈로그 전체 수집

공개망에서 Tracker API의 Python 환경으로 수집 스크립트를 실행합니다. 새 환경은 Python
3.12 이상에서 `python3 -m pip install -e apps/api`로 준비할 수 있습니다.

```bash
python3 scripts/collect-compatibility-repository.py --source all --output-dir ./compatibility-repositories
```

`--source maven`, `--source pypi`, `--source oracle`로 기관을 하나씩 실행할 수도 있습니다.
수집기는 Maven Central 전체 색인, PyPI 공개 프로젝트 목록과 프로젝트별 릴리스 정보,
Oracle Linux Yum 공개 목록에 연결된 저장소의 `repomd.xml`과 primary 색인을 읽습니다.
범위는 기관이 색인에 공개한 패키지·버전입니다. Maven은 색인에 반영된 시점을 기준으로 합니다.
Oracle 특정 채널은 `--oracle-repo`로 지정할 수 있습니다.

| 출력 | 용도 |
| --- | --- |
| `catalog-*.tar.gz` | 패키지·버전·파일 URL, 공식 색인 출처와 SHA-256, 반입 지원 여부, 수집 오류를 검토합니다. PyPI 소스 배포본과 Tracker 미지원 Oracle 패키지도 목록에 남깁니다. |
| `tracker-*.tar.gz` | 공식 POM, PyPI 릴리스 JSON과 지원 wheel, 지원 Oracle RPM을 담습니다. 각 압축은 최대 20개 항목과 16 MiB 제한을 적용하며 Tracker 검증기를 통과한 뒤 저장합니다. |
| `*.tar.gz.sha256` | 반입 전에 각 압축의 무결성을 확인합니다. |
| `catalog.sqlite3`, `indexes/` | 수집한 색인과 항목 상태를 작업 폴더에 저장합니다. |

같은 출력 경로로 재실행하면 완료한 항목을 건너뜁니다. 새 시점의 카탈로그는 새 출력
경로에 수집합니다. `--catalog-only`는 원본 증거 수집 전에 목록을 먼저 확보하고,
`--export-only`는 현재까지의 목록을 네트워크 요청 없이 다시 압축합니다.
`--limit`로 기관별 원본 요청 범위를 나눌 수 있습니다. 종료 코드 3이면 미완료 항목과 오류를
`catalog-*.tar.gz`의 `summary.json`과 목록에서 확인합니다. Maven Central이 색인 요청을
제한하는 경우 이미 확보한 공식 색인 파일을 `--maven-index`로 지정할 수 있습니다.
[Maven Central 색인](https://maven.apache.org/repository/central-index.html),
[PyPI Index API](https://docs.pypi.org/api/index-api/),
[Oracle Linux Yum 저장소](https://docs.oracle.com/en/operating-systems/oracle-linux/software-management/sfw-mgmt-AvailableYumRepositories.html)

## 패키지와 버전을 지정해 수집

저장소 소스의 공개망 사본에서 아래처럼 검토할 패키지와 버전을 명시합니다. 수집기는 Python 표준 라이브러리로 지정 HTTPS 저장소에 접속합니다. Maven Central의 POM과 Oracle Linux Yum의 RPM은 버전별 원본 URL에서 직접 내려받습니다. PyPI는 공식 릴리스 JSON API로 지정 wheel 파일을 찾고, 원본 저장소에서 받은 바이트를 PyPI가 공개한 크기와 SHA-256으로 대조합니다.

```bash
python3 scripts/collect-compatibility-data.py \
  --output tracker-official-compatibility.tar.gz \
  --maven commons-io:commons-io 2.16.1 \
  --python urllib3 2.2.3 urllib3-2.2.3-py3-none-any.whl \
  --oracle-rpm zlib 1.2.11-13.el8 \
    https://yum.oracle.com/repo/OracleLinux/OL8/2/baseos/base/x86_64/getPackage/zlib-1.2.11-13.el8.x86_64.rpm
```

같은 옵션을 반복하면 최대 20개 항목을 한 압축에 담습니다. 파일별 원본 URL, 크기, SHA-256과 수집 시각은 `manifest.json`에 기록합니다. 파일 전체의 체크섬은 함께 생성한 `.tar.gz.sha256`에 있습니다.

## 폐쇄망에서 확인

1. `shasum -a 256 -c tracker-official-compatibility.tar.gz.sha256` 또는 Linux의 `sha256sum -c tracker-official-compatibility.tar.gz.sha256`으로 전송받은 압축의 해시를 확인합니다.
2. Tracker의 **설정 → 공식 호환성 자료**에서 단건 수집 압축 또는 `tracker-*.tar.gz` 하나를 선택해 **반입하고 검증**을 누릅니다. 압축 파일의 한도는 16 MiB, 압축 해제 자료의 한도는 32 MiB입니다.
3. **선언 근거 보기**와 **원본과 검증 해시**를 열면 기관별 근거와 URL, SHA-256을 확인할 수 있습니다.

## 후보 버전 검토에서 확인

**SBOM 회차 → 배포 기준 회차 → 폐쇄망 후보 버전 일괄 검토 → 결과 보기**에서 **공식 출처·근거** 열을 확인합니다. 같은 서비스·환경의 후보 SBOM에서 검토 대상 패키지와 버전이 확인되면 이미 반입된 자료가 자동으로 표시됩니다. 새 자료를 반입한 뒤 이전 검토 결과를 다시 열어도 저장된 판정과 빌드·실행 기록은 그대로이고 출처만 최신 반입 상태를 반영합니다.

- Maven은 `groupId:artifactId`와 버전, Python은 정규화한 PyPI 이름과 버전으로 대조합니다.
- Oracle Linux RPM은 패키지 이름, 전체 RPM 버전(epoch/version/release), 아키텍처를 함께 대조합니다. PURL에 배포판 버전이 있으면 RPM 저장소의 Oracle Linux 버전도 맞아야 합니다. 다른 배포판의 RPM이나 Oracle Linux 여부가 불명확한 RPM은 연결하지 않습니다.
- 후보별 최근 자료를 최대 3건 표시합니다. **선언 근거 보기**와 **원본과 검증 해시**에서 세부 정보와 수집 날짜를 확인할 수 있습니다. **일치 자료 없음**은 반입 자료에서 일치 항목을 찾지 못했다는 뜻입니다.

표의 기관명은 Tracker에 고정된 저장소 출처입니다. 반입 검증은 지정 주소와 압축 내부 바이트의 일치를 확인합니다. 원본 서명을 독립 검증하려면 공급사가 제공하는 별도 서명·검증 체계가 필요합니다.

공개 자료의 POM은 선언 수준으로 표시됩니다. 상위 POM과 프로필을 적용한 Maven 해석, 사내 Python 의존성 해석, 대상 C 실행 파일의 심볼 대조, 빌드·실행 통과 여부는 [폐쇄망 후보 버전 일괄 검토](offline-upgrade-ko.md)에서 배포 기준별로 기록합니다.

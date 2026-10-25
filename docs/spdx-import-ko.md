# SPDX 2.3 JSON 반입

기존 SBOM 업로드 API에 SPDX 2.3 JSON을 업로드할 수 있습니다. 원본 파일과 SHA-256은 기존 artifact 저장소에 그대로 보관하고, 내부 조회·정책 평가를 위해 CycloneDX 1.6으로 정규화합니다. KODA에서 생성한 SPDX도 반입할 수 있으며 두 프로젝트의 실행 의존성은 분리되어 있습니다.

업로드 화면에서 지원하는 입력은 **CycloneDX 1.4·1.5·1.6·1.7 JSON/XML**과 **SPDX 2.3 JSON**입니다. SPDX 지원 버전과 형식은 원본 문서의 `spdxVersion=SPDX-2.3`을 기준으로 검사합니다.

- SPDX 패키지 식별자, 이름·버전, PURL/CPE externalRefs, 유효한 checksums, 선언 라이선스·공급자를 변환합니다.
- 원본 패키지는 `koda:spdx:package`, 문서 메타데이터와 전체 관계는 메타데이터 properties에 보존합니다. `NOASSERTION`과 `NONE`은 라이선스 식으로 오인하지 않고 원본 근거에 유지합니다.
- `DEPENDS_ON`과 역방향 `DEPENDENCY_OF`만 의존 그래프로 변환합니다. `CONTAINS`, 파일·외부 문서 관계는 보존하되 패키지 의존 관계로 추측하지 않습니다.
- 중복 SPDXID, 충돌하는 PURL/CPE, 잘못된 해시, 존재하지 않는 관계 대상은 반입을 거절합니다. 현재 지원 형식은 `SPDX-2.3` JSON입니다.
- 선택적 CycloneDX 스키마 검증기를 사용하는 경우 정규화된 임시 JSON을 검사합니다. 원본 업로드를 덮어쓰지 않습니다. Grype는 저장된 원본 SPDX를 입력으로 사용합니다.

추가 의존성과 외부 호출은 없습니다. SPDX에 포함된 URL은 식별·근거 정보이며 업로드 과정에서 접속하지 않습니다.

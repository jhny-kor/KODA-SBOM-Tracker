# 오픈소스 라이선스 정책

산출물을 누구에게 전달할 수 있는지 판단할 때 읽습니다.

## 산출물별 배포 범위

| 산출물 | 만드는 스크립트 | 배포 범위 |
| --- | --- | --- |
| 소스 저장소 | — | Apache-2.0 |
| Windows Preview 설치파일 | `build-windows-preview-installer.ps1` | 설치 폴더 `legal` 포함 시 배포 가능 |
| 폐쇄망 압축파일 | `build-airgap-release.sh` | **내부 반입 전용** |
| 이미지 번들 | `build-offline-bundle.sh` | **내부 반입 전용** |
| 전체 Windows 설치파일 | `build-windows-installer.ps1` | **내부 반입 전용** |

## 기본 정책

- KODA SBOM Tracker 자체 코드는 Apache License 2.0으로 배포합니다.
- 모든 소스·설치파일·웹 이미지·API 이미지에는 `LICENSE`, `NOTICE`,
  `THIRD_PARTY_NOTICES.md`를 읽을 수 있는 형태로 포함합니다.
- React, React DOM, Pretendard를 포함하는 웹 산출물에는 실제 설치된 패키지의 라이선스
  전문을 `legal` 디렉터리에 복사합니다. 파일이 없으면 빌드를 실패시킵니다.
- 기존에 만든 고지 없는 산출물은 새 빌드로 교체하기 전까지 배포하지 않습니다.

## 허용되는 배포

Docker 없는 Windows Preview는 설치 마법사에서 Apache-2.0을 표시하고 설치 폴더에 서드파티
라이선스를 함께 제공하는 경우 배포할 수 있습니다.

컨테이너 이미지를 포함하는 다음 산출물은 내부 반입 전용입니다.

- `build-airgap-release.sh`가 만드는 폐쇄망 압축파일
- `build-offline-bundle.sh`가 만드는 이미지 번들
- `build-windows-installer.ps1`이 만드는 전체 Windows 설치파일

이 산출물은 컨테이너 OS와 전이 의존성의 GPL/LGPL 등 조건을 함께 검토해야 합니다. 완전한
대응 소스 제공 방식과 법무 승인이 준비되기 전에는 고객, 협력사, 계열사 또는 공개 저장소로
전달하지 않습니다. 생성 스크립트와 검증 스크립트는 이 범위를 `internal-only`로 고정합니다.

## 릴리스 확인

1. 루트 법적 고지 세 파일이 현재 버전인지 확인합니다.
2. `pytest tests/backend/test_license_compliance.py`를 실행합니다.
3. 산출물 안의 `legal` 또는 루트에서 법적 고지를 직접 열어 확인합니다.
4. 컨테이너 이미지 번들은 `DISTRIBUTION_SCOPE=internal-only`인지 확인합니다.
5. 외부 배포가 필요하면 빌드를 우회하지 말고 대응 소스 범위와 제공 기간을 법무와 먼저
   확정합니다.

이 문서는 엔지니어링 통제이며 법률 자문이나 라이선스 준수 인증을 대신하지 않습니다.

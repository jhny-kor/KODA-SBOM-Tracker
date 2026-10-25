# Linux Docker 이미지 날짜 태그

새 Linux 반입 배포를 빌드하면 KODA SBOM Tracker API·Web·Worker 이미지에 `YYYYMMDDTHHMMSSZ-<git 12자리>[-dirty]` 태그를 자동 부여합니다. 예: `local/koda-sbom-portal-api:20261019T143000Z-0123456789ab`.

- 날짜·시간은 UTC이며 `Z`로 표시합니다. 한국 시간은 UTC보다 9시간 빠릅니다.
- 같은 날 여러 빌드도 초 단위로 구분하며, 미커밋 변경이 있으면 `-dirty`가 붙습니다. 커밋번호만으로 미커밋 소스 전체의 동일성을 보장하지 않으므로 배포 서명·manifest 검증도 유지합니다.
- `build-airgap-release.sh`와 `build-offline-bundle.sh`가 날짜 태그로 직접 빌드하며 OCI `created`·`revision`·`version` 라벨을 기록합니다. 기존 이미지에 새 날짜를 붙이는 동작이 아닙니다.
- 배포물의 `metadata.env`에 IMAGE_TAG·IMAGE_BUILT_AT·IMAGE_REVISION, `config/release-images.env`에 설치할 이미지 참조를 기록합니다. 검증된 배포물을 설치하거나 오프라인 번들을 반입하면 기존 `.env`의 애플리케이션 이미지 4개 설정만 갱신하고 DB 비밀번호 등은 유지합니다.
- 명시적 태그가 필요하면 `TRACKER_RELEASE_IMAGE_TAG=20261019T143000Z-release1`처럼 UTC 날짜로 시작하는 값을 지정합니다. 운영 `.env`의 기존 `dev` 값은 새 배포 태그로 사용하지 않습니다.
- PostgreSQL·Nginx·Grype 등 외부 이미지는 공급자가 제공한 버전 태그·고정 digest를 유지합니다. 취약점 데이터의 갱신 시각은 데이터 manifest에서 따로 확인합니다.

설치 폴더에서 다음 명령으로 실제 컨테이너의 이미지 태그와 ID를 확인합니다.

```bash
docker compose --env-file .env -f compose.yaml -f compose.airgap.yaml images
docker ps --format 'table {{.Names}}\t{{.Image}}'
```

날짜는 반입된 이미지들 사이의 빌드 순서를 확인하는 정보입니다. 폐쇄망 서버가 외부 최신 릴리스를 자동 확인하는 기능은 아닙니다. 기존 실행 이미지·로컬 빌드 자료는 이번 변경으로 삭제하거나 다시 빌드하지 않습니다.

검증: backend 632개 통과·19개 환경 의존 검사 제외. 날짜 태그 생성, 잘못된 태그 거부, 설정·파일 권한 보존, 테스트 이미지 도구를 사용한 배포 tar의 태그 전달을 확인했습니다. `docker compose config --images`에서도 새 날짜 태그 적용을 확인했습니다. 이번 작업에서 전체 운영 이미지를 새로 빌드하거나 설치하지는 않았습니다.

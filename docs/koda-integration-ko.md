# KODA 통합 인증·운영 계약

KODA Linux 통합본은 KODA SBOM Tracker를 계정·세션의 단일 원본으로 사용합니다.
두 제품은 같은 HTTPS 오리진에서 서비스되며 KODA의 내부 8765 포트는 호스트에
공개하지 않습니다.

```text
https://<서버>/          KODA SBOM Tracker
https://<서버>/koda/     KODA
```

## 로그인과 로그아웃

사용자는 Tracker 로그인 화면에서 로그인합니다. 로그인 화면의 LDAP 선택지는 향후
연동용이며 현재 선택하면 `501 ldap_not_configured`로 실패합니다.

gateway는 보호된 KODA 요청마다 Tracker의 `GET /api/v1/auth/session`으로 쿠키
세션을 확인합니다. 이 endpoint는 Bearer 토큰을 받지 않으며 성공할 때만 UUID,
세션 만료 시각, 표시 이름을 응답 헤더로 제공합니다. gateway는 브라우저가 임의로
보낸 인증·신원 헤더를 제거하고 검증된 값만 KODA에 전달합니다.

KODA와 Tracker의 로그아웃은 모두 `POST /api/v1/auth/logout-current`를 호출해
현재 브라우저의 서버 세션을 폐기합니다. 어느 한쪽에서 로그아웃해도 양쪽 보호
화면은 다시 로그인이 필요합니다.

## 계정과 권한

계정 UUID와 활성 상태는 Tracker가 관리합니다. KODA는 이 UUID를 별도 비밀번호
없이 사용하며, 처음 본 계정은 `pending`으로 등록합니다.

권한은 사이트별로 독립적입니다.

- Tracker: 역할 정책으로 Tracker 화면과 SBOM 업로드·분석·설정 기능을 제어합니다.
- KODA: 시스템 관리자 여부와 프로젝트 멤버십 역할로 KODA 화면과 기능을 제어합니다.
- KODA 보안·품질 점검 규칙: KODA 시스템 관리자만 변경합니다.
- 일반 KODA 사용자: 허용된 프로젝트에서 검사 기준과 기준 범위만 선택합니다.

Tracker의 관리자·매니저 정책과 KODA의 마지막 활성 시스템 관리자는 각각 제거
방지 규칙을 적용합니다.

## 운영과 장애 동작

운영에서는 `TRACKER_ENVIRONMENT=production`, `TRACKER_SECURE_COOKIES=true`,
`TRACKER_PUBLIC_ORIGIN=https://<서버>`를 사용하고 앞단 TLS 종료기가 원래 Host와
HTTPS scheme을 보존해야 합니다.

Tracker 인증 확인이 실패하거나 시간 초과되면 gateway는 KODA 보호 화면과 API를
`503`으로 실패시킵니다. 이전 인증 결과를 캐시하거나 KODA를 익명으로 열지
않습니다. KODA에서 이미 시작된 분석 작업은 KODA 저장소와 worker 상태에 따라
계속 처리되며, 인증 복구 후 같은 계정·프로젝트 권한으로 조회합니다.

상태 확인 경로만 인증 예외입니다.

- `/healthz`
- `/api/v1/healthz`
- `/koda/live`
- `/koda/ready`는 KODA 저장소·worker와 Tracker health를 함께 확인합니다.

통합 압축파일 생성과 설치는 KODA 저장소의
`platforms/linux/suite/README.ko.md`를 따릅니다.

Dependency-Track UI는 Tracker/KODA SSO 대상이 아니며 별도 계정으로 로그인합니다.
Tracker backend용 team API 키는 `v1/team/self`의 권한으로 검증하며 team 사용자
멤버가 0명이어도 사용할 수 있습니다. 공개 frontend base URL에는 `/api`를 붙이지
않고, 관리자 자동화 base에만 `/api`를 붙입니다. 흰 화면·API 키·BOM 400 문제는
[폐쇄망 장애 대응](troubleshooting-ko.md)을 따릅니다.

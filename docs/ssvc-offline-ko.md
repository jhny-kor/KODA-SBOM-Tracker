# 폐쇄망 SSVC 대응 우선순위

Tracker 회차 상세의 **SSVC · 대응 우선순위**에서 현재 취약점 페이지의 정확한 구성요소·버전·취약점을 선택해 평가합니다. 인터넷 조회 없이 내장 결정표를 계산하며 원래 취약점 심각도와 정책 결과를 덮어쓰지 않습니다. OSV는 이 기능에 필요하지 않습니다.

## 모델과 입력

CERT/CC Deployer Patch Application Priority `ssvc:DT_DP:1.0.0`의 72개 조합을 그대로 사용합니다. CISA Coordinator의 Track/Attend/Act와 다른 모델입니다. 결과는 `defer`(보류), `scheduled`(정기 조치), `out-of-cycle`(일정 외 우선 조치), `immediate`(즉시 대응)입니다. 조직의 SLA 일수나 배포 차단을 자동 결정하지는 않습니다.

입력은 Exploitation 1.1.0, System Exposure 1.0.1, Automatable 2.0.0, Human Impact 2.0.2입니다. 악용 상태·서비스 노출·자동화 가능성·업무 및 안전 영향을 담당자가 확인하고 판단 근거와 가정을 기록합니다. 업무·안전 영향은 화면의 입력 기준을 참조하세요. 폐쇄망이라는 이유만으로 노출을 small로 자동 설정하지 않습니다. 내부 공격 경로와 통제를 확인해야 합니다.

확인하지 못한 입력은 빈 값으로 남깁니다. 이 경우 결과는 **미평가**이며 defer로 계산하지 않습니다. KEV 비등재와 낮은 EPSS는 악용 근거 없음의 증거가 아닙니다. 원시 발견에 KEV가 확인된 경우 악용 상태를 active 또는 미확인으로만 저장할 수 있습니다. 참조 문서 ID·경로·URL은 기록용 문자열이며 서버가 내려받지 않습니다.

## 범위·이력·재평가

평가는 서비스·환경·릴리스·SBOM 회차·분석 리비전·정확한 구성요소 버전·취약점에 연결됩니다. 매 저장은 새 행이며 과거 판단·기술 근거 스냅샷·결정표 해시·작성자·시각을 보존합니다. 기존 판단 수정이나 다른 서비스로 자동 재사용은 하지 않습니다. 새 판단은 기존 판단을 이력으로 남깁니다.

최신 분석이 대기·실행·실패 상태이거나 SBOM이 보관된 경우 새 판단을 저장하지 못합니다. 화면을 연 뒤 분석 리비전이 변경되면 서버는 409로 거절하므로 새로고침 후 평가해야 합니다. 활성 취약점 번들이 분석 당시 버전과 다르면 먼저 재분석해야 합니다.

분석 리비전, 취약점 근거(KEV·EPSS 포함), 활성 취약점 번들 또는 재평가 기한이 달라지면 과거 판단에 **재평가 필요**를 표시합니다. 과거 결과는 당시 값으로 보존하며 자동으로 더 낮은 우선순위로 바꾸지 않습니다. 페이지 새로고침에서 현재 근거와 비교합니다.

## 권한과 API

- `ssvc.view`: 모델·판단 이력 조회. `ssvc.manage`: 새 판단 저장 및 조회.
- 신규 기본 역할에는 모두 조회 권한, admin/manager/analyst에는 관리 권한을 부여합니다. 기존 설치의 최초 기능 갱신 시 runs.view 또는 vex.view가 있던 역할에는 조회, vex.manage 또는 roles.manage가 있던 역할에는 관리 권한을 추가합니다. 이후 사용자 지정 역할 설정을 유지합니다.
- 브라우저 세션의 변경 요청에는 CSRF 토큰이 필요합니다. 서비스 API 토큰에는 이 기능의 조회·작성 권한을 제공하지 않습니다.
- `GET /api/v1/ssvc/model`: 모델·입력값·원본 출처·해시.
- `GET /api/v1/sbom-runs/{id}/ssvc?page=1&size=20`: 해당 회차의 판단 이력과 현재 재평가 상태.
- `POST /api/v1/sbom-runs/{id}/ssvc`: `component`, `vulnerabilityId`, `expectedRevisionId`, 네 필드의 `inputs`, `rationale`, 선택적 `references`·시간대를 포함한 미래 `reviewAt`.

## 결정표 출처와 배포

공식 소프트웨어 데이터의 고정 커밋 `fa6a3a4cb3943d76e3f0057d84dc57b5fe3e064a`에서 `data/csv/ssvc/deployer_patch_application_priority_1_0_0.csv`를 반입했습니다. [공식 모델 설명](https://certcc.github.io/SSVC/howto/deployer_tree/), [고정 원본](https://github.com/CERTCC/SSVC/blob/fa6a3a4cb3943d76e3f0057d84dc57b5fe3e064a/data/csv/ssvc/deployer_patch_application_priority_1_0_0.csv).

결정표와 출처·SHA-256·MIT (SEI)-style 라이선스 전문은 `apps/api/koda_tracker/ssvc_data/`에 동봉합니다. 런타임은 네트워크에서 결정표를 갱신하지 않으며 해시·72개 입력 조합을 검사합니다. 모델 변경은 버전·결정표 해시가 기록되는 새 제품 릴리스로 검토해 배포합니다. 새 `ssvc_assessments` 테이블은 서버 시작의 기존 create_all 경로에서 생성되며 기존 발견·검토 테이블은 변경하지 않습니다.

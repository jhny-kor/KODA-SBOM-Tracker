# 문서용 도식

| 파일 | 쓰이는 곳 |
| --- | --- |
| `koda-sbom-tracker-screens.svg` | README, 화면·기능 한눈에 보기 |
| `tracker-integration-tabs.jpg` | 화면·기능 한눈에 보기의 연동 설정 화면 |
| `koda-sbom-tracker-flow.svg` | 화면·기능 한눈에 보기 |
| `koda-suite-process.svg` | KODA 통합 인증·운영 계약 — 전체 흐름 |

## koda-suite-process.svg 수정

이 도식만 생성 도구를 씁니다. 원본 사양은 `koda-suite-process.workflow.json`이며
[archify](https://github.com/tt-a1i/archify) 스킬로 렌더합니다.

```sh
node bin/archify.mjs validate workflow koda-suite-process.workflow.json --quality showcase --json
node bin/archify.mjs deliver  workflow koda-suite-process.workflow.json out.html --quality showcase --json
```

`deliver`가 만든 HTML에서 `<svg>` 블록만 꺼내, 이 저장소 색상으로 맞춘 내부 `<style>`을
붙여 `koda-suite-process.svg`로 저장합니다. 색상은 다른 두 도식과 같은 값을 씁니다
(본문 `#17232d`, 보조 `#667680`, 강조 `#087b82`, 경고 `#c86b00`, 위험 `#cf2525`).

도식은 라이트 배경(`#f7f9fa`) 한 벌만 유지하며 별도 다크 버전을 두지 않습니다.

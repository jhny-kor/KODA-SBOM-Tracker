import type { ComponentSnapshot } from "./types";

const fields: [string, string][] = [
  ["model", "모델"], ["revision", "하드웨어 리비전"], ["parent-id", "상위 장치 ID"],
  ["source", "수집 출처"], ["observed-at", "관측 시각"],
  ["evidence:runningVersion", "실행 버전"], ["evidence:storedVersion", "저장 버전"],
  ["evidence:applicationState", "보고된 적용 상태"], ["evidence:state", "관측 상태"],
  ["evidence:versionFormat", "버전 표기 형식"], ["evidence:rawVersion", "원본 버전값"],
  ["evidence:microcode", "마이크로코드"], ["evidence:virtualization", "가상화 관측"],
  ["evidence:observationScope", "관측 범위"], ["evidence:evidenceSHA256", "수집 증적 SHA-256"],
];

export function AssetEvidence({ component }: { component: ComponentSnapshot }) {
  if (!["device", "firmware", "device-driver"].includes(component.componentType || "")) return null;
  const values = new Map<string, string>();
  if (Array.isArray(component.properties)) {
    for (const property of component.properties) {
      if (!property || typeof property !== "object") continue;
      const row = property as Record<string, unknown>;
      if (typeof row.name === "string" && row.name.startsWith("koda:asset:") && typeof row.value === "string") values.set(row.name.slice("koda:asset:".length), row.value);
    }
  }
  const observed = fields.filter(([key]) => values.get(key));
  const versions = [...values].filter(([key]) => /^evidence:(running|stored|fixed)\./.test(key));
  return <details>
    <summary>장치·펌웨어 관측 정보</summary>
    <dl>
      <dt>유형</dt><dd>{component.componentType}</dd>
      <dt>수집 버전</dt><dd>{component.version || "미확인"}</dd>
      {observed.map(([key, label]) => <div key={key}><dt>{label}</dt><dd><code className="wrap">{values.get(key)}</code></dd></div>)}
      {versions.map(([key, value]) => <div key={key}><dt>{key.slice("evidence:".length)}</dt><dd>{value}</dd></div>)}
    </dl>
    <p>패치 완료 여부는 제조사 권고와 현재 적용 상태를 함께 확인합니다.</p>
    {!values.size && <p>상세 수집 근거가 제공되지 않았습니다.</p>}
  </details>;
}

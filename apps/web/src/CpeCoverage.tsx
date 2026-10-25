import type { AnalysisRevisionSummary } from "./types";
import "./quality.css";

const statusLabels: Record<string, string> = {
  completed: "제공 CPE 조건 평가 완료", incomplete: "평가 범위 불완전",
  unavailable: "적용 자료 이용 불가", not_evaluated: "미평가",
};
const reasons: Record<string, string> = {
  "No concrete CPE 2.3 identities supplied; no package-name inference performed": "구체적인 CPE 2.3 제품 식별자가 제공되지 않아 평가하지 않았습니다. 제품 이름으로 CPE를 추정하지 않습니다.",
  "No indexed applicability conditions for supplied products; absence is not proof of safety": "제공한 제품에 대한 적용 조건이 반입 자료에서 확인되지 않았습니다. 이 결과로 안전 여부를 확정할 수 없습니다.",
};
const count = (value: unknown, unit = "") => typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value.toLocaleString() + unit : "확인 불가";

export function CpeCoverage({ analysis, loading = false }: { analysis?: AnalysisRevisionSummary; loading?: boolean }) {
  const summary = analysis?.dataSources?.cpeApplicability;
  const status = typeof summary?.status === "string" ? summary.status : "unknown";
  const reason = typeof summary?.reason === "string" ? summary.reason : "";
  const countsIncomplete = [summary?.invalidCpes, summary?.unmatchedProducts, summary?.unknownCves].some(value => typeof value !== "number" || !Number.isSafeInteger(value) || value !== 0);
  const scopeIncomplete = status !== "completed" || countsIncomplete;

  return <section className="workflow-panel cpe-coverage tracker-view" aria-label="오프라인 CPE 평가 범위">
    <h3>오프라인 CPE 평가 범위</h3>
    {loading ? <p>최신 분석의 CPE 평가 범위를 불러오는 중입니다.</p> : !analysis ? <p>분석 리비전이 없습니다. CPE 평가 여부를 확인할 수 없습니다.</p> : <>
      <p>최신 분석 r{analysis.sequence} · {analysis.state === "completed" ? "분석 완료" : `분석 ${analysis.state}`} · CPE {statusLabels[status] || "상태 확인 필요"}</p>
      {analysis.state !== "completed" && <p>최신 분석이 완료되지 않았습니다. 아래 값은 현재 확보된 근거이며 최종 점검 결과로 확정할 수 없습니다.</p>}
      {!summary ? <p>이 분석에는 CPE 평가 근거가 없습니다. 구버전 분석 또는 미평가 상태이므로 CPE 취약점 없음으로 간주할 수 없습니다.</p> : <>
        <div className="table-scroll" role="region" aria-label="CPE 평가 현황 가로 스크롤" tabIndex={0}><table className="cpe-coverage-table" aria-label="CPE 평가 항목별 현황"><tbody>
          <tr><th scope="row">입력 CPE</th><td>{count(summary.inputCpes, "개")}</td><th scope="row">유효하지 않은 CPE</th><td>{count(summary.invalidCpes, "개")}</td></tr>
          <tr><th scope="row">적용 조건이 없는 제품</th><td>{count(summary.unmatchedProducts, "개")}</td><th scope="row">평가한 CVE</th><td>{count(summary.evaluatedCves, "개")}</td></tr>
          <tr><th scope="row">조건 판정 불가 CVE</th><td>{count(summary.unknownCves, "개")}</td><th scope="row">적용 조건 형식·복잡도 확인 필요 CVE</th><td>{count(summary.indexIncompleteCves, "개")}</td></tr>
          <tr><th scope="row">영향 확인 CVE</th><td>{count(summary.affectedCves, "개")}</td><th scope="row">추가 발견 / 기존 발견 보강</th><td>{count(summary.addedFindings)} / {count(summary.matchedExisting)}건</td></tr>
          <tr className="cpe-coverage-wide"><th scope="row">적용 조건 없는 과거 NVD 레코드</th><td colSpan={3}>{count(summary.legacyDetailsOnly, "개")}</td></tr>
          <tr className="cpe-coverage-wide"><th scope="row">인벤토리 전체성</th><td colSpan={3}>{summary.inventoryComplete === true ? "완전한 인벤토리로 평가됨" : "확인되지 않음 · 누락 환경 조건은 판정 불가로 처리"}</td></tr>
        </tbody></table></div>
        {reason && <p>평가 사유: {reasons[reason] || reason}</p>}
        {!!summary.unresolved?.length && <details><summary>미판정 근거 보기 (최대 100개)</summary><ul className="paths">{summary.unresolved.slice(0, 100).map((item, index) => <li key={`${item.id}-${index}`}>{item.id}: {item.reason}</li>)}</ul></details>}
        {scopeIncomplete && <p>식별자 또는 적용 자료가 부족하거나 조건을 확정하지 못했습니다. 미평가·미판정 항목을 취약점 없음으로 집계해서는 안 됩니다.</p>}
        <p>제공한 CPE와 반입한 NVD 적용 조건을 기준으로 평가합니다. 발견 0건은 전체 제품·환경의 안전을 보장하지 않습니다.</p>
      </>}
    </>}
  </section>;
}

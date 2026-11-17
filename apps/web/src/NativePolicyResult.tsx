import { analysisAvailable } from "./analysisAvailability";
import { useEffect, useState } from "react";
import { fetchRunPolicyViolations, previewMode } from "./api";
import { formatSeoulDateTime } from "./format";
import type { AnalysisRevisionSummary, NativePolicyFields } from "./types";

export function NativePolicyResult({ result, runId, analysisId }: { result: NativePolicyFields & { policyViolationCount?: number; vulnerableComponentCount?: number | null }; runId?: string; analysisId?: string }) {
  const [reload, setReload] = useState(0);
  const [pagination, setPagination] = useState({ key: "", page: 1 });
  const [remote, setRemote] = useState<{ key: string; items: Record<string, unknown>[]; total: number; error?: string }>({ key: "", items: [], total: 0 });
  const selectedAnalysis = analysisId || result.analysisId || "";
  const queryBase = `${runId || "local"}:${selectedAnalysis}:${result.policyVersion || ""}:${result.policyState || ""}`;
  const requestedPage = pagination.key === queryBase ? pagination.page : 1;
  const queryKey = `${queryBase}:${requestedPage}:${reload}`;
  const serverResults = !previewMode && Boolean(runId);
  useEffect(() => {
    if (!serverResults || !runId) return;
    let active = true;
    void fetchRunPolicyViolations(runId, requestedPage, 25, selectedAnalysis).then((value) => {
      if (active) setRemote({ key: queryKey, items: value.items, total: value.total });
    }).catch((error: unknown) => {
      if (active) setRemote({ key: queryKey, items: [], total: 0, error: error instanceof Error ? error.message : "정책 결과를 불러오지 못했습니다." });
    });
    return () => { active = false; };
  }, [queryKey, requestedPage, runId, selectedAnalysis, serverResults]);
  const loaded = !serverResults || remote.key === queryKey;
  const error = serverResults && loaded ? remote.error : undefined;
  const violations = serverResults ? loaded ? remote.items : [] : result.policyViolations || [];
  const total = serverResults ? loaded ? remote.total : 0 : violations.length;
  const pageCount = Math.max(1, Math.ceil(total / 25));
  const currentPage = Math.min(requestedPage, pageCount);
  const visible = serverResults ? violations : violations.slice((currentPage - 1) * 25, currentPage * 25);
  const evaluated = analysisAvailable(result) && result.policyState === "completed";
  const status = result.policyStatus;
  const label = result.policyState === "failed" ? "평가 실패" : !evaluated ? "미평가" : status === "fail" ? "위반" : status === "warn" ? "경고" : status === "info" ? "정보" : status === "pass" ? "통과" : "평가 완료";
  return <section className="native-policy-result" aria-label="KODA 정책 평가 결과">
    <div className="detail-table-heading"><h3>KODA 정책 평가{result.policyVersion ? ` · v${result.policyVersion}` : ""}</h3><span className={`state ${evaluated && status === "pass" ? "completed" : "partial"}`}>{label}</span></div>
    {result.policyError && <p className="drawer-error" role="alert">{result.policyError}</p>}
    {!evaluated && <p>정책 평가가 완료되지 않았습니다. 새 분석 리비전으로 Grype 분석과 현재 KODA 정책을 실행할 수 있습니다.</p>}
    {serverResults && !loaded && <p role="status">정책 결과를 불러오는 중입니다.</p>}
    {error && <div><p className="drawer-error" role="alert">{error}</p><button type="button" className="secondary compact" onClick={() => setReload((value) => value + 1)}>정책 결과 다시 불러오기</button></div>}
    {loaded && !error && (evaluated || (analysisAvailable(result) && violations.length > 0)) && <>{evaluated ? <p>활성 위반·경고·정보 {result.policyViolationCount ?? 0}건 · 정책 예외·승인된 VEX도 아래에 근거를 표시합니다.</p> : <p>아래는 기존 분석에 저장된 정책 기록입니다. KODA 자체 정책 평가 결과와 구분됩니다.</p>}<div className="table-scroll"><table><thead><tr><th>정책</th><th>구성요소</th><th>취약점</th><th>판정</th><th>근거</th></tr></thead><tbody>{visible.map((violation, index) => <tr key={`${String(violation.policyId)}-${index}`}><td>{String(violation.policyName || violation.policyId || violation.rule || "-")}</td><td className="mono wrap">{typeof violation.component === "object" && violation.component ? String((violation.component as Record<string, unknown>).name || "-") : String(violation.component || "-")}</td><td>{String(violation.vulnerabilityId || "-")}</td><td>{violation.suppressed ? violation.suppressionSource === "vex" ? "승인된 VEX" : "정책 예외" : violation.action === "info" ? "정보" : violation.action === "warn" ? "경고" : violation.action === "fail" ? "위반" : String(violation.type || "기존 결과")}</td><td>{String(violation.reason || "-")}{violation.vex && typeof violation.vex === "object" ? <div>VEX: {String((violation.vex as Record<string, unknown>).detail || "")} · 승인자 {String((violation.vex as Record<string, unknown>).reviewer || "-")}</div> : null}{violation.suppressed && violation.exception && typeof violation.exception === "object" ? <div>{String((violation.exception as Record<string, unknown>).reason || "")} · {(violation.exception as Record<string, unknown>).expiresAt ? `만료 ${formatSeoulDateTime(String((violation.exception as Record<string, unknown>).expiresAt))}` : "만료 없음 (무기한)"}</div> : null}</td></tr>)}{!violations.length && <tr><td colSpan={5}>적용한 정책의 위반·경고·정보가 없습니다.</td></tr>}</tbody></table></div>{pageCount > 1 && <div className="detail-pagination"><span>전체 {total}건 · {currentPage}/{pageCount}페이지</span><div><button className="secondary compact" type="button" disabled={currentPage <= 1} onClick={() => setPagination({ key: queryBase, page: currentPage - 1 })}>정책 결과 이전</button><button className="secondary compact" type="button" disabled={currentPage >= pageCount} onClick={() => setPagination({ key: queryBase, page: currentPage + 1 })}>정책 결과 다음</button></div></div>}</>}
    {result.analysisMetrics && Object.keys(result.analysisMetrics).length > 0 && <><h3>리비전 분석 지표</h3><dl className="native-policy-metrics">{Object.entries({ componentCount: "구성요소", vulnerableComponentCount: "취약 구성요소", vulnerabilityCount: "원시 취약점 발견", effectiveVulnerabilityCount: "VEX 적용 후 취약점", vexSuppressedCount: "VEX 영향 없음·오탐", kevCount: "KEV 발견", policyFailCount: "정책 위반", policyWarnCount: "정책 경고", policyInfoCount: "정책 정보", policySuppressedCount: "정책 예외·VEX 적용" }).map(([key, name]) => {
      const value = key === "vulnerableComponentCount"
        ? (analysisAvailable(result) ? result.vulnerableComponentCount : null)
        : result.analysisMetrics?.[key];
      return <div key={key}><dt>{name}</dt><dd>{typeof value === "number" ? value.toLocaleString() : "-"}</dd></div>;
    })}</dl><p className="policy-metrics-note">평가 시각: {result.analysisMetrics.evaluatedAt ? formatSeoulDateTime(String(result.analysisMetrics.evaluatedAt)) : "-"} · 데이터 기준일: {String(result.analysisMetrics.dataAsOf || "확인 필요")} · Grype: {String(result.analysisMetrics.toolVersion || "확인 필요")}</p>{result.analysisMetrics.policyDataComplete === false && <p className="drawer-error">일부 정책 데이터가 없습니다. 평가 근거의 데이터 경고를 확인하세요.</p>}</>}
  </section>;
}

export function AnalysisPolicyHistory({ analysis, runId }: { analysis: AnalysisRevisionSummary; runId: string }) {
  const [open, setOpen] = useState(false);
  return <details className="analysis-policy-history" onToggle={(event) => setOpen(event.currentTarget.open)}><summary>이 리비전의 정책 결과</summary>{open && <NativePolicyResult result={{ ...analysis, policyViolationCount: analysis.policyCount ?? 0 }} runId={runId} analysisId={analysis.id} />}</details>;
}

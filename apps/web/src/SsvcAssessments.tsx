import { FlowSelect } from "./ScrollingSelect";
import { useEffect, useState, type FormEvent } from "react";
import { previewMode } from "./api";
import { formatSeoulDateTime } from "./format";
import { WorkflowPagination } from "./ReanalysisSchedule";
import { fetchSsvcAssessments, submitSsvcAssessment, type SsvcAssessmentInput, type SsvcInputs, type SsvcResult } from "./ssvcApi";

const outcomes: Record<string, string> = {
  defer: "Defer · 보류", scheduled: "Scheduled · 정기 조치",
  "out-of-cycle": "Out-of-Cycle · 일정 외 우선 조치", immediate: "Immediate · 즉시 대응",
};
const inputDefinitions: { name: keyof SsvcInputs; label: string; options: [string, string][] }[] = [
  { name: "exploitation", label: "악용 상태", options: [["none", "악용·공개 PoC 근거 없음"], ["public poc", "공개 PoC·알려진 악용 방법 있음"], ["active", "실제 악용 근거 있음"]] },
  { name: "systemExposure", label: "시스템 노출", options: [["small", "제한적 · 로컬 또는 엄격 통제"], ["controlled", "통제됨 · 접근 제한과 완화 조치"], ["open", "개방됨 · 널리 접근 가능한 네트워크"]] },
  { name: "automatable", label: "악용 자동화 가능성", options: [["no", "자동화 어려움"], ["yes", "악용 과정 자동화 가능"]] },
  { name: "humanImpact", label: "업무·안전 영향", options: [["low", "낮음"], ["medium", "중간"], ["high", "높음"], ["very high", "매우 높음"]] },
];
const emptyResult: SsvcResult = { items: [], total: 0, page: 1, size: 20, model: "ssvc:DT_DP:1.0.0", revisionId: null, analysisReady: false, archived: false };
const errorText = (error: unknown) => error instanceof Error ? error.message : "SSVC 요청에 실패했습니다.";
const staleLabels: Record<string, string> = { model_changed: "결정 모델·결정표 변경", analysis_changed: "분석 변경", evidence_changed: "취약점 근거·데이터 변경", analysis_data_outdated: "새 취약점 자료로 재분석 필요", review_due: "재평가 기한 경과" };

function componentIdentity(finding: Record<string, unknown>): string {
  let component = String(finding.component || "");
  const version = String(finding.version || finding.componentVersion || "");
  if (!component.startsWith("pkg:") && version && !component.endsWith("@" + version)) component += "@" + version;
  return component;
}

export function SsvcAssessmentsPanel({ runId, findings, canManage }: { runId: string; findings: Record<string, unknown>[]; canManage: boolean }) {
  const [result, setResult] = useState<SsvcResult>(emptyResult);
  const [page, setPage] = useState(1);
  const [reload, setReload] = useState(0);
  const [load, setLoad] = useState<"loading" | "ready" | "error">(previewMode ? "ready" : "loading");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const choices = findings.filter(finding => finding.component && (finding.canonicalId || finding.id));
  const editable = canManage && !previewMode && load === "ready" && result.analysisReady && !result.archived;

  useEffect(() => {
    if (previewMode) return;
    let active = true;
    setLoad("loading");
    void fetchSsvcAssessments(runId, page).then(value => {
      if (active) { setResult(value); setLoad("ready"); }
    }).catch((error: unknown) => {
      if (active) { setMessage(errorText(error)); setLoad("error"); }
    });
    return () => { active = false; };
  }, [runId, page, reload]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!editable || !result.revisionId) return;
    const form = event.currentTarget;
    const values = new FormData(form);
    const finding = choices[Number(values.get("finding"))];
    if (!finding) return;
    const inputs = Object.fromEntries(inputDefinitions.map(definition => [definition.name, String(values.get(definition.name) || "") || null])) as SsvcInputs;
    const body: SsvcAssessmentInput = {
      component: componentIdentity(finding), vulnerabilityId: String(finding.canonicalId || finding.id),
      expectedRevisionId: result.revisionId, inputs, rationale: String(values.get("rationale") || ""),
      references: String(values.get("references") || "").split("\n").map(value => value.trim()).filter(Boolean),
    };
    const reviewAt = String(values.get("reviewAt") || "");
    if (reviewAt) {
      const date = new Date(reviewAt);
      if (!Number.isFinite(date.getTime()) || date.getTime() <= Date.now()) { setMessage("재평가 기한은 미래여야 합니다."); return; }
      body.reviewAt = date.toISOString();
    }
    setBusy(true); setMessage("");
    try {
      const saved = await submitSsvcAssessment(runId, body);
      setMessage(saved.outcome ? `SSVC 판단을 저장했습니다: ${outcomes[saved.outcome] || saved.outcome}` : "미평가 사유를 저장했습니다. 입력이 모두 확인되면 새 판단을 추가하세요.");
      form.reset(); setPage(1); setReload(value => value + 1);
    } catch (error) { setMessage(errorText(error)); }
    finally { setBusy(false); }
  }

  return <section className="workflow-panel tracker-view" aria-label="SSVC 대응 우선순위">
    <div className="detail-table-heading"><h3>SSVC · 대응 우선순위</h3><button className="secondary compact" disabled={busy || previewMode} onClick={() => setReload(value => value + 1)}>SSVC 새로고침</button></div>
    <p>CERT/CC Deployer {result.model} · 모든 판단은 내부 결정표로 계산합니다. 같은 취약점도 서비스·환경에 따라 다르게 평가하세요. KEV 비등재·낮은 EPSS만으로 악용 근거 없음을 판단하지 마세요.</p>
    <details><summary>업무·안전 영향 입력 기준</summary><p>핵심 업무 기능(MEF)과 조직 전체 임무 실패를 구분하세요. 안전 영향과 업무 영향을 검토해 아래 조합을 선택하고 근거·가정을 기록합니다.</p><ul>
      <li>낮음: 안전 영향이 무시할 수준이며 업무 기능이 저하되거나 심각하게 제한됨.</li>
      <li>중간: 안전 영향이 무시할 수준이지만 핵심 업무 기능이 실패하거나, 경미한 안전 영향과 업무 기능 저하·심각한 제한이 함께 있음.</li>
      <li>높음: 중대한 안전 영향과 업무 기능 저하·심각한 제한이 함께 있거나, 경미한 안전 영향과 핵심 업무 기능 실패가 함께 있음.</li>
      <li>매우 높음: 재난적 안전 영향 또는 조직 전체 임무 실패.</li>
    </ul></details>
    {previewMode && <p className="preview-note">미리보기에서는 실제 SSVC 조회·저장을 실행하지 않습니다.</p>}
    {message && <p className="form-message" role="status">{message}</p>}
    {canManage && !previewMode && <form onSubmit={event => void submit(event)}><fieldset className="workflow-form ssvc-assessment-form" disabled={!editable || busy || !choices.length}>
      <legend>현재 페이지의 취약점 평가</legend>
      <div className="ssvc-select-row">
        <label>대상 취약점<FlowSelect name="finding" aria-label="SSVC 대상 취약점">{choices.map((finding, index) => <option key={index} value={index}>{String(finding.canonicalId || finding.id)} · {String(finding.component)}</option>)}</FlowSelect></label>
        {inputDefinitions.map(definition => <label key={definition.name}>{definition.label}<FlowSelect name={definition.name} aria-label={`SSVC ${definition.label}`} defaultValue=""><option value="">미확인 · 미평가로 저장</option>{definition.options.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</FlowSelect></label>)}
      </div>
      <div className="ssvc-input-row">
        <label>판단 근거·가정 또는 미평가 사유<textarea name="rationale" aria-label="SSVC 판단 근거" required maxLength={10000} rows={3} /></label>
        <label>근거 참조 (줄마다 문서 ID·경로·URL)<textarea name="references" aria-label="SSVC 근거 참조" rows={2} maxLength={20000} /></label>
      </div>
      <label>재평가 기한 (현재 시간대, 선택)<input name="reviewAt" aria-label="SSVC 재평가 기한" type="datetime-local" /></label>
      <button type="submit" className="primary">SSVC 판단 저장</button>
    </fieldset></form>}
    {!previewMode && load === "ready" && !result.analysisReady && <p>최신 분석이 완료된 후 평가할 수 있습니다.</p>}
    {result.archived && <p>보관된 SBOM의 판단 이력입니다.</p>}
    {load === "loading" && <p>SSVC 판단 이력을 불러오는 중입니다.</p>}
    {load === "error" && <p>SSVC 이력을 조회하지 못했습니다. 새로고침으로 재시도하세요.</p>}
    {load === "ready" && result.items.map(item => <article className="table-frame workflow-review" key={item.id}>
      <h4>{item.vulnerabilityId} · {item.outcome ? outcomes[item.outcome] || item.outcome : "미평가"}{item.stale ? " · 재평가 필요" : ""}{item.superseded ? " · 이전 판단" : ""}</h4>
      <p className="mono wrap">{item.component} · {item.componentVersion}</p>
      <p>{item.rationale}</p><p>{item.author} · {formatSeoulDateTime(item.createdAt)} · 재평가 기한 {formatSeoulDateTime(item.reviewAt)}</p>
      {item.stale && <p>변경 근거: {item.staleReasons.map(value => staleLabels[value] || value).join(", ")}. 기존 결과는 당시 판단으로 보존됩니다.</p>}
      <details><summary>입력·근거 스냅샷 보기</summary><p>모델 {item.model} · 결정표 SHA-256 {item.tableSha256}</p><pre className="wrap tracker-raw-code">{JSON.stringify({ inputs: item.inputs, references: item.references, evidence: item.evidence }, null, 2)}</pre></details>
    </article>)}
    {load === "ready" && !result.items.length && <p>저장된 SSVC 판단이 없습니다. 미평가 상태입니다.</p>}
    <WorkflowPagination page={page} total={result.total} pageSize={20} label="SSVC 판단" onPage={setPage} />
  </section>;
}

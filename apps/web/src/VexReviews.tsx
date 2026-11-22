import { RunDetailCard } from "./RunDetailCard";
import { FlowSelect } from "./ScrollingSelect";
import { useEffect, useState, type FormEvent } from "react";
import { commentVexReview, decideVexReview, fetchReviewEvents, fetchVexReviews, importVex, previewMode, submitVexReview } from "./api";
import { formatSeoulDateTime } from "./format";
import { DetailPagination } from "./DetailPagination";
import type { ReviewEvent, VexReview, VexReviewInput, VexState } from "./types";

const states: Record<VexState, string> = { in_triage: "검토 중", exploitable: "영향 있음", not_affected: "영향 없음", false_positive: "오탐", resolved: "해결됨", resolved_with_pedigree: "패치 이력으로 해결됨" };
const statuses = { submitted: "승인 대기", approved: "승인됨", rejected: "반려됨" };
const errorText = (error: unknown) => error instanceof Error ? error.message : "워크플로 요청에 실패했습니다.";
function ReviewCard({ review, username, canManage, canApprove, onChanged }: { review: VexReview; username?: string; canManage: boolean; canApprove: boolean; onChanged: () => void }) {
  const [events, setEvents] = useState<ReviewEvent[] | null>(null);
  const [reason, setReason] = useState("");
  const [comment, setComment] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  async function history() {
    try { setEvents((await fetchReviewEvents(review.id)).items); } catch (error) { setMessage(errorText(error)); }
  }
  async function act(decision?: "approved" | "rejected") {
    setBusy(true); setMessage("");
    try {
      if (decision) { await decideVexReview(review.id, decision, reason); onChanged(); }
      else { await commentVexReview(review.id, comment); setComment(""); await history(); }
    } catch (error) { setMessage(errorText(error)); } finally { setBusy(false); }
  }
  return <article className="table-frame workflow-review"><h4>{review.vulnerabilityId} · {states[review.state]} · {statuses[review.status]}</h4><p className="mono wrap">{review.component}</p><p>요청: {review.author} · {formatSeoulDateTime(review.createdAt)}{review.expired ? " · 만료됨" : ""}{review.expiresAt ? ` · 만료 ${formatSeoulDateTime(review.expiresAt)}` : ""}</p><p>근거: {review.detail}</p>{review.justification && <p>판단 사유: {review.justification}</p>}{review.reviewer && <p>검토자: {review.reviewer} · {review.decisionReason}</p>}
    {review.status === "approved" && <p>승인 시점 이후의 새 분석에서 적용됩니다. 기존 리비전의 원시 발견과 지표는 보존됩니다.</p>}
    {canApprove && review.status === "submitted" && (review.author === username ? <p>본인이 요청한 검토는 다른 승인자가 승인해야 합니다.</p> : <div className="workflow-decision"><label>승인·반려 사유<input aria-label={`검토 ${review.id} 결정 사유`} value={reason} onChange={(event) => setReason(event.target.value)} required maxLength={2000} /></label><button className="primary compact" disabled={busy || !reason.trim()} onClick={() => void act("approved")}>검토 승인</button><button className="danger compact" disabled={busy || !reason.trim()} onClick={() => void act("rejected")}>검토 반려</button></div>)}
    <button className="secondary compact" onClick={() => void history()}>검토 이력 보기</button>{events && <ul className="paths">{events.map((event) => <li key={event.id}>{formatSeoulDateTime(event.createdAt)} · {event.actor || event.author} · {event.kind || event.type} · {event.comment || event.detail}</li>)}</ul>}{canManage && <form className="workflow-decision" onSubmit={(event) => { event.preventDefault(); void act(); }}><label>검토 의견<input aria-label={`검토 ${review.id} 의견`} value={comment} onChange={(event) => setComment(event.target.value)} required maxLength={2000} /></label><button className="secondary compact" disabled={busy || !comment.trim()}>의견 등록</button></form>}{message && <p className="form-message" role="status">{message}</p>}</article>;
}
export function VexReviewsPanel({ runId, findings, username, canManage, canApprove }: { runId: string; findings: Record<string, unknown>[]; username?: string; canManage: boolean; canApprove: boolean }) {
  const [reviews, setReviews] = useState<{items: VexReview[];total:number}>({items:[],total:0});
  const [loadState, setLoadState] = useState<"loading" | "ready" | "error">(previewMode ? "ready" : "loading");
  const [page, setPage] = useState(1);
  const [reload, setReload] = useState(0);
  const [state, setState] = useState<VexState>("in_triage");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const editable = canManage && !previewMode;
  const choices = findings.filter((finding) => finding.component && (finding.canonicalId || finding.id));
  useEffect(() => {
    if (previewMode) return;
    let active = true;
    setLoadState("loading");
    void fetchVexReviews(runId, page).then((value) => { if (active) { setReviews(value); setLoadState("ready"); } }).catch((error: unknown) => { if (active) { setMessage(errorText(error)); setLoadState("error"); } });
    return () => { active = false; };
  }, [runId, page, reload]);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = event.currentTarget; const values = new FormData(form); const finding = choices[Number(values.get("finding"))];
    if (!finding || !editable) return;
    const version = String(finding.version || "");
    const component = String(finding.component) + (finding.oracleHomeEvidence && version ? `@${version}` : "");
    const body: VexReviewInput = { component, vulnerabilityId:String(finding.canonicalId || finding.id), state, detail:String(values.get("detail")), justification:String(values.get("justification") || ""), response:String(values.get("response") || "").split(",").map((value) => value.trim()).filter(Boolean) };
    const expiry = String(values.get("expiresAt") || "");
    if (expiry) { const date = new Date(expiry); if (!Number.isFinite(date.getTime()) || date.getTime() <= Date.now()) { setMessage("만료 시각은 미래여야 합니다."); return; } body.expiresAt = date.toISOString(); }
    setBusy(true); setMessage("");
    try { await submitVexReview(runId, body); setMessage("검토 요청을 제출했습니다. 다른 승인자의 승인 후 새 분석부터 반영됩니다."); form.reset(); setState("in_triage"); setReload((value) => value + 1); } catch (error) { setMessage(errorText(error)); } finally { setBusy(false); }
  }
  async function upload(file?: File) {
    if (!file || !editable) return;
    setBusy(true); setMessage("");
    try { await importVex(runId, JSON.parse(await file.text())); setMessage("CycloneDX VEX를 검토 요청으로 가져왔습니다. 자동 승인되지 않습니다."); setReload((value) => value + 1); } catch (error) { setMessage(errorText(error)); } finally { setBusy(false); }
  }
  return <RunDetailCard className="workflow-panel tracker-view" title="VEX · 취약점 검토" label="VEX 검토 워크플로" actions={!previewMode && <a className="secondary compact" href={`/api/v1/sbom-runs/${encodeURIComponent(runId)}/vex`}>CycloneDX VEX 내려받기</a>}><p>영향 없음·오탐은 근거와 다른 승인자의 승인이 필요합니다. 승인된 유효 판단은 새 분석에서 반영하고 원시 취약점 발견은 보존합니다.</p>{previewMode && <p className="preview-note">샘플 모드에서는 검토·승인·VEX 가져오기를 실행하지 않습니다.</p>}{message && <p className="form-message" role="status">{message}</p>}
    {editable && <><form onSubmit={(event) => void submit(event)}><fieldset disabled={busy || !choices.length} className="workflow-form vex-review-form"><legend>현재 페이지의 취약점으로 검토 요청</legend><div className="vex-select-row"><label>대상 취약점<FlowSelect name="finding" aria-label="VEX 대상 취약점">{choices.map((finding, index) => <option key={index} value={index}>{String(finding.canonicalId || finding.id)} · {String(finding.component)}</option>)}</FlowSelect></label><label>VEX 상태<FlowSelect aria-label="VEX 상태" value={state} onChange={(event) => setState(event.target.value as VexState)}>{Object.entries(states).map(([value,label]) => <option key={value} value={value}>{label}</option>)}</FlowSelect></label><label>판단 사유<FlowSelect name="justification" aria-label="VEX 판단 사유" required={state === "not_affected" || state === "false_positive"}><option value="">선택</option>{["code_not_present","code_not_reachable","requires_configuration","requires_dependency","requires_environment","protected_by_compiler","protected_at_runtime","protected_at_perimeter","protected_by_mitigating_control"].map((value) => <option key={value}>{value}</option>)}</FlowSelect></label></div><div className="vex-input-row"><label>증거·상세 근거<textarea name="detail" aria-label="VEX 증거" rows={3} required maxLength={10000} /></label><label>대응 (쉼표 구분)<input name="response" placeholder="update, rollback, workaround_available" /></label><label>만료 시각 (현재 시간대, 선택)<input name="expiresAt" type="datetime-local" /></label></div><button className="primary" type="submit">검토 요청 제출</button></fieldset></form>{!choices.length && <p>현재 취약점 페이지에 검토할 발견이 없습니다.</p>}<label>CycloneDX VEX 가져오기<input type="file" accept="application/json,.json" aria-label="CycloneDX VEX 가져오기" disabled={busy} onChange={(event) => { void upload(event.target.files?.[0]); event.target.value = ""; }} /></label></>}
    {loadState === "ready" && reviews.items.map((review) => <ReviewCard key={review.id} review={review} username={username} canManage={editable} canApprove={canApprove && !previewMode} onChanged={() => setReload((value) => value + 1)} />)}{loadState === "loading" ? <p>검토 요청을 불러오는 중입니다.</p> : loadState === "error" ? <button className="secondary" onClick={() => setReload((value) => value + 1)}>검토 요청 다시 불러오기</button> : !reviews.items.length && <p>등록된 검토 요청이 없습니다.</p>}<DetailPagination page={page} total={reviews.total} label="VEX 검토" pageSize={10} onPage={setPage} /></RunDetailCard>;
}

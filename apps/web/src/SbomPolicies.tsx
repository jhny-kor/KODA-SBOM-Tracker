import { FlowSelect } from "./ScrollingSelect";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { fetchSbomPolicies, previewMode, updateSbomPolicies, validateSbomPolicyExpression } from "./api";
import { ScopeSelect } from "./ReanalysisSchedule";
import { formatSeoulDateTime } from "./format";
import type { SbomPolicyDocument, SbomPolicyException, SbomPolicyRule, CatalogItem } from "./types";

const kinds: Record<SbomPolicyRule["kind"], string> = {
  severity: "취약점 심각도", kev: "KEV 등재", license_denied: "금지 라이선스",
  license_unknown: "라이선스 확인 필요", component_denied: "금지 구성요소", cel: "CEL 고급 조건",
};
const emptyRule = (): SbomPolicyRule => ({ id: `rule-${crypto.randomUUID()}`, name: "새 정책", kind: "severity", enabled: true, action: "fail", values: ["critical"] });

export function SbomPoliciesPanel({ canManage, services = [], environments = [] }: { canManage: boolean; services?: CatalogItem[]; environments?: CatalogItem[] }) {
  const [document, setDocument] = useState<SbomPolicyDocument | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [validation, setValidation] = useState<Record<string, string>>({});
  const validationRequests = useRef<Record<string, number>>({});
  const editable = canManage && !previewMode;
  useEffect(() => {
    let active = true;
    void fetchSbomPolicies().then((value) => { if (active) setDocument(value); }).catch((error: unknown) => {
      if (active) setMessage(error instanceof Error ? error.message : "정책을 불러오지 못했습니다.");
    });
    return () => { active = false; };
  }, []);
  function changeRule(id: string, update: Partial<SbomPolicyRule>) {
    validationRequests.current[id] = (validationRequests.current[id] || 0) + 1;
    setValidation((current) => ({...current, [id]: ""}));
    setDocument((current) => current && ({ ...current, rules: current.rules.map((rule) => rule.id === id ? { ...rule, ...update } : rule) }));
  }
  async function validate(rule: SbomPolicyRule) {
    const token = (validationRequests.current[rule.id] || 0) + 1;
    validationRequests.current[rule.id] = token;
    setValidation((current) => ({...current, [rule.id]: "검증 중…"}));
    try {
      const result = await validateSbomPolicyExpression(rule.expression || "", rule.target || "vulnerability");
      if (validationRequests.current[rule.id] === token) setValidation((current) => ({...current, [rule.id]: result.valid ? `CEL 컴파일 성공 · ${result.runtime || "CEL"}. 실제 일치 여부는 분석에서 평가합니다.` : "CEL 검증 실패"}));
    } catch (error) {
      if (validationRequests.current[rule.id] === token) setValidation((current) => ({...current, [rule.id]: `CEL 검증 실패: ${error instanceof Error ? error.message : "알 수 없는 오류"}`}));
    }
  }
  async function reload() {
    setBusy(true); setMessage("");
    try { setDocument(await fetchSbomPolicies()); }
    catch (error) { setMessage(error instanceof Error ? error.message : "정책을 불러오지 못했습니다."); }
    finally { setBusy(false); }
  }
  async function save() {
    if (!document || !editable) return;
    setBusy(true); setMessage("");
    try {
      const cleaned = { ...document, rules: document.rules.map((rule) => ({ ...rule, values: rule.values.filter((value) => value.trim()) })) };
      if (cleaned.rules.some((rule) => (rule.kind === "cel" && !rule.expression?.trim()) || !rule.name.trim() || (["severity", "license_denied", "component_denied"].includes(rule.kind) && !rule.values.length))) throw new Error("정책 이름과 필요한 조건 값을 입력하세요.");
      const saved = await updateSbomPolicies(cleaned);
      setDocument(saved); setMessage(`정책 v${saved.version}을 저장했습니다. 새 분석 리비전부터 적용됩니다.`);
    } catch (error) { setMessage(error instanceof Error ? error.message : "정책 저장에 실패했습니다."); }
    finally { setBusy(false); }
  }
  function addException(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const values = new FormData(event.currentTarget);
    const expiry = new Date(String(values.get("expiresAt")));
    if (!Number.isFinite(expiry.getTime()) || expiry.getTime() <= Date.now()) { setMessage("예외 만료일은 미래 시각이어야 합니다."); return; }
    const vulnerabilityId = String(values.get("vulnerabilityId") || "").trim();
    const runId = String(values.get("runId") || "").trim();
    const exception: SbomPolicyException = {
      id: `exception-${crypto.randomUUID()}`, ruleId: String(values.get("ruleId")), component: String(values.get("component")).trim(),
      ...(vulnerabilityId ? { vulnerabilityId } : {}), ...(runId ? {runId} : {}), reason: String(values.get("reason")).trim(), expiresAt: expiry.toISOString(),
    };
    setDocument((current) => current && ({ ...current, exceptions: [...current.exceptions, exception] }));
    event.currentTarget.reset();
  }
  return <div className="settings-panel sbom-policy-panel" id="settings-panel-sbom-policies" role="tabpanel" aria-labelledby="settings-tab-sbom-policies">
    <div className="settings-panel-heading"><div><h2>SBOM 정책{document ? ` · v${document.version}` : ""}</h2><p>Grype DB 분석과 SBOM 정보로 KODA가 직접 평가합니다. 정책 변경은 새 분석 리비전에 적용되며 기존 결과는 보존됩니다.</p></div>
      <div className="button-row"><button className="secondary" type="button" disabled={busy} onClick={() => void reload()}>다시 불러오기</button>{canManage && <button className="primary" type="button" disabled={!editable || busy || !document} onClick={() => void save()}>{previewMode ? "샘플 정책 · 저장 안 함" : busy ? "저장 중…" : "정책 버전 저장"}</button>}</div></div>
    {previewMode && <p className="preview-note" role="note">샘플 정책입니다. 실제 저장이나 정책 평가는 실행하지 않습니다.</p>}
    {message && <p className="form-message" role="status">{message}</p>}
    {!document ? <p>{message ? "정책을 불러오지 못했습니다. 다시 불러오기로 재시도할 수 있습니다." : "정책을 불러오는 중입니다."}</p> : <>
      <p>최종 변경: {document.createdAt ? formatSeoulDateTime(document.createdAt) : "샘플"} · {document.createdBy || "-"}</p>
      <div className="policy-rules">{document.rules.map((rule, index) => <fieldset className="table-frame policy-rule" key={rule.id} disabled={!editable || busy}>
        <legend>규칙 {index + 1}</legend>
        <label>정책 이름<input aria-label={`규칙 ${index + 1} 이름`} value={rule.name} maxLength={128} onChange={(event) => changeRule(rule.id, { name: event.target.value })} /></label>
        <label>판정 조건<FlowSelect aria-label={`규칙 ${index + 1} 조건`} value={rule.kind} onChange={(event) => changeRule(rule.id, { kind: event.target.value as SbomPolicyRule["kind"], values: [], expression: "", legacyConditions: [] })}>{Object.entries(kinds).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</FlowSelect></label>
        <label>처리<FlowSelect aria-label={`규칙 ${index + 1} 처리`} value={rule.action} onChange={(event) => changeRule(rule.id, { action: event.target.value as "fail" | "warn" | "info" })}><option value="fail">위반</option><option value="warn">경고</option><option value="info">정보</option></FlowSelect></label>
        <label className="checkbox-label"><input aria-label={`규칙 ${index + 1} 사용`} type="checkbox" checked={rule.enabled} onChange={(event) => changeRule(rule.id, { enabled: event.target.checked })} />사용</label>
        {["severity", "license_denied", "component_denied"].includes(rule.kind) && <label className="policy-values">조건 값 (쉼표로 구분)<input aria-label={`규칙 ${index + 1} 조건 값`} value={rule.values.join(", ")} onChange={(event) => changeRule(rule.id, { values: event.target.value.split(",").map((item) => item.trim()) })} placeholder={rule.kind === "severity" ? "critical, high" : rule.kind === "license_denied" ? "AGPL-3.0-only" : "pkg:pypi/example@1.0 또는 example@1.0"} /></label>}
        <div className="workflow-scopes policy-values"><ScopeSelect label={`규칙 ${index + 1} 서비스 범위`} items={services} value={rule.serviceIds || []} onChange={(serviceIds) => changeRule(rule.id, {serviceIds})} /><ScopeSelect label={`규칙 ${index + 1} 환경 범위`} items={environments} value={rule.environmentIds || []} onChange={(environmentIds) => changeRule(rule.id, {environmentIds})} /><label>릴리스 범위 (쉼표 구분, 비우면 전체)<input aria-label={`규칙 ${index + 1} 릴리스 범위`} value={(rule.releaseVersions || []).join(", ")} onChange={(event) => changeRule(rule.id, {releaseVersions:event.target.value.split(",").map((value) => value.trim()).filter(Boolean)})} /></label></div>
        {!!rule.runIds?.length && <details className="policy-values"><summary>고정 회차 범위 {rule.runIds.length}개 · 이관 시점의 원본 범위</summary><p>아래 회차와 서비스·환경·릴리스 조건을 모두 충족할 때만 적용합니다. 이후 새 원본 프로젝트는 원본을 다시 이관해야 범위에 포함됩니다.</p><pre className="migration-report">{rule.runIds.join("\n")}</pre></details>}
        <div className="policy-values workflow-form"><label className="checkbox-label"><input type="checkbox" checked={!!rule.projectScope} onChange={event=>changeRule(rule.id,{projectScope:event.target.checked ? {sourceId:"native",projectIds:[],tags:[],includeChildren:false,onlyLatest:false} : null})}/>동적 프로젝트 범위 사용</label>
          {rule.projectScope && <><label>프로젝트 원본 ID<input aria-label={`규칙 ${index+1} 프로젝트 원본`} value={rule.projectScope.sourceId} onChange={event=>changeRule(rule.id,{projectScope:{...rule.projectScope!,sourceId:event.target.value}})}/></label>
          <label>프로젝트 ID (쉼표 구분)<input aria-label={`규칙 ${index+1} 프로젝트 ID`} value={rule.projectScope.projectIds.join(", ")} onChange={event=>changeRule(rule.id,{projectScope:{...rule.projectScope!,projectIds:event.target.value.split(",").map(value=>value.trim()).filter(Boolean)}})}/></label>
          <label>프로젝트 태그 (쉼표 구분)<input aria-label={`규칙 ${index+1} 프로젝트 태그`} value={rule.projectScope.tags.join(", ")} onChange={event=>changeRule(rule.id,{projectScope:{...rule.projectScope!,tags:event.target.value.split(",").map(value=>value.trim()).filter(Boolean)}})}/></label>
          <label className="checkbox-label"><input type="checkbox" checked={rule.projectScope.includeChildren} onChange={event=>changeRule(rule.id,{projectScope:{...rule.projectScope!,includeChildren:event.target.checked}})}/>하위 프로젝트 포함</label>
          <label className="checkbox-label"><input type="checkbox" checked={rule.projectScope.onlyLatest} onChange={event=>changeRule(rule.id,{projectScope:{...rule.projectScope!,onlyLatest:event.target.checked}})}/>최신 프로젝트 버전만</label><p>같은 원본에서 프로젝트 또는 태그가 일치하는 범위에 적용합니다. 둘 다 비우면 해당 원본 전체입니다. 계층·태그·최신 표시는 매번 새 분석에서 조회합니다.</p></>}
        </div>
        {!!rule.legacyConditions?.length && <details className="policy-values"><summary>고급 조건 계산 근거 {rule.legacyConditions.length}개</summary><p>달력 기간·단위별 버전 거리·SPDX 조건을 검증된 보조 계산으로 처리합니다. 필요한 데이터가 없으면 통과로 간주하지 않습니다.</p><pre className="migration-report">{JSON.stringify(rule.legacyConditions,null,2)}</pre></details>}
        {rule.kind === "cel" && <div className="policy-values workflow-cel"><label>CEL 평가 대상<FlowSelect aria-label={`규칙 ${index + 1} CEL 대상`} disabled={!!rule.legacyConditions?.length} value={rule.target || "vulnerability"} onChange={(event) => changeRule(rule.id, {target:event.target.value as SbomPolicyRule["target"]})}><option value="vulnerability">취약점별</option><option value="component">구성요소별</option><option value="project">프로젝트 전체</option></FlowSelect></label><label>위반으로 판정할 CEL 조건<textarea aria-label={`규칙 ${index + 1} CEL 조건`} maxLength={8192} rows={4} value={rule.expression || ""} onChange={(event) => changeRule(rule.id, {expression:event.target.value})} /></label><p>조건이 true인 대상을 위반·경고로 기록합니다. project, environment, release, run, component, vulnerability, now 컨텍스트와 exists/all/map/filter, matches, timestamp/duration 등을 사용할 수 있습니다. CWE는 vulnerability.cwes, EPSS는 vulnerability.epssScore, 단위별 버전 거리는 component.packageMetadata.versionDistanceParts로 조회합니다. 필요한 데이터가 없으면 경고를 기록합니다.</p><code>{rule.target === "component" ? 'has(component.ageDays) && component.ageDays > 365' : rule.target === "project" ? 'project.slug == "orders" && environment.slug == "production"' : 'vulnerability.severity in ["Critical", "High", "critical", "high"] && vulnerability.kev'}</code>{editable && <button className="secondary compact" type="button" disabled={!rule.expression?.trim()} onClick={() => void validate(rule)}>CEL 문법 검증</button>}{validation[rule.id] && <p role="status">{validation[rule.id]}</p>}</div>}
        {editable && <button type="button" className="danger compact" onClick={() => setDocument((current) => current && ({ ...current, rules: current.rules.filter((item) => item.id !== rule.id), exceptions: current.exceptions.filter((item) => item.ruleId !== rule.id) }))}>규칙 삭제</button>}
      </fieldset>)}</div>
      {!document.rules.length && <p>규칙이 없습니다. 정책 평가 시 적용할 규칙이 없음을 기록합니다.</p>}
      {editable && <button className="secondary" type="button" disabled={busy} onClick={() => setDocument((current) => current && ({ ...current, rules: [...current.rules, emptyRule()] }))}>규칙 추가</button>}
      <h3>정책 예외</h3><p>구성요소 식별자는 정확히 일치해야 합니다. 회차 범위를 지정하면 해당 회차에만 적용합니다. 이관된 무기한 예외는 원본 의미를 보존하며, 만료 시각이 있는 예외는 만료 후 새 평가에서 다시 판정합니다.</p>
      <div className="table-scroll"><table><thead><tr><th>정책</th><th>구성요소 / 취약점</th><th>회차 범위</th><th>사유</th><th>만료 (서울)</th>{editable && <th>작업</th>}</tr></thead><tbody>{document.exceptions.map((exception) => <tr key={exception.id}><td>{document.rules.find((rule) => rule.id === exception.ruleId)?.name || exception.ruleId}</td><td className="mono wrap">{exception.component}<br />{exception.vulnerabilityId || "모든 취약점"}</td><td className="mono wrap">{exception.runId || "전체 회차"}</td><td>{exception.reason}</td><td>{exception.expiresAt ? <>{formatSeoulDateTime(exception.expiresAt)}{new Date(exception.expiresAt).getTime() <= Date.now() ? " · 만료" : ""}</> : "만료 없음 (무기한)"}</td>{editable && <td><button className="danger compact" type="button" disabled={busy} onClick={() => setDocument((current) => current && ({ ...current, exceptions: current.exceptions.filter((item) => item.id !== exception.id) }))}>예외 삭제</button></td>}</tr>)}{!document.exceptions.length && <tr><td colSpan={editable ? 6 : 5}>등록한 예외가 없습니다.</td></tr>}</tbody></table></div>
      {editable && <form className="policy-exception-form" onSubmit={addException}><fieldset disabled={busy || !document.rules.length}><legend>예외 추가</legend>
        <label>대상 정책<FlowSelect name="ruleId" aria-label="예외 대상 정책">{document.rules.map((rule) => <option key={rule.id} value={rule.id}>{rule.name}</option>)}</FlowSelect></label>
        <label>구성요소 식별자<input name="component" required maxLength={2048} placeholder="정확한 PURL 또는 구성요소 이름" /></label>
        <label>대상 회차 ID (선택)<input name="runId" maxLength={128} placeholder="비우면 전체 회차" /></label>
        <label>취약점 ID (선택)<input name="vulnerabilityId" maxLength={128} placeholder="CVE-2026-1234" /></label>
        <label>예외 사유<input name="reason" required maxLength={1000} /></label>
        <label>만료 시각 (현재 시간대)<input name="expiresAt" type="datetime-local" required /></label>
        <button className="secondary" type="submit">예외 추가</button>
      </fieldset></form>}
    </>}
  </div>;
}

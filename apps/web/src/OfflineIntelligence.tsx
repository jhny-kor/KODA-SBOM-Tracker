import { FlowSelect } from "./ScrollingSelect";
import { useEffect, useState } from "react";
import { previewMode, request } from "./api";

type Source = {kind: string; id: string; dataDate: string; status: string; sha256: string; sourceUrl: string; maxAgeDays: number};
type Manifest = {sha256: string; sources: Source[]; counts: Record<string, number>};
type Status = {missingKinds?: string[]; current: Manifest; history: {id: string; kind: string; sourceId: string; dataDate: string; records: number; author: string}[]};
type Impact = {coverage?: {page: number; size: number; totalProjects: number; returnedProjects: number; summaryScope: string}; projects: {runId: string; service: string; environment: string; release: string; analysisState: string; findings: number; responseStates: Record<string, number>; overdue: number}[]; uniqueVulnerabilities: number; responseStates: Record<string, number>};
type ReferenceSource = {status?: string; dataDate?: string};
type ReferenceEvidence<T> = {source?: ReferenceSource; record: T};
type ComponentReference = {
  lifecycle?: (ReferenceEvidence<{cycle?: string; eolDate?: string; latestVersion?: string}> & {endOfLife?: boolean})[];
  packageMetadata?: ReferenceEvidence<{latestVersion?: string; status?: string; fetchedAt?: string; expiresAt?: string}>[];
  licenses?: {id: string; status: string}[];
  cpe?: unknown[];
  cpeMatch?: unknown[];
  packageMetadataConflict?: boolean;
};
type Component = {name?: string; version?: string; purl?: string; offlineReference?: ComponentReference};
type OvalEvidence = {evaluation?: {status?: string; reason?: string}};
type Reference = {supplierVexConflict?: boolean; supplierVex?: unknown[]; cwe?: unknown[]; ubuntuOval?: OvalEvidence[]; ssvcRecommendation?: {inputs?: Record<string, unknown>; conflicts?: string[]}};
type Finding = {component?: string; version?: string; componentVersion?: string; canonicalId?: string; id?: string; offlineReference?: Reference};
type Context = {revisionId: string | null; analysisReady: boolean; snapshotChanged: boolean; summary: Manifest; components: Component[]; findings: Finding[]};
type ResponseEvent = {stale?: boolean; id: string; component: string; vulnerabilityId: string; state: string; owner: string; rationale: string; dueAt: string | null};
const base = "/api/v1/offline-intelligence";
const message = (error: unknown) => error instanceof Error ? error.message : String(error);
const sourceState = (source?: ReferenceSource) => source?.status === "fresh" ? "자료 기준일 내" : source?.status === "stale" ? "기준일 경과" : "자료 상태 미확인";
const zonedTimestamp = (value?: string) => value && /(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value)) ? Date.parse(value) : null;
const ovalLabels: Record<string, string> = {affected_review: "영향 있음 (검토 참고)", not_affected_review: "영향 없음 (검토 참고)", unknown: "판정 불가"};
const ovalReasons: Record<string, string> = {exact_ubuntu_platform_required: "정확한 Ubuntu 재고 필요", unsupported_oval_construct: "미지원 OVAL 조건", dpkg_unavailable: "dpkg 없음", unsupported_or_incomplete_inventory: "조건·재고 불충분", context_evaluation_budget_exceeded: "평가 범위 초과"};
function ComponentReferenceTable({components}: {components: Component[]}) {
  return <><h4>구성요소 자료 활용 현황 · 현재 반입 자료</h4><div className="table-scroll tracker-table-scroll" role="region" aria-label="구성요소 자료 가로 스크롤" tabIndex={0}><table className="tracker-evidence-table tracker-evidence-components" aria-label="구성요소별 오프라인 자료 활용"><thead><tr><th>구성요소 / PURL</th><th>지원 종료 근거</th><th>패키지 최신 버전 관측</th><th>SPDX 라이선스 사전</th><th>CPE 사전 / 적용 문자열</th></tr></thead><tbody>{components.map((component, index) => {
    const ref = component.offlineReference;
    return <tr key={`${component.purl || component.name}-${index}`}><td>{component.name || "이름 미확인"} {component.version}<small className="workflow-id">{component.purl || "PURL 미제공"}</small></td>
      <td>{ref?.lifecycle?.length ? ref.lifecycle.map((entry, offset) => <div key={offset}>{entry.endOfLife === true ? "지원 종료" : entry.endOfLife === false ? "지원 종료 아님 (관측)" : "지원 종료 여부 미확인"}{entry.record.eolDate ? ` · ${entry.record.eolDate}` : ""}<small className="workflow-id">{sourceState(entry.source)}</small></div>) : "일치 근거 없음"}</td>
      <td>{ref?.packageMetadata?.length ? ref.packageMetadata.map((entry, offset) => {
        const expiresAt = zonedTimestamp(entry.record.expiresAt), fetchedAt = zonedTimestamp(entry.record.fetchedAt), now = Date.now();
        const expired = expiresAt !== null && expiresAt <= now;
        const eligible = fetchedAt !== null && expiresAt !== null && fetchedAt <= now && now < expiresAt && entry.record.status === "fresh" && entry.source?.status === "fresh";
        return <div key={offset}>{entry.record.latestVersion || "최신 버전 미확인"}<small className="workflow-id">{expired ? "관측값 만료" : eligible ? "유효한 관측 근거" : "최신성·유효기간 미확인"} · {sourceState(entry.source)}</small><small className="workflow-id">원본 상태 {entry.record.status || "미확인"} · 관측 {entry.record.fetchedAt || "미확인"} · 만료 {entry.record.expiresAt || "미확인"}</small></div>;
      }) : "일치 근거 없음"}{ref?.packageMetadataConflict && <div>관측값 충돌 · 수동 검토 필요</div>}</td>
      <td>{ref?.licenses?.length ? ref.licenses.map((entry, offset) => <div key={offset}>{entry.id} · {entry.status === "known" ? "사전 확인" : "사전 근거 없음"}</div>) : "선언된 라이선스 근거 없음"}</td>
      <td>사전 {ref?.cpe?.length || 0}개 / 적용 문자열 {ref?.cpeMatch?.length || 0}개{!ref?.cpe?.length && !ref?.cpeMatch?.length && <small className="workflow-id">일치 근거 없음 · 안전 판정 아님</small>}</td></tr>;
  })}{!components.length && <tr><td colSpan={5}>구성요소 자료가 없습니다. 적용 여부를 확인할 수 없습니다.</td></tr>}</tbody></table></div></>;
}
function OvalSummary({entries}: {entries?: OvalEvidence[]}) {
  if (!entries?.length) return <>OVAL 일치 근거 없음</>;
  return <>{entries.map((entry, index) => {
    const status = entry.evaluation?.status || "unknown";
    const reason = entry.evaluation?.reason || "";
    return <div key={index}>{ovalLabels[status] || "판정 불가"}{status === "unknown" && reason ? ` · ${ovalReasons[reason] || reason}` : ""}</div>;
  })}</>;
}

export function OfflineIntelligencePanel() {
  const [status, setStatus] = useState<Status | null>(null);
  const [impact, setImpact] = useState<Impact | null>(null);
  const [error, setError] = useState("");
  async function loadImpact(page: number) {
    try {setImpact(await request<Impact>(`${base}/impact?page=${page}&size=50`));} catch(e) {setError(message(e));}
  }
  useEffect(() => { if (previewMode) return; let active = true; Promise.all([request<Status>(base), request<Impact>(`${base}/impact`)]).then(([next, projects]) => { if (active) {setStatus(next); setImpact(projects);} }).catch(e => {if (active) setError(message(e));}); return () => {active = false;}; }, []);
  return <section className="card tracker-view"><h3>폐쇄망 참조 자료 현황 · 영향과 대응</h3>
    <p>참조 자료는 설정 → 취약점 데이터에서 서명된 통합 압축파일로 반입·적용합니다. 이 화면에서는 자료별 기준일·유효기간과 영향·대응 현황을 확인합니다. 공급자 VEX 자동 억제와 SSVC 자동 결정은 적용하지 않습니다.</p>
    {previewMode && <p>참조 자료 현황과 대응 기록은 서버 연결 모드에서 확인할 수 있습니다.</p>}
    {error && <p role="alert">{error}</p>}
    {status && <>{Boolean(status.missingKinds?.length) && <p>자료 없음: {status.missingKinds?.join(", ")}</p>}<p>현재 {status.current.sources.length}개 소스 · 자료가 없거나 만료된 경우 최신 근거로 사용하지 않습니다.</p><div className="table-scroll tracker-table-scroll" role="region" aria-label="반입 소스 가로 스크롤" tabIndex={0}><table className="tracker-evidence-table tracker-evidence-sources" aria-label="반입 참조 소스 현황"><thead><tr><th>종류 / 소스</th><th>기준일</th><th>상태 / 유효일</th><th>원본 SHA-256</th></tr></thead><tbody>{status.current.sources.map(source => <tr key={`${source.kind}/${source.id}`}><td>{source.kind} / {source.id}</td><td>{source.dataDate}</td><td>{source.status} / {source.maxAgeDays}</td><td><code>{source.sha256}</code></td></tr>)}</tbody></table></div>
    <details><summary>변경 불가 반입 이력 (최근 100건)</summary>{status.history.map(row => <p key={row.id}>{row.kind} / {row.sourceId} · {row.dataDate} · {row.records}건 · {row.author} · <a href={`${base}/snapshots/${encodeURIComponent(row.id)}/original`} download>검증 원본 내려받기</a></p>)}</details></>}
    {impact && <><h4>프로젝트 영향 · 대응 현황</h4><p>릴리스별 최신 점검 기준 · 현재 페이지 고유 취약점 {impact.uniqueVulnerabilities}개. 미평가·재분석 대기는 analysisState로 표시합니다.</p><div className="table-scroll tracker-table-scroll" role="region" aria-label="프로젝트 영향 가로 스크롤" tabIndex={0}><table className="tracker-evidence-table tracker-evidence-impact" aria-label="프로젝트 영향과 대응 현황"><thead><tr><th>서비스 / 환경 / 릴리스</th><th>분석 상태</th><th>탐지</th><th>대응 상태</th><th>기한 경과</th></tr></thead><tbody>{impact.projects.map(project => <tr key={project.runId}><td>{project.service} / {project.environment} / {project.release}</td><td>{project.analysisState}</td><td>{project.findings}</td><td>{Object.entries(project.responseStates).map(([state,count]) => `${state}: ${count}`).join(", ")}</td><td>{project.overdue}</td></tr>)}</tbody></table></div>{impact.coverage && <p>전체 {impact.coverage.totalProjects}개 릴리스 중 현재 {impact.coverage.returnedProjects}개 · {impact.coverage.page}페이지 (상태 집계는 현재 페이지 기준) <button disabled={impact.coverage.page <= 1} onClick={() => void loadImpact((impact.coverage?.page || 1)-1)}>이전 프로젝트</button><button disabled={impact.coverage.page * impact.coverage.size >= impact.coverage.totalProjects} onClick={() => void loadImpact((impact.coverage?.page || 1)+1)}>다음 프로젝트</button></p>}</>}
  </section>;
}

export function OfflineRunEvidence({runId, canRespond, canViewResponses}: {runId: string; canRespond: boolean; canViewResponses: boolean}) {
  const [context, setContext] = useState<Context | null>(null);
  const [events, setEvents] = useState<ResponseEvent[]>([]);
  const [error, setError] = useState(""); const [busy, setBusy] = useState(false);
  const [target, setTarget] = useState("0"); const [state, setState] = useState("triaged");
  const [owner, setOwner] = useState(""); const [reason, setReason] = useState(""); const [due, setDue] = useState("");
  const url = `/api/v1/sbom-runs/${encodeURIComponent(runId)}`;
  useEffect(() => { if (previewMode) return; let active = true; Promise.all([request<Context>(`${url}/offline-intelligence`), canViewResponses ? request<{items: ResponseEvent[]}>(`${url}/responses`) : Promise.resolve({items: []})]).then(([value, history]) => {if (active) {setContext(value); setEvents(history.items);}}).catch(e => {if (active) setError(message(e));}); return () => {active = false;}; }, [url, canViewResponses]);
  async function save() {
    const finding = context?.findings[Number(target)]; if (!finding || !context?.revisionId) return;
    let component = String(finding.component || ""); const version = String(finding.version || finding.componentVersion || "");
    if (!component.startsWith("pkg:") && version && !component.endsWith(`@${version}`)) component += `@${version}`;
    setBusy(true); setError("");
    try { const row = await request<ResponseEvent>(`${url}/responses`, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({component, vulnerabilityId: finding.canonicalId || finding.id, expectedRevisionId: context.revisionId, state, owner, rationale: reason, dueAt: due ? new Date(due).toISOString() : null})}); setEvents(previous => [row, ...previous]); setReason(""); } catch(e) {setError(message(e));} finally {setBusy(false);}
  }
  return <section className="card offline-run-evidence tracker-view"><h3>오프라인 자료 근거 · 대응 기록</h3>{error && <p role="alert">{error}</p>}
    {context && <><p>{context.snapshotChanged ? "현재 반입 자료가 분석 당시와 다릅니다. 재분석 전의 판정은 과거 근거입니다." : "분석 당시 자료와 현재 자료가 일치합니다."} 공급자 주장과 수명주기 정보는 검토 근거이며 탐지·심각도를 변경하지 않습니다.</p>
    <p>활성 참조 소스 {context.summary.sources.length}개 · 자동 SSVC 결정 없음 · 자동 VEX 억제 없음</p>
    <ComponentReferenceTable components={context.components} />
    <details><summary>구성요소 수명주기 · 패키지 · SPDX · CPE 사전 근거</summary><pre className="tracker-raw-code">{JSON.stringify(context.components.map(value => ({name: value.name, version: value.version, purl: value.purl, evidence: value.offlineReference})), null, 2)}</pre></details>
    <div className="table-scroll tracker-table-scroll" role="region" aria-label="취약점 근거 가로 스크롤" tabIndex={0}><table className="tracker-evidence-table tracker-evidence-findings" aria-label="취약점별 오프라인 자료 활용"><thead><tr><th>취약점 / 구성요소</th><th>공급자 VEX 검토</th><th>SSVC 참고 입력</th><th>CWE / Ubuntu OVAL 검토</th></tr></thead><tbody>{context.findings.map((value,index) => <tr key={index}><td>{value.canonicalId || value.id} / {value.component}</td><td>{value.offlineReference?.supplierVexConflict ? "기존 탐지와 공급자 주장이 충돌합니다. 수동 검토 필요" : `${value.offlineReference?.supplierVex?.length || 0}개 일치 근거`}</td><td>{Object.entries(value.offlineReference?.ssvcRecommendation?.inputs || {}).map(([name, input]) => `${name}: ${String(input)}`).join(", ") || "유효한 악용 근거 없음"} · 최종 판단 필요</td><td>{value.offlineReference?.cwe?.length ? `CWE 분류 ${value.offlineReference.cwe.length}개` : "CWE 근거 없음"}<div><OvalSummary entries={value.offlineReference?.ubuntuOval} /></div></td></tr>)}</tbody></table></div>
    <details><summary>취약점 공급자 VEX 충돌 · CWE · SSVC 추천 근거</summary><pre className="tracker-raw-code">{JSON.stringify(context.findings.map(value => ({id: value.canonicalId || value.id, component: value.component, evidence: value.offlineReference})), null, 2)}</pre></details>
    {canRespond && <form onSubmit={e => {e.preventDefault(); void save();}}><h4>대응 상태 기록</h4><label>대상 <FlowSelect aria-label="대응 대상" value={target} onChange={e => setTarget(e.target.value)}>{context.findings.map((value,index) => <option key={index} value={index}>{value.canonicalId || value.id} / {value.component}</option>)}</FlowSelect></label><label>상태 <FlowSelect aria-label="대응 상태" value={state} onChange={e => setState(e.target.value)}>{["open", "triaged", "in_progress", "mitigated", "accepted", "verification_requested"].map(value => <option key={value}>{value}</option>)}</FlowSelect></label><label>담당자 <input aria-label="대응 담당자" value={owner} required onChange={e => setOwner(e.target.value)} /></label><label>재검토 기한 <input aria-label="대응 기한" type="datetime-local" value={due} onChange={e => setDue(e.target.value)} required={state === "accepted"} /></label><label>대응 근거 <textarea aria-label="대응 근거" value={reason} required onChange={e => setReason(e.target.value)} /></label><button disabled={busy || !context.analysisReady || !context.findings.length}>대응 이력 저장</button><p>mitigated는 담당자의 조치 기록입니다. 해결 검증은 새 점검 결과로 확인합니다.</p></form>}
    </>}
    {canViewResponses && <details><summary>대응 이력 (최근 1000건)</summary>{events.map(row => <p key={row.id}>{row.vulnerabilityId} / {row.component} · {row.state}{row.stale ? " · 재검토 필요" : ""} · {row.owner} · {row.rationale} {row.dueAt && `· 기한 ${row.dueAt}`}</p>)}</details>}
  </section>;
}

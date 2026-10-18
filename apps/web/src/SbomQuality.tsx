import { useDeferredValue, useEffect, useState, type FormEvent } from "react";
import { previewMode } from "./api";
import { formatSeoulDateTime } from "./format";
import { createQualityRevision, DEFAULT_QUALITY_WEIGHTS, fetchEffectiveQualityProfile, fetchQualityIssues, fetchQualityProfile, fetchQualityRevisions, fetchQualityTagProfiles, QUALITY_DOMAINS, qualityExportUrl, saveQualityProfile } from "./quality-api";
import type { EffectiveQualityProfile, QualityDomain, QualityIssue, QualityPage, QualityProfile, QualityRevision, QualitySummary } from "./quality-api";
import "./quality.css";

const statusLabels: Record<string, string> = { pass: "통과", warn: "경고", fail: "기준 미달", failed: "진단 실패" };
const severityLabels: Record<string, string> = { error: "오류", warning: "경고", info: "정보" };
const fieldLabels: Record<string, string> = { identity: "식별", graph: "의존성 관계", license: "라이선스", integrity: "무결성", provenance: "출처·시각", timestamp: "생성 시각" };
const fieldStatusLabels: Record<string, string> = { available: "확인 가능", missing: "누락", invalid: "잘못된 값", not_applicable: "적용 불가", declared_only: "선언된 해시만 검사 (실제 파일 대조 전)", syntax_only: "구문 검사 (법률상 호환성 판정 전)" };
function valueLabel(value: unknown): string {
  if (value === null || value === undefined || value === "") return "없음";
  return typeof value === "string" ? value : JSON.stringify(value);
}
function delta(value: number): string { return value > 0 ? `+${value}` : String(value); }
const inheritanceLabels: Record<string, string> = { project: "프로젝트 직접 기준", tag: "프로젝트 태그 기준", parent: "부모 프로젝트 기준", parent_tag: "부모 태그 기준", global: "공통 기본 기준" };
function InheritanceEvidence({ profile }: { profile: QualityProfile }) {
  const resolution = profile.resolution;
  if (!resolution) return null;
  return <div className="quality-inheritance"><p><strong>적용 경로: {inheritanceLabels[resolution.kind] || resolution.kind}</strong>{(resolution.depth ?? 0) > 0 ? ` · 상위 ${resolution.depth}단계` : ""}{profile.tag ? ` · 태그 ${profile.tag} (우선순위 ${profile.priority ?? 0})` : ""}</p>
    {resolution.inheritedFrom && <p>기준을 제공한 프로젝트: <code>{resolution.inheritedFrom}</code></p>}
    {resolution.sourceId && <p>원본 범위: <code>{resolution.sourceId}</code></p>}
    {!!resolution.chain?.length && <details><summary>상속 경로·태그 근거</summary><ol>{resolution.chain.map(node => <li key={node.projectId}><code>{node.sourceProjectId}</code> · 직접 기준 v{node.profileVersion}{node.profileInherited ? " (상속 사용)" : ""} · 태그 {node.tags.length ? node.tags.join(", ") : "없음"}</li>)}</ol></details>}
  </div>;
}
function QualityScore({ summary }: { summary: QualitySummary }) {
  const details = summary.scoreDetails;
  return <div className="quality-score" aria-label="가중 품질 점수">
    <p><strong>{summary.score === null ? "점수 없음 · 이전 엔진 또는 적용 불가" : `가중 품질 점수 ${summary.score.toFixed(2)} / 100`}</strong></p>
    {summary.minScore !== undefined && summary.minScore !== null && <p>점수 하한 {summary.minScore.toFixed(2)}점{summary.scoreThresholdViolated ? " · 점수 하한 미달" : ""}</p>}
    {!!summary.blockingIssueCount && <p className="quality-issue-error">필수 오류 {summary.blockingIssueCount}건 · 높은 점수로 필수 오류를 상쇄할 수 없습니다.</p>}
    {details?.domains && <><div className="table-scroll"><table><thead><tr><th>영역</th><th>영역 점수</th><th>통과 / 검사 단위</th><th>설정 가중치</th><th>합산 기여점수</th></tr></thead><tbody>{QUALITY_DOMAINS.map(domain => {
      const item = details.domains?.[domain];
      if (!item) return null;
      return <tr key={domain}><th>{fieldLabels[domain]}</th><td>{item.applicable === false || item.score === null ? "적용 불가" : item.score.toFixed(2)}</td><td>{item.numerator ?? item.passed ?? 0} / {item.denominator ?? item.total ?? 0}</td><td>{item.weight ?? 0}%</td><td>{item.weightedContribution === null || item.weightedContribution === undefined ? "제외" : item.weightedContribution.toFixed(2)}</td></tr>;
    })}</tbody></table></div><p className="muted">적용 불가 영역은 합산 분모에서 제외합니다. 누락된 필수 자료는 정상으로 계산하지 않습니다. 점수는 KODA 기준이며 공식 표준 인증 점수가 아닙니다.</p></>}
  </div>;
}
const emptyIssues: QualityPage<QualityIssue> = { items: [], total: 0, page: 1, size: 20 };

export function SbomQualityPanel({ runId, canRerun, canViewProfiles, canManage, archived = false, analysisId = "" }: {
  runId: string; canRerun: boolean; canViewProfiles: boolean; canManage: boolean; archived?: boolean; analysisId?: string;
}) {
  if (previewMode) return <section className="quality-panel"><h3>SBOM 품질</h3><p className="muted">품질 진단은 서버에 저장된 SBOM에서 실행합니다. 미리보기에서는 진단 결과를 생성하지 않습니다.</p></section>;
  return <QualityResults key={runId} runId={runId} canRerun={canRerun} canViewProfiles={canViewProfiles} canManage={canManage} archived={archived} analysisId={analysisId} />;
}

function QualityResults({ runId, canRerun, canViewProfiles, canManage, archived, analysisId }: {
  runId: string; canRerun: boolean; canViewProfiles: boolean; canManage: boolean; archived: boolean; analysisId: string;
}) {
  const [revisions, setRevisions] = useState<QualityRevision[]>([]);
  const [historyPage, setHistoryPage] = useState(1);
  const [historyTotal, setHistoryTotal] = useState(0);
  const [selectedId, setSelectedId] = useState("");
  const [issues, setIssues] = useState(emptyIssues);
  const [page, setPage] = useState(1);
  const [severity, setSeverity] = useState("");
  const [ruleId, setRuleId] = useState("");
  const deferredRule = useDeferredValue(ruleId.trim());
  const [refresh, setRefresh] = useState(0);
  const [loading, setLoading] = useState(true);
  const [issuesLoading, setIssuesLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [tab, setTab] = useState<"results" | "profile">("results");
  const selected = revisions.find(item => item.id === selectedId) || null;
  useEffect(() => {
    let cancelled = false;
    setLoading(true); setError("");
    void fetchQualityRevisions(runId, historyPage).then(result => {
      if (cancelled) return;
      setRevisions(result.items); setHistoryTotal(result.total);
      setSelectedId(result.items[0]?.id || ""); setPage(1);
    }).catch(reason => { if (!cancelled) { setError(reason instanceof Error ? reason.message : "품질 이력을 불러오지 못했습니다."); setRevisions([]); setSelectedId(""); } })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [runId, historyPage, refresh, analysisId]);
  useEffect(() => {
    let cancelled = false;
    if (!selectedId) { setIssues(emptyIssues); return; }
    setIssuesLoading(true); setError("");
    void fetchQualityIssues(runId, selectedId, page, severity, deferredRule).then(result => {
      if (!cancelled) setIssues(result);
    }).catch(reason => { if (!cancelled) { setError(reason instanceof Error ? reason.message : "품질 이슈를 불러오지 못했습니다."); setIssues(emptyIssues); } })
      .finally(() => { if (!cancelled) setIssuesLoading(false); });
    return () => { cancelled = true; };
  }, [runId, selectedId, page, severity, deferredRule, refresh]);
  async function rerun() {
    setBusy(true); setError("");
    try { await createQualityRevision(runId); setHistoryPage(1); setRefresh(value => value + 1); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "품질 진단을 실행하지 못했습니다."); }
    finally { setBusy(false); }
  }
  return <section className="quality-panel" aria-label="SBOM 품질 진단">
    <div className="quality-heading"><div><h3>SBOM 품질</h3><p className="muted">취약점 위험과 별도로 SBOM의 식별·관계·라이선스·무결성·출처를 진단합니다.</p></div>
      {canRerun && <button type="button" className="secondary compact" disabled={busy || archived} onClick={() => void rerun()}>{busy ? "진단 중…" : "품질 재진단"}</button>}
    </div>
    {archived && <p className="muted">보관된 회차는 기존 품질 이력만 조회할 수 있습니다.</p>}
    <div className="quality-tabs" role="tablist" aria-label="SBOM 품질 메뉴">
      <button type="button" role="tab" id="quality-results-tab" aria-selected={tab === "results"} aria-controls="quality-results" onClick={() => setTab("results")}>진단 결과</button>
      {canViewProfiles && <button type="button" role="tab" id="quality-profile-tab" aria-selected={tab === "profile"} aria-controls="quality-profile" onClick={() => setTab("profile")}>프로젝트별 품질 기준</button>}
    </div>
    {error && <p role="alert" className="form-message">{error}</p>}
    {tab === "profile" && canViewProfiles ? <QualityProfileEditor key={runId} runId={runId} initialProjectId={selected?.profileSnapshot.resolution?.owningProjectId || selected?.profileSnapshot.resolution?.projectId || selected?.profileSnapshot.projectId || ""} canManage={canManage} /> : <div id="quality-results" role="tabpanel" aria-labelledby="quality-results-tab">
      {loading ? <p role="status">품질 이력을 불러오는 중입니다…</p> : !selected ? <p>저장된 품질 진단이 없습니다. 분석 또는 품질 재진단을 실행하세요.</p> : <>
        <div className="quality-toolbar"><label>품질 리비전<select aria-label="품질 리비전" value={selectedId} onChange={event => { setSelectedId(event.target.value); setPage(1); }}>{revisions.map(item => <option key={item.id} value={item.id}>r{item.sequence} · {formatSeoulDateTime(item.createdAt)} · {statusLabels[item.summary.qualityStatus] || item.state}</option>)}</select></label>
          <a className="secondary compact" href={qualityExportUrl(runId, selectedId, "csv")} download>품질 CSV</a><a className="secondary compact" href={qualityExportUrl(runId, selectedId, "json")} download>품질 JSON</a>
        </div>
        <p className={`quality-status quality-${selected.state === "failed" ? "failed" : selected.summary.qualityStatus}`} role="status">{statusLabels[selected.state === "failed" ? "failed" : selected.summary.qualityStatus]} · {selected.profileSnapshot.name} v{selected.profileSnapshot.version} · {selected.profileSnapshot.mode === "enforce" ? "강제 기준" : "경고 모드"}</p>
        <InheritanceEvidence profile={selected.profileSnapshot} />
        {selected.error && <p role="alert" className="form-message">{selected.error}</p>}
        {selected.state === "completed" && <>
          <div className="quality-metrics"><span>구성요소 <strong>{selected.summary.componentCount}</strong></span><span>오류 <strong>{selected.summary.errorCount}</strong></span><span>경고 <strong>{selected.summary.warningCount}</strong></span><span>식별자 누락 <strong>{selected.summary.missingIdentityCount} ({selected.summary.missingIdentityRatio === null ? "적용 불가" : `${(selected.summary.missingIdentityRatio * 100).toFixed(1)}%`})</strong></span><span>끊어진 참조 <strong>{selected.summary.unresolvedRefCount}</strong></span></div>
          <QualityScore summary={selected.summary} />
          {Object.keys(selected.summary.fieldStatus || {}).length > 0 && <details><summary>필드별 적용·누락·미확인 상태</summary><dl className="quality-fields">{Object.entries(selected.summary.fieldStatus).map(([name, value]) => <div key={name}><dt>{fieldLabels[name] || name}</dt><dd>{typeof value === "string" ? fieldStatusLabels[value] || value : valueLabel(value)}</dd></div>)}</dl></details>}
        </>}
        {selected.comparison && <p className="muted">직전 품질 진단 대비 오류 {delta(selected.comparison.errorDelta)}건 · 경고 {delta(selected.comparison.warningDelta)}건{typeof selected.comparison.scoreDelta === "number" ? ` · 점수 ${selected.comparison.scoreDelta > 0 ? "+" : ""}${selected.comparison.scoreDelta.toFixed(2)}점` : ""}. 평가 기준·엔진 변경 여부도 함께 확인하세요.</p>}
        <small className="quality-evidence">엔진 {selected.engineVersion} · 원본 SHA-256 <span className="mono">{selected.originalSha256}</span></small>
        {selected.summary.sourceBasis && <p className="muted">진단 근거: {selected.summary.sourceBasis === "verified_original_artifact" ? "SHA-256 확인을 마친 원본 SBOM" : "저장된 정규화 JSON (원본 파일 확인 전 · CI 통과 불가)"}</p>}
        <div className="quality-toolbar"><label>심각도<select aria-label="품질 심각도" value={severity} onChange={event => { setSeverity(event.target.value); setPage(1); }}><option value="">전체</option><option value="error">오류</option><option value="warning">경고</option></select></label><label>규칙 ID<input aria-label="품질 규칙 ID" placeholder="예: identity.missing" value={ruleId} onChange={event => { setRuleId(event.target.value); setPage(1); }} /></label><span>전체 {issues.total}건</span></div>
        <div className="table-scroll quality-table" aria-busy={issuesLoading}><table><thead><tr><th>심각도·규칙</th><th>구성요소·원본 위치</th><th>진단 근거</th><th>개선 방법</th></tr></thead><tbody>{issuesLoading ? <tr><td colSpan={4}>품질 이슈를 불러오는 중입니다…</td></tr> : issues.items.map(issue => <tr key={issue.id}><td><span className={`quality-issue-${issue.severity}`}>{severityLabels[issue.severity] || issue.severity}</span><br/><code>{issue.ruleId}</code></td><td>{issue.componentName || "문서"}{issue.bomRef && <small>bom-ref: {issue.bomRef}</small>}<code>{issue.path}</code></td><td>{issue.message}<small>관측: {valueLabel(issue.observed)}</small><small>기대: {valueLabel(issue.expected)}</small></td><td>{issue.remediation}</td></tr>)}{!issuesLoading && !issues.items.length && <tr><td colSpan={4}>{selected.state === "failed" ? "진단 실패 상태입니다. 통과로 간주하지 않습니다." : severity || deferredRule ? "필터에 맞는 품질 이슈가 없습니다." : "발견된 품질 이슈가 없습니다."}</td></tr>}</tbody></table></div>
        <div className="quality-pagination"><span>이슈 {page}/{Math.max(1, Math.ceil(issues.total / 20))}페이지</span><button type="button" className="secondary compact" aria-label="품질 이슈 이전 페이지" disabled={page <= 1 || issuesLoading} onClick={() => setPage(value => value - 1)}>이전</button><button type="button" className="secondary compact" aria-label="품질 이슈 다음 페이지" disabled={page * 20 >= issues.total || issuesLoading} onClick={() => setPage(value => value + 1)}>다음</button></div>
      </>}
      {historyTotal > 20 && <div className="quality-pagination"><span>진단 이력 {historyPage}/{Math.ceil(historyTotal / 20)}페이지</span><button type="button" className="secondary compact" aria-label="품질 이력 이전 페이지" disabled={historyPage <= 1 || loading} onClick={() => setHistoryPage(value => value - 1)}>이전 이력</button><button type="button" className="secondary compact" aria-label="품질 이력 다음 페이지" disabled={historyPage * 20 >= historyTotal || loading} onClick={() => setHistoryPage(value => value + 1)}>다음 이력</button></div>}
    </div>}
  </section>;
}

type ProfileScope = { kind: "project" | "tag"; projectId: string; sourceId: string; tag: string };
function scopeKey(scope: ProfileScope) { return JSON.stringify(scope.kind === "tag" ? ["tag", scope.sourceId.trim(), scope.tag.trim()] : ["project", scope.projectId.trim()]); }
function QualityProfileEditor({ runId, initialProjectId, canManage }: { runId: string; initialProjectId: string; canManage: boolean }) {
  const initial: ProfileScope = { kind: "project", projectId: initialProjectId, sourceId: "", tag: "" };
  const [scope, setScope] = useState(initial);
  const [loadedScope, setLoadedScope] = useState(initial);
  const [profile, setProfile] = useState<QualityProfile | null>(null);
  const [effective, setEffective] = useState<EffectiveQualityProfile | null>(null);
  const [effectiveError, setEffectiveError] = useState("");
  const [tagProfiles, setTagProfiles] = useState<QualityPage<QualityProfile>>({ items: [], total: 0, page: 1, size: 20 });
  const [tagPage, setTagPage] = useState(1);
  const [tagError, setTagError] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [message, setMessage] = useState("");
  const changedScope = scopeKey(scope) !== scopeKey(loadedScope);
  const weights = profile?.scoreWeights || DEFAULT_QUALITY_WEIGHTS;
  const weightSum = QUALITY_DOMAINS.reduce((sum, domain) => sum + weights[domain], 0);
  const validWeights = weightSum === 100 && QUALITY_DOMAINS.every(domain => Number.isInteger(weights[domain]) && weights[domain] >= 0 && weights[domain] <= 100);
  const isGlobal = loadedScope.kind === "project" && !loadedScope.projectId;
  useEffect(() => {
    let cancelled = false;
    void fetchEffectiveQualityProfile(runId).then(result => { if (!cancelled) { setEffective(result); setEffectiveError(""); } })
      .catch(reason => { if (!cancelled) setEffectiveError(reason instanceof Error ? reason.message : "현재 적용 기준을 불러오지 못했습니다."); });
    return () => { cancelled = true; };
  }, [runId, refresh]);
  useEffect(() => {
    let cancelled = false;
    setLoading(true); setMessage(""); setProfile(null);
    const request = loadedScope.kind === "tag" ? fetchQualityProfile("", { sourceId: loadedScope.sourceId, tag: loadedScope.tag }) : fetchQualityProfile(loadedScope.projectId);
    void request.then(result => { if (!cancelled) setProfile(result); })
      .catch(reason => { if (!cancelled) setMessage(reason instanceof Error ? reason.message : "품질 기준을 불러오는 데 실패했습니다."); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [loadedScope, refresh]);
  useEffect(() => {
    let cancelled = false;
    if (loadedScope.kind !== "tag" || !loadedScope.sourceId) { setTagProfiles({ items: [], total: 0, page: 1, size: 20 }); return; }
    setTagError("");
    void fetchQualityTagProfiles(loadedScope.sourceId, tagPage).then(result => { if (!cancelled) setTagProfiles(result); })
      .catch(reason => { if (!cancelled) { setTagError(reason instanceof Error ? reason.message : "태그 기준 목록 조회 실패"); setTagProfiles({ items: [], total: 0, page: 1, size: 20 }); } });
    return () => { cancelled = true; };
  }, [loadedScope.kind, loadedScope.sourceId, tagPage, refresh]);
  function change<K extends keyof QualityProfile>(key: K, value: QualityProfile[K]) { setProfile(current => current ? { ...current, [key]: value } : current); }
  function changeWeight(domain: QualityDomain, value: number) { setProfile(current => current ? { ...current, scoreWeights: { ...(current.scoreWeights || DEFAULT_QUALITY_WEIGHTS), [domain]: value } } : current); }
  function load(next: ProfileScope) { const cleaned = { ...next, projectId: next.projectId.trim(), sourceId: next.sourceId.trim(), tag: next.tag.trim() }; setScope(cleaned); setLoadedScope(cleaned); setTagPage(1); setRefresh(value => value + 1); }
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!profile || !canManage || !validWeights || changedScope) return;
    setBusy(true); setMessage("");
    try {
      const result = loadedScope.kind === "tag" ? await saveQualityProfile("", profile, { sourceId: loadedScope.sourceId, tag: loadedScope.tag }) : await saveQualityProfile(loadedScope.projectId, profile);
      setProfile(result);
      setMessage(`품질 기준 v${result.version}을 저장했습니다. 기존 진단은 보존됩니다. 영향받는 회차 ${result.reanalysisRequested ?? 0}건의 재분석을 접수했습니다.`);
      // Refresh only current resolution/tag list; preserve the just-observed profile version.
      void fetchEffectiveQualityProfile(runId).then(setEffective).catch(reason => setEffectiveError(reason instanceof Error ? reason.message : "현재 기준 조회 실패"));
      if (loadedScope.kind === "tag") void fetchQualityTagProfiles(loadedScope.sourceId, tagPage).then(setTagProfiles).catch(reason => setTagError(reason instanceof Error ? reason.message : "태그 목록 조회 실패"));
    } catch (reason) { setMessage(reason instanceof Error ? reason.message : "품질 기준을 저장하지 못했습니다."); }
    finally { setBusy(false); }
  }
  return <div id="quality-profile" role="tabpanel" aria-labelledby="quality-profile-tab">
    <p className="muted">현재 프로젝트의 직접 기준 → 현재 태그 기준 → 가까운 부모의 직접·태그 기준 → 공통 기준 순서로 적용합니다. 태그는 같은 원본 범위에서만 적용하고 같은 우선순위가 충돌하면 진단을 실패시킵니다.</p>
    {effective && <div className="quality-current-profile"><h4>현재 회차에 적용되는 기준</h4><p>{effective.profile.name} v{effective.profile.version}</p><InheritanceEvidence profile={effective.profile} />{effective.project && <p>회차 프로젝트: <code>{effective.project.id}</code>{canManage && <button type="button" className="secondary compact" disabled={busy} onClick={() => load({ kind: "project", projectId: effective.project!.id, sourceId: effective.project!.sourceId, tag: "" })}>현재 프로젝트 기준 불러오기</button>}</p>}</div>}
    {effectiveError && <p role="alert">{effectiveError}</p>}
    <p className="muted">프로젝트 ID를 비우면 공통 기준을 관리합니다. 프로젝트 ID는 KODA 내부 ID입니다. 선택한 편집 대상의 새 버전을 저장하며 현재 적용 중인 부모 기준을 자동으로 수정하지 않습니다.</p>
    <form className="quality-toolbar" onSubmit={event => { event.preventDefault(); load(scope); }}>
      <label>편집 범위<select aria-label="품질 기준 편집 범위" value={scope.kind} onChange={event => setScope(current => ({ ...current, kind: event.target.value as ProfileScope["kind"] }))}><option value="project">프로젝트·공통 기준</option><option value="tag">태그 기준</option></select></label>
      {scope.kind === "project" ? <label>프로젝트 ID<input aria-label="품질 기준 프로젝트 ID" value={scope.projectId} onChange={event => setScope(current => ({ ...current, projectId: event.target.value }))} placeholder="비워두면 공통 기본 기준" /></label> : <><label>원본 ID<input aria-label="품질 기준 원본 ID" required value={scope.sourceId} onChange={event => setScope(current => ({ ...current, sourceId: event.target.value }))} placeholder="프로젝트 카탈로그 sourceId" /></label><label>태그<input aria-label="품질 기준 태그" required value={scope.tag} onChange={event => setScope(current => ({ ...current, tag: event.target.value }))} /></label></>}
      <button type="submit" className="secondary compact" disabled={loading || busy || (scope.kind === "tag" && (!scope.sourceId.trim() || !scope.tag.trim()))}>기준 불러오기</button>
    </form>
    {message && <p className="form-message" role="status">{message}</p>}
    {loading ? <p role="status">품질 기준을 불러오는 중입니다…</p> : profile && <form onSubmit={event => void save(event)} className="quality-profile-form">
      <p>현재 편집 대상: <strong>{loadedScope.kind === "tag" ? `${loadedScope.sourceId} / 태그 ${loadedScope.tag}` : loadedScope.projectId || "공통 기본 기준"}</strong> · 버전 {profile.version}{profile.version === 0 ? " (최초 저장 전)" : ""}</p>
      {!isGlobal && <label className="quality-inherit-toggle"><input type="checkbox" aria-label="품질 기준 상속 사용" checked={profile.inherit ?? false} disabled={!canManage || busy} onChange={event => change("inherit", event.target.checked)} />직접 기준을 해제하고 다음 기준 상속 (버전 이력은 보존)</label>}
      <fieldset disabled={!canManage || busy || profile.inherit} className="quality-profile-fields"><legend>직접 적용할 기준</legend><div className="quality-profile-grid">
        <label>기준 이름<input aria-label="품질 기준 이름" required maxLength={200} value={profile.name} onChange={event => change("name", event.target.value)} /></label>
        <label>적용 모드<select aria-label="품질 기준 적용 모드" value={profile.mode} onChange={event => change("mode", event.target.value as QualityProfile["mode"])}><option value="warn">경고 모드</option><option value="enforce">강제 기준</option></select></label>
        {loadedScope.kind === "tag" && <label>태그 우선순위<input aria-label="품질 태그 우선순위" type="number" step={1} min={-1000000} max={1000000} required value={profile.priority ?? 0} onChange={event => change("priority", Number(event.target.value))} /></label>}
        <label>허용 오류 수<input aria-label="품질 허용 오류 수" type="number" min={0} step={1} required value={profile.maxErrors} onChange={event => change("maxErrors", Number(event.target.value))} /></label>
        <label>허용 경고 수<input aria-label="품질 허용 경고 수" type="number" min={0} step={1} value={profile.maxWarnings ?? ""} placeholder="비우면 제한 없음" onChange={event => change("maxWarnings", event.target.value === "" ? null : Number(event.target.value))} /></label>
        <label>허용 식별자 누락 비율 (0–1)<input aria-label="품질 허용 식별자 누락 비율" type="number" min={0} max={1} step={0.01} required value={profile.maxMissingIdentityRatio} onChange={event => change("maxMissingIdentityRatio", Number(event.target.value))} /></label>
        <label>허용 끊어진 참조 수<input aria-label="품질 허용 끊어진 참조 수" type="number" min={0} step={1} required value={profile.maxUnresolvedRefs} onChange={event => change("maxUnresolvedRefs", Number(event.target.value))} /></label>
        <label>허용 SBOM 경과 일수<input aria-label="품질 허용 SBOM 경과 일수" type="number" min={1} step={1} required value={profile.maxAgeDays} onChange={event => change("maxAgeDays", Number(event.target.value))} /></label>
        <label>최소 품질 점수 (0–100)<input aria-label="품질 최소 점수" type="number" min={0} max={100} step={0.01} value={profile.minScore ?? ""} placeholder="비우면 점수 하한 없음" onChange={event => change("minScore", event.target.value === "" ? null : Number(event.target.value))} /></label>
      </div>
      <h4>가중치 · 합계 {weightSum}%</h4><div className="quality-weight-grid">{QUALITY_DOMAINS.map(domain => <label key={domain}>{fieldLabels[domain]} (%)<input aria-label={`품질 ${fieldLabels[domain]} 가중치`} type="number" min={0} max={100} step={1} required value={weights[domain]} onChange={event => changeWeight(domain, Number(event.target.value))} /></label>)}</div>
      {!validWeights && <p role="alert" className="form-message">가중치는 각 0–100의 정수이며 합계가 100이어야 합니다.</p>}
      </fieldset>
      <p className="muted">경고 모드는 기준 미달을 알려줍니다. 강제 모드는 점수 하한·개별 기준·필수 오류로 차단합니다. 실제 배포 중단은 CI 연결이 필요합니다.</p>
      {canManage && <button type="submit" className="primary compact" disabled={busy || changedScope || !validWeights}>{busy ? "저장 중…" : "품질 기준 새 버전 저장"}</button>}
    </form>}
    {loadedScope.kind === "tag" && <div className="quality-tag-profiles"><h4>같은 원본의 태그 기준</h4>{tagError && <p role="alert">{tagError}</p>}<ul>{tagProfiles.items.map(item => <li key={item.scopeKey || item.tag}><span>{item.tag} · 우선순위 {item.priority ?? 0} · v{item.version}{item.inherit ? " · 해제됨" : ""}</span><button type="button" className="secondary compact" disabled={busy} onClick={() => load({ kind: "tag", projectId: "", sourceId: loadedScope.sourceId, tag: item.tag || "" })}>태그 {item.tag} 불러오기</button></li>)}</ul>{!tagProfiles.total && !tagError && <p>등록된 태그 기준이 없습니다.</p>}<div className="quality-pagination"><span>태그 기준 {tagPage}/{Math.max(1, Math.ceil(tagProfiles.total / 20))}페이지</span><button type="button" className="secondary compact" aria-label="태그 기준 이전 페이지" disabled={tagPage <= 1} onClick={() => setTagPage(value => value - 1)}>이전</button><button type="button" className="secondary compact" aria-label="태그 기준 다음 페이지" disabled={tagPage * 20 >= tagProfiles.total} onClick={() => setTagPage(value => value + 1)}>다음</button></div></div>}
  </div>;
}

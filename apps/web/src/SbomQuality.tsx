import { useDeferredValue, useEffect, useState, type FormEvent } from "react";
import { previewMode } from "./api";
import { formatSeoulDateTime } from "./format";
import { createQualityRevision, fetchQualityIssues, fetchQualityProfile, fetchQualityRevisions, qualityExportUrl, saveQualityProfile } from "./quality-api";
import type { QualityIssue, QualityPage, QualityProfile, QualityRevision } from "./quality-api";
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
    {tab === "profile" && canViewProfiles ? <QualityProfileEditor key={selected?.profileSnapshot.projectId || "default"} initialProjectId={selected?.profileSnapshot.projectId || ""} canManage={canManage} /> : <div id="quality-results" role="tabpanel" aria-labelledby="quality-results-tab">
      {loading ? <p role="status">품질 이력을 불러오는 중입니다…</p> : !selected ? <p>저장된 품질 진단이 없습니다. 분석 또는 품질 재진단을 실행하세요.</p> : <>
        <div className="quality-toolbar"><label>품질 리비전<select aria-label="품질 리비전" value={selectedId} onChange={event => { setSelectedId(event.target.value); setPage(1); }}>{revisions.map(item => <option key={item.id} value={item.id}>r{item.sequence} · {formatSeoulDateTime(item.createdAt)} · {statusLabels[item.summary.qualityStatus] || item.state}</option>)}</select></label>
          <a className="secondary compact" href={qualityExportUrl(runId, selectedId, "csv")} download>품질 CSV</a><a className="secondary compact" href={qualityExportUrl(runId, selectedId, "json")} download>품질 JSON</a>
        </div>
        <p className={`quality-status quality-${selected.state === "failed" ? "failed" : selected.summary.qualityStatus}`} role="status">{statusLabels[selected.state === "failed" ? "failed" : selected.summary.qualityStatus]} · {selected.profileSnapshot.name} v{selected.profileSnapshot.version} · {selected.profileSnapshot.mode === "enforce" ? "강제 기준" : "경고 모드"}</p>
        {selected.error && <p role="alert" className="form-message">{selected.error}</p>}
        {selected.state === "completed" && <>
          <div className="quality-metrics"><span>구성요소 <strong>{selected.summary.componentCount}</strong></span><span>오류 <strong>{selected.summary.errorCount}</strong></span><span>경고 <strong>{selected.summary.warningCount}</strong></span><span>식별자 누락 <strong>{selected.summary.missingIdentityCount} ({selected.summary.missingIdentityRatio === null ? "적용 불가" : `${(selected.summary.missingIdentityRatio * 100).toFixed(1)}%`})</strong></span><span>끊어진 참조 <strong>{selected.summary.unresolvedRefCount}</strong></span></div>
          <p className="muted">{selected.summary.score === null ? "점수 미적용 · 항목별 근거를 확인하세요." : `품질 점수 ${selected.summary.score}`}</p>
          {Object.keys(selected.summary.fieldStatus || {}).length > 0 && <details><summary>필드별 적용·누락·미확인 상태</summary><dl className="quality-fields">{Object.entries(selected.summary.fieldStatus).map(([name, value]) => <div key={name}><dt>{fieldLabels[name] || name}</dt><dd>{typeof value === "string" ? fieldStatusLabels[value] || value : valueLabel(value)}</dd></div>)}</dl></details>}
        </>}
        {selected.comparison && <p className="muted">직전 품질 진단 대비 오류 {delta(selected.comparison.errorDelta)}건 · 경고 {delta(selected.comparison.warningDelta)}건. 평가 기준·엔진 변경 여부도 함께 확인하세요.</p>}
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

function QualityProfileEditor({ initialProjectId, canManage }: { initialProjectId: string; canManage: boolean }) {
  const [projectId, setProjectId] = useState(initialProjectId);
  const [loadedId, setLoadedId] = useState(initialProjectId);
  const [profile, setProfile] = useState<QualityProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [message, setMessage] = useState("");
  useEffect(() => {
    let cancelled = false;
    setLoading(true); setMessage(""); setProfile(null);
    void fetchQualityProfile(loadedId).then(result => { if (!cancelled) setProfile(result); })
      .catch(reason => { if (!cancelled) setMessage(reason instanceof Error ? reason.message : "품질 기준을 불러오지 못했습니다."); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [loadedId, refresh]);
  function change<K extends keyof QualityProfile>(key: K, value: QualityProfile[K]) { setProfile(current => current ? { ...current, [key]: value } : current); }
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!profile || !canManage) return;
    setBusy(true); setMessage("");
    try {
      const result = await saveQualityProfile(loadedId, profile); setProfile(result);
      setMessage(`품질 기준 v${result.version}을 저장했습니다. 기존 진단은 보존됩니다. 영향받는 회차 ${result.reanalysisRequested ?? 0}건의 재분석을 접수했습니다. 즉시 확인하려면 진단 결과에서 품질 재진단을 실행하세요.`);
    } catch (reason) { setMessage(reason instanceof Error ? reason.message : "품질 기준을 저장하지 못했습니다."); }
    finally { setBusy(false); }
  }
  return <div id="quality-profile" role="tabpanel" aria-labelledby="quality-profile-tab">
    <p className="muted">프로젝트 ID를 비우면 공통 기본 기준을 관리합니다. 프로젝트 ID는 프로젝트 카탈로그의 KODA 내부 ID입니다. 기준은 버전별로 보존됩니다.</p>
    <form className="quality-toolbar" onSubmit={event => { event.preventDefault(); setLoadedId(projectId.trim()); setRefresh(value => value + 1); }}><label>프로젝트 ID<input aria-label="품질 기준 프로젝트 ID" value={projectId} onChange={event => setProjectId(event.target.value)} placeholder="비워두면 공통 기본 기준" /></label><button type="submit" className="secondary compact" disabled={loading || busy}>기준 불러오기</button></form>
    {message && <p className="form-message" role="status">{message}</p>}
    {loading ? <p role="status">품질 기준을 불러오는 중입니다…</p> : profile && <form onSubmit={event => void save(event)} className="quality-profile-form">
      <p>현재 대상: <strong>{loadedId || "공통 기본 기준"}</strong> · 버전 {profile.version}{profile.version === 0 ? " (최초 저장 전)" : ""}</p>
      <div className="quality-profile-grid">
        <label>기준 이름<input aria-label="품질 기준 이름" required maxLength={200} value={profile.name} disabled={!canManage || busy} onChange={event => change("name", event.target.value)} /></label>
        <label>적용 모드<select aria-label="품질 기준 적용 모드" value={profile.mode} disabled={!canManage || busy} onChange={event => change("mode", event.target.value as QualityProfile["mode"])}><option value="warn">경고 모드</option><option value="enforce">강제 기준</option></select></label>
        <label>허용 오류 수<input aria-label="품질 허용 오류 수" type="number" min={0} step={1} required value={profile.maxErrors} disabled={!canManage || busy} onChange={event => change("maxErrors", Number(event.target.value))} /></label>
        <label>허용 경고 수<input aria-label="품질 허용 경고 수" type="number" min={0} step={1} value={profile.maxWarnings ?? ""} disabled={!canManage || busy} placeholder="비우면 제한 없음" onChange={event => change("maxWarnings", event.target.value === "" ? null : Number(event.target.value))} /></label>
        <label>허용 식별자 누락 비율 (0–1)<input aria-label="품질 허용 식별자 누락 비율" type="number" min={0} max={1} step={0.01} required value={profile.maxMissingIdentityRatio} disabled={!canManage || busy} onChange={event => change("maxMissingIdentityRatio", Number(event.target.value))} /></label>
        <label>허용 끊어진 참조 수<input aria-label="품질 허용 끊어진 참조 수" type="number" min={0} step={1} required value={profile.maxUnresolvedRefs} disabled={!canManage || busy} onChange={event => change("maxUnresolvedRefs", Number(event.target.value))} /></label>
        <label>허용 SBOM 경과 일수<input aria-label="품질 허용 SBOM 경과 일수" type="number" min={1} step={1} required value={profile.maxAgeDays} disabled={!canManage || busy} onChange={event => change("maxAgeDays", Number(event.target.value))} /></label>
      </div>
      <p className="muted">경고 모드는 기준 미달을 알려주며, 강제 기준은 기준 미달 결과를 실패로 기록합니다. 실제 배포 중단은 CI가 차단 결과를 확인하도록 연결해야 적용됩니다.</p>
      {canManage && <button type="submit" className="primary compact" disabled={busy || projectId.trim() !== loadedId}>{busy ? "저장 중…" : "품질 기준 새 버전 저장"}</button>}
    </form>}
  </div>;
}

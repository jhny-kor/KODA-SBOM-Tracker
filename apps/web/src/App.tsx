import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import {
  demoMode,
  activateVulnerabilityBundle,
  archiveRun,
  createApiToken,
  createAnalysis,
  createEnvironment,
  createService,
  createUser,
  fetchAuditEvents,
  fetchApiTokens,
  fetchCatalogs,
  fetchComparison,
  fetchDependencyTrackStatus,
  fetchRun,
  fetchRuns,
  fetchUsers,
  fetchVulnerabilityBundles,
  login,
  logout,
  resumeSession,
  retryDependencyTrack,
  revokeApiToken,
  uploadRun,
  syncVulnerabilityBundles,
} from "./api";
import { demoChanges, demoRuns } from "./demo";
import { Icon } from "./icons";
import type { AnalysisRevisionSummary, AuditEvent, CatalogItem, Comparison, ComponentChange, DependencyTrackStatus, RecordChange, SbomRun, UserSummary, VulnerabilityBundle } from "./types";

type Page = "dashboard" | "services" | "runs" | "compare" | "vuln" | "audit" | "settings";

const nav: { id: Page; label: string; icon: string }[] = [
  { id: "dashboard", label: "대시보드", icon: "dashboard" },
  { id: "services", label: "서비스", icon: "service" },
  { id: "runs", label: "SBOM 회차", icon: "runs" },
  { id: "compare", label: "회차 비교", icon: "compare" },
  { id: "vuln", label: "취약점 데이터", icon: "shield" },
  { id: "audit", label: "감사 로그", icon: "audit" },
  { id: "settings", label: "설정", icon: "settings" },
];

function stateLabel(state: SbomRun["state"]) {
  return { completed: "완료", processing: "처리 중", partial: "일부 실패", failed: "실패", queued: "대기", archived: "보관" }[state];
}

function Header({ collapsed, onToggle, onLogout, dataAsOf }: { collapsed: boolean; onToggle: () => void; onLogout: () => void; dataAsOf: string }) {
  return (
    <header className="topbar">
      <button className="icon-button menu-button" onClick={onToggle} aria-label={collapsed ? "사이드바 펼치기" : "사이드바 접기"}>
        <Icon name="menu" />
      </button>
      <label className="global-search">
        <Icon name="search" />
        <input aria-label="전체 검색" placeholder="서비스, 릴리스, 구성요소 검색" />
        <kbd>/</kbd>
      </label>
      <div className="topbar-spacer" />
      <div className="freshness"><span className="online-dot" />오프라인 데이터 기준일: {dataAsOf || "미반입"} <span className="info">i</span></div>
      <span className="divider" />
      <button className="icon-button" aria-label="알림"><Icon name="bell" /></button>
      <button className="user-menu" onClick={onLogout} title="로그아웃"><Icon name="user" /><span>보안운영팀</span><Icon name="chevron" /></button>
    </header>
  );
}

function Sidebar({ page, collapsed, onNavigate }: { page: Page; collapsed: boolean; onNavigate: (page: Page) => void }) {
  return (
    <aside className={`sidebar ${collapsed ? "collapsed" : ""}`}>
      <div className="brand"><span className="brand-mark">K</span><strong>KODA SBOM Tracker</strong></div>
      <nav aria-label="주 메뉴">
        {nav.map((item) => (
          <button key={item.id} className={page === item.id ? "active" : ""} onClick={() => onNavigate(item.id)} title={item.label}>
            <Icon name={item.icon} /><span>{item.label}</span>
          </button>
        ))}
      </nav>
      <div className="connection"><span className="online-dot" /><span><strong>연결 상태: 오프라인</strong><small>내부망 전용</small></span></div>
    </aside>
  );
}

function SelectFilter({ label, value, values, onChange }: { label: string; value: string; values: string[]; onChange: (value: string) => void }) {
  return (
    <label className="select-filter"><span>{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        <option value="">전체</option>
        {values.map((item) => <option key={item}>{item}</option>)}
      </select>
    </label>
  );
}

function RunsPage({ runs, onUpload, onSelect }: { runs: SbomRun[]; onUpload: () => void; onSelect: (run: SbomRun) => void }) {
  const [service, setService] = useState("");
  const [environment, setEnvironment] = useState("");
  const [state, setState] = useState("");
  const filtered = runs.filter((run) =>
    (!service || run.service.name === service) &&
    (!environment || run.environment.name === environment) &&
    (!state || run.state === state)
  );
  const dataAsOf = runs.map((run) => run.dataAsOf).filter(Boolean).sort().at(-1) || "미반입";
  const queued = runs.filter((run) => run.state === "queued" || run.state === "processing").length;
  const failed = runs.filter((run) => run.state === "failed" || run.state === "partial").length;
  return (
    <section className="page runs-page">
      <div className="page-heading">
        <div><h1>SBOM 회차</h1><button className="primary" onClick={onUpload}><Icon name="upload" />SBOM 업로드</button></div>
        <div className="status-summary">
          <span>최신 데이터 기준일 <strong>{dataAsOf}</strong></span>
          <i />
          <span>대기 작업 <strong className="warning">{queued}건</strong></span>
          <i />
          <span>실패 작업 <strong className="danger">{failed}건</strong></span>
        </div>
      </div>
      <div className="filters">
        <SelectFilter label="서비스" value={service} values={[...new Set(runs.map((run) => run.service.name))]} onChange={setService} />
        <SelectFilter label="환경" value={environment} values={[...new Set(runs.map((run) => run.environment.name))]} onChange={setEnvironment} />
        <SelectFilter label="상태" value={state} values={["completed", "processing", "partial"]} onChange={setState} />
        <button className="secondary reset" onClick={() => { setService(""); setEnvironment(""); setState(""); }}>초기화 <Icon name="reset" /></button>
      </div>
      <div className="table-frame">
        <div className="table-scroll">
          <table className="runs-table">
            <thead><tr><th>서비스</th><th>환경</th><th>릴리스</th><th>회차</th><th>분석 기준일</th><th>구성요소</th><th>취약점</th><th>정책 위반</th><th>처리 상태</th><th>업로드 시각</th></tr></thead>
            <tbody>
              {filtered.map((run) => (
                <tr key={run.id} onClick={() => onSelect(run)} tabIndex={0}>
                  <td className="sticky-name">{run.service.name}</td><td>{run.environment.name}</td><td>{run.releaseVersion}</td>
                  <td>{run.roundNumber}차</td><td>{run.dataAsOf || "-"}</td><td>{run.componentCount.toLocaleString()}</td>
                  <td>{run.vulnerabilityCount}</td><td>{run.policyViolationCount}</td>
                  <td><span className={`state ${run.state}`}>{stateLabel(run.state)}</span></td>
                  <td>{new Date(run.createdAt).toISOString().replace("T", " ").slice(0, 16)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="table-footer"><span>전체 {filtered.length}건</span><div><select aria-label="페이지당 행 수"><option>20개씩 보기</option><option>50개씩 보기</option></select><button aria-label="첫 페이지">|‹</button><button aria-label="이전 페이지">‹</button><button className="current">1</button><button>2</button><button>3</button><button aria-label="다음 페이지">›</button><button aria-label="마지막 페이지">›|</button></div></div>
      </div>
    </section>
  );
}

function changeLabel(change: ComponentChange) {
  if (change.change === "added") return "추가";
  if (change.change === "removed") return "제거";
  if (change.fields.includes("sha256")) return "해시 변경";
  return "버전 변경";
}

function ComparePage({ runs }: { runs: SbomRun[] }) {
  const defaultTarget = runs.find((run) => run.state === "completed") || runs[0];
  const defaultBase = runs.find(
    (run) =>
      run.id !== defaultTarget?.id &&
      run.state === "completed" &&
      run.service.id === defaultTarget?.service.id &&
      run.environment.id === defaultTarget?.environment.id,
  ) || runs.find((run) => run.id !== defaultTarget?.id && run.state === "completed") || runs[1];
  const [baseId, setBaseId] = useState(defaultBase?.id ?? "");
  const [targetId, setTargetId] = useState(defaultTarget?.id ?? "");
  const [baseAnalyses, setBaseAnalyses] = useState<AnalysisRevisionSummary[]>([]);
  const [targetAnalyses, setTargetAnalyses] = useState<AnalysisRevisionSummary[]>([]);
  const [baseAnalysisId, setBaseAnalysisId] = useState("");
  const [targetAnalysisId, setTargetAnalysisId] = useState("");
  const [tab, setTab] = useState<"components" | "vulnerabilities" | "policies">("components");
  const [selected, setSelected] = useState<ComponentChange | null>(demoChanges[2]);
  const [comparison, setComparison] = useState<Comparison | null>(null);
  const [message, setMessage] = useState("");
  const options = runs.slice(0, 10);
  const label = (run: SbomRun) => `${run.service.name} / ${run.environment.name} / ${run.releaseVersion} / ${run.roundNumber}차`;
  async function compare() {
    if (!baseId || !targetId || baseId === targetId) {
      setMessage("서로 다른 두 회차를 선택하세요.");
      return;
    }
    setMessage("비교 중…");
    try {
      const result = await fetchComparison(baseId, targetId, baseAnalysisId || undefined, targetAnalysisId || undefined);
      setComparison(result);
      setSelected(result.components[0] || null);
      setMessage("");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "비교에 실패했습니다.");
    }
  }
  useEffect(() => {
    if (!targetId && defaultTarget) setTargetId(defaultTarget.id);
    if (!baseId && defaultBase) setBaseId(defaultBase.id);
  }, [baseId, defaultBase, defaultTarget, targetId]);
  useEffect(() => {
    let cancelled = false;
    async function loadAnalyses() {
      if (!baseId || !targetId) return;
      try {
        const [baseDetail, targetDetail] = await Promise.all([fetchRun(baseId), fetchRun(targetId)]);
        if (cancelled) return;
        setBaseAnalyses(baseDetail.analyses || []);
        setTargetAnalyses(targetDetail.analyses || []);
        setBaseAnalysisId((current) => current && baseDetail.analyses.some((item) => item.id === current) ? current : baseDetail.analyses[0]?.id || "");
        setTargetAnalysisId((current) => current && targetDetail.analyses.some((item) => item.id === current) ? current : targetDetail.analyses[0]?.id || "");
      } catch (error) {
        if (!cancelled) setMessage(error instanceof Error ? error.message : "분석 리비전을 불러오지 못했습니다.");
      }
    }
    void loadAnalyses();
    return () => { cancelled = true; };
  }, [baseId, targetId]);
  useEffect(() => {
    if (!comparison && baseId && targetId && baseId !== targetId) void compare();
    // Initial selections only; subsequent comparisons are explicit.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [baseAnalysisId, baseId, comparison, targetAnalysisId, targetId]);
  const summary = comparison?.summary;
  const changes = comparison?.components || [];
  return (
    <section className="page compare-page">
      <h1>회차 비교</h1>
      <div className="compare-pickers">
        <label><span>기준 회차</span><select value={baseId} onChange={(event) => { setBaseId(event.target.value); setComparison(null); }}>{options.map((run) => <option value={run.id} key={run.id}>{label(run)}</option>)}</select></label>
        <span className="swap">⇄</span>
        <label><span>비교 회차</span><select value={targetId} onChange={(event) => { setTargetId(event.target.value); setComparison(null); }}>{options.map((run) => <option value={run.id} key={run.id}>{label(run)}</option>)}</select></label>
        <button className="primary compare-action" onClick={() => void compare()}>비교</button>
      </div>
      <div className="analysis-pickers"><label><span>기준 분석 리비전</span><select value={baseAnalysisId} onChange={(event) => { setBaseAnalysisId(event.target.value); setComparison(null); }}><option value="">최신 리비전</option>{baseAnalyses.map((item) => <option key={item.id} value={item.id}>r{item.sequence} · {item.dataAsOf || "기준일 미상"}</option>)}</select></label><label><span>비교 분석 리비전</span><select value={targetAnalysisId} onChange={(event) => { setTargetAnalysisId(event.target.value); setComparison(null); }}><option value="">최신 리비전</option>{targetAnalyses.map((item) => <option key={item.id} value={item.id}>r{item.sequence} · {item.dataAsOf || "기준일 미상"}</option>)}</select></label></div>
      {message && <p className="form-message" role="status">{message}</p>}
      <div className="diff-summary">
        {[
          ["구성요소 추가", summary?.componentsAdded ?? 0, "teal"],
          ["구성요소 제거", summary?.componentsRemoved ?? 0, "red"],
          ["구성요소 변경", summary?.componentsChanged ?? 0, "amber"],
          ["신규 취약점", summary?.vulnerabilitiesAdded ?? 0, "red"],
          ["해소 취약점", summary?.vulnerabilitiesRemoved ?? 0, "teal"],
          ["정책 변화", summary?.policiesChanged ?? 0, "red"],
        ].map((item) => <div key={item[0]}><span>{item[0]}</span><strong className={String(item[2])}>{item[1]}</strong></div>)}
      </div>
      <div className="tabs" role="tablist">
        <button className={tab === "components" ? "active" : ""} onClick={() => setTab("components")}>구성요소</button>
        <button className={tab === "vulnerabilities" ? "active" : ""} onClick={() => setTab("vulnerabilities")}>취약점</button>
        <button className={tab === "policies" ? "active" : ""} onClick={() => setTab("policies")}>정책 위반</button>
      </div>
      {tab === "components" ? (
        <>
          <div className="table-frame diff-table-frame"><div className="table-scroll"><table className="diff-table">
            <thead><tr><th>변화</th><th>구성요소</th><th>기준 버전</th><th>비교 버전</th><th>PURL</th><th>SHA-256</th></tr></thead>
            <tbody>{changes.map((change) => <tr key={change.identityKey} className={selected?.identityKey === change.identityKey ? "selected" : ""} onClick={() => setSelected(change)}>
              <td><span className={`change ${changeLabel(change).replace(" ", "-")}`}>{changeLabel(change)}</span></td><td>{change.name}</td><td>{change.baseVersion ?? "-"}</td><td>{change.targetVersion ?? "-"}</td><td className="mono">{change.purl}</td><td className="mono">{(change.targetSha256 || change.baseSha256)?.slice(0, 18)}…</td>
            </tr>)}</tbody>
          </table></div></div>
          {selected ? <ComponentInspector change={selected} comparison={comparison} /> : <EmptyComparison kind="구성요소" rows={[]} />}
        </>
      ) : (
        <EmptyComparison
          kind={tab === "vulnerabilities" ? "취약점" : "정책 위반"}
          rows={tab === "vulnerabilities" ? comparison?.vulnerabilities || [] : comparison?.policies || []}
        />
      )}
    </section>
  );
}

function ComponentInspector({ change, comparison }: { change: ComponentChange; comparison: Comparison | null }) {
  return (
    <div className="inspector">
      <div><h3>구성요소 상세</h3><dl><dt>구성요소</dt><dd>{change.name}</dd><dt>PURL</dt><dd className="mono wrap">{change.purl}</dd><dt>라이선스</dt><dd>Apache-2.0</dd><dt>타입</dt><dd>library</dd><dt>스코프</dt><dd>compile</dd><dt>최초 탐지</dt><dd>2025-05-02 10:21:34</dd><dt>최종 탐지</dt><dd>2025-05-12 14:28:11</dd></dl></div>
      <div><h3>경로</h3><ul className="paths"><li>com.koda.payment:payment-api:1.4.2<ul><li>com.koda.payment:payment-core:1.4.2<ul><li>{change.name}:{change.baseVersion}</li></ul></li></ul></li><li>com.koda.payment:payment-admin:1.4.2</li></ul>
        <h3>연관 취약점</h3><ul className="vulnerabilities"><li><b>신규</b> CVE-2024-30260 <em>HIGH</em></li><li><b>신규</b> CVE-2024-22243 <em>MEDIUM</em></li><li><span>해소</span> CVE-2020-13956</li></ul>
      </div>
      <div><h3>해시 비교</h3><label>기준 회차<input readOnly value={change.baseSha256 || "-"} /></label><label>비교 회차<input readOnly value={change.targetSha256 || "-"} /></label><small>원본: {comparison?.base.sha256.slice(0, 12)}… → {comparison?.target.sha256.slice(0, 12)}…</small><h3>변경 내용</h3><p>{changeLabel(change)}으로 인한 바이너리 차이</p><div className="inspector-actions"><button className="secondary">원본 SBOM 보기</button><a className="primary" href="/dependency-track/" target="_blank" rel="noreferrer">Dependency-Track에서 열기 <Icon name="external" /></a></div></div>
    </div>
  );
}

function EmptyComparison({ kind, rows }: { kind: string; rows: RecordChange[] }) {
  return <div className="empty-state"><Icon name="shield" /><h2>{kind} 변화</h2><p>선택한 두 회차의 {kind} 스냅샷을 비교합니다.</p><table><tbody><tr><th>변화</th><th>식별자/규칙</th><th>구성요소</th><th>상태</th></tr>{rows.length ? rows.map((row, index) => {
    const record = row.record || row.target || row.base || {};
    return <tr key={`${row.change}-${index}`}><td>{row.change === "added" ? "신규" : row.change === "removed" ? "해소" : "변경"}</td><td>{String(record.id || record.rule || "-")}</td><td>{String(record.component || "-")}</td><td>{String(record.severity || record.status || "검토 필요")}</td></tr>;
  }) : <tr><td colSpan={4}>변화가 없습니다.</td></tr>}</tbody></table></div>;
}

function UploadModal({
  services,
  environments,
  onClose,
  onUploaded,
}: {
  services: CatalogItem[];
  environments: CatalogItem[];
  onClose: () => void;
  onUploaded: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true); setMessage("");
    try {
      await uploadRun(new FormData(event.currentTarget));
      setMessage("SBOM을 접수했습니다. 분석 작업이 시작됩니다.");
      setTimeout(onUploaded, 700);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "업로드에 실패했습니다");
    } finally { setBusy(false); }
  }
  return <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}><section className="modal" role="dialog" aria-modal="true" aria-labelledby="upload-title">
    <header><h2 id="upload-title">SBOM 업로드</h2><button className="icon-button" onClick={onClose}><Icon name="close" /></button></header>
    <form onSubmit={submit}>
      <label>서비스<select name="serviceId" required>{services.map((service) => <option key={service.id} value={service.id}>{service.name}</option>)}</select></label>
      <div className="form-row"><label>환경<select name="environmentId" required>{environments.map((environment) => <option key={environment.id} value={environment.id}>{environment.name}</option>)}</select></label><label>릴리스<input name="releaseVersion" placeholder="예: 1.4.2" required /></label></div>
      <label>SBOM 파일<input name="sbom" type="file" accept=".json,.xml,application/json,application/xml" required /><small>CycloneDX JSON/XML, 최대 25 MiB</small></label>
      <label>메모<textarea name="note" rows={3} placeholder="변경 사유 또는 배포 식별자" /></label>
      {message && <p className="form-message">{message}</p>}
      <footer><button type="button" className="secondary" onClick={onClose}>취소</button><button disabled={busy} className="primary">{busy ? "업로드 중…" : "업로드"}</button></footer>
    </form>
  </section></div>;
}

function RunDetail({ run, onClose, onChanged }: { run: SbomRun; onClose: () => void; onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [archiveReason, setArchiveReason] = useState("");
  async function runAction(action: () => Promise<unknown>, success: string) {
    setBusy(true); setMessage("");
    try { await action(); setMessage(success); onChanged(); } catch (error) { setMessage(error instanceof Error ? error.message : "작업에 실패했습니다"); } finally { setBusy(false); }
  }
  return <div className="drawer-backdrop" onMouseDown={(event) => event.target === event.currentTarget && onClose()}><aside className="detail-drawer"><header><div><span>{run.service.name}</span><h2>{run.releaseVersion} · {run.roundNumber}차</h2></div><button className="icon-button" onClick={onClose}><Icon name="close" /></button></header>
    <div className="detail-status"><span className={`state ${run.state}`}>{stateLabel(run.state)}</span><span>{run.environment.name}</span><span>CycloneDX {run.specVersion}</span></div>
    <dl><dt>원본 파일</dt><dd>{run.filename}</dd><dt>SHA-256</dt><dd className="mono wrap">{run.sha256}</dd><dt>분석 기준일</dt><dd>{run.dataAsOf || "-"}</dd><dt>오프라인 분석</dt><dd>{run.analysisState || "-"}</dd><dt>Dependency-Track</dt><dd>{run.dependencyTrackState || "-"}</dd><dt>구성요소</dt><dd>{run.componentCount.toLocaleString()}개</dd><dt>취약점</dt><dd>{run.vulnerabilityCount}건</dd><dt>정책 위반</dt><dd>{run.policyViolationCount}건</dd></dl>
    <div className="drawer-actions">{message && <p className="form-message" role="status">{message}</p>}{run.dependencyTrackError && <p className="drawer-error">{run.dependencyTrackError}</p>}<div className="drawer-action-row"><button className="secondary" disabled={busy} onClick={() => void runAction(() => retryDependencyTrack(run.id), "Dependency-Track 재시도를 접수했습니다.")}>DTrack 재시도</button><button className="secondary" disabled={busy} onClick={() => void runAction(() => createAnalysis(run.id), "새 분석 리비전을 접수했습니다.")}>새 분석 리비전</button></div><div className="drawer-action-row"><a className="secondary" href={`/api/v1/sbom-runs/${run.id}/artifact`}>원본 SBOM 내려받기</a><a className="primary" href="/dependency-track/" target="_blank" rel="noreferrer">Dependency-Track에서 열기 <Icon name="external" /></a></div><form className="archive-form" onSubmit={(event) => { event.preventDefault(); if (archiveReason.trim()) void runAction(() => archiveRun(run.id, archiveReason.trim()), "회차를 논리 보관했습니다."); }}><input aria-label="보관 사유" placeholder="보관 사유" value={archiveReason} onChange={(event) => setArchiveReason(event.target.value)} /><button className="secondary" disabled={busy || !archiveReason.trim()}>논리 보관</button></form></div>
  </aside></div>;
}

function ServicesPage({
  services,
  environments,
  onChanged,
}: {
  services: CatalogItem[];
  environments: CatalogItem[];
  onChanged: () => void;
}) {
  const [mode, setMode] = useState<"service" | "environment" | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true); setMessage("");
    const values = new FormData(event.currentTarget);
    try {
      if (mode === "service") {
        await createService({ slug: String(values.get("slug")), name: String(values.get("name")) });
      } else if (mode === "environment") {
        await createEnvironment({ slug: String(values.get("slug")), name: String(values.get("name")), sortOrder: Number(values.get("sortOrder") || 0) });
      }
      setMode(null); setMessage("새 항목을 등록했습니다."); onChanged();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "등록에 실패했습니다");
    } finally { setBusy(false); }
  }
  return <section className="page generic-page">
    <div className="page-heading"><div><h1>서비스</h1><p>서비스·환경·릴리스 구조와 업로드 권한을 관리합니다.</p></div><div className="button-row"><button className="secondary" onClick={() => setMode("environment")}>환경 추가</button><button className="primary" onClick={() => setMode("service")}>서비스 추가</button></div></div>
    {message && <p className="form-message" role="status">{message}</p>}
    <div className="settings-grid"><div className="table-frame"><h2 className="table-title">서비스 {services.length}개</h2><table><thead><tr><th>서비스</th><th>slug</th><th>상태</th></tr></thead><tbody>{services.length ? services.map((item) => <tr key={item.id}><td>{item.name}</td><td className="mono">{item.slug}</td><td>활성</td></tr>) : <tr><td colSpan={3}>등록된 서비스가 없습니다.</td></tr>}</tbody></table></div><div className="table-frame"><h2 className="table-title">환경 {environments.length}개</h2><table><thead><tr><th>환경</th><th>slug</th><th>상태</th></tr></thead><tbody>{environments.length ? environments.map((item) => <tr key={item.id}><td>{item.name}</td><td className="mono">{item.slug}</td><td>활성</td></tr>) : <tr><td colSpan={3}>등록된 환경이 없습니다.</td></tr>}</tbody></table></div></div>
    {mode && <div className="modal-backdrop" role="presentation"><section className="modal" role="dialog" aria-modal="true"><header><h2>{mode === "service" ? "서비스 추가" : "환경 추가"}</h2><button className="icon-button" onClick={() => setMode(null)}><Icon name="close" /></button></header><form onSubmit={submit}><label>이름<input name="name" required autoFocus /></label><label>slug<input name="slug" pattern="[a-z0-9][a-z0-9-]{1,126}[a-z0-9]" required /><small>영문 소문자, 숫자, 하이픈만 사용합니다.</small></label>{mode === "environment" && <label>정렬 순서<input name="sortOrder" type="number" defaultValue="50" /></label>} {message && <p className="form-message">{message}</p>}<footer><button type="button" className="secondary" onClick={() => setMode(null)}>취소</button><button className="primary" disabled={busy}>{busy ? "등록 중…" : "등록"}</button></footer></form></section></div>}
  </section>;
}

function VulnerabilityPage({ bundles, onSync, onActivate }: { bundles: VulnerabilityBundle[]; onSync: () => Promise<void>; onActivate: (version: string) => Promise<void> }) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  async function sync() {
    setBusy(true); setMessage("");
    try { await onSync(); setMessage("파일시스템의 반입 상태를 동기화했습니다."); } catch (error) { setMessage(error instanceof Error ? error.message : "동기화에 실패했습니다"); } finally { setBusy(false); }
  }
  async function activate(version: string) {
    setBusy(true); setMessage("");
    try { await onActivate(version); setMessage(`${version} 번들을 활성 상태로 기록했습니다.`); } catch (error) { setMessage(error instanceof Error ? error.message : "활성화에 실패했습니다"); } finally { setBusy(false); }
  }
  return <section className="page generic-page"><div className="page-heading"><div><h1>취약점 데이터</h1><p>폐쇄망에 반입한 Grype·NVD·CISA KEV 데이터의 무결성과 기준일을 확인합니다.</p></div><button className="primary" onClick={() => void sync()} disabled={busy}>{busy ? "확인 중…" : "반입 상태 동기화"}</button></div>{message && <p className="form-message" role="status">{message}</p>}<div className="table-frame"><div className="table-scroll"><table><thead><tr><th>번들</th><th>Grype</th><th>NVD 기준일</th><th>KEV 기준일</th><th>alias / KEV</th><th>manifest SHA-256</th><th>상태</th><th>반입 시각</th></tr></thead><tbody>{bundles.length ? bundles.map((item) => <tr key={item.id}><td>{item.version}</td><td>{item.dataAsOf}<br /><small>schema {item.grypeDbSchema}</small></td><td>{item.nvdDataAsOf}</td><td>{item.kevDataAsOf}</td><td>{item.aliasCount} / {item.kevCount}</td><td className="mono">{item.manifestSha256.slice(0, 18)}…</td><td>{item.active ? <span className="state completed">활성</span> : <button className="secondary compact" onClick={() => void activate(item.version)} disabled={busy}>활성 기록</button>}</td><td>{new Date(item.importedAt).toLocaleString("ko-KR")}</td></tr>) : <tr><td colSpan={8}>등록된 취약점 데이터 번들이 없습니다. 반입 후 동기화하세요.</td></tr>}</tbody></table></div></div></section>;
}

function AuditPage({ events }: { events: AuditEvent[] }) {
  const [query, setQuery] = useState("");
  const filtered = events.filter((item) => `${item.actor} ${item.action} ${item.targetId}`.toLowerCase().includes(query.toLowerCase()));
  return <section className="page generic-page"><h1>감사 로그</h1><p>업로드·재분석·설정 변경과 관리자 작업을 불변 이력으로 조회합니다.</p><div className="generic-toolbar"><label className="global-search"><Icon name="search" /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="행위자, 작업, 대상 검색" /></label><span>{filtered.length}건</span></div><div className="table-frame"><div className="table-scroll"><table><thead><tr><th>시각</th><th>행위자</th><th>작업</th><th>대상</th><th>상세</th></tr></thead><tbody>{filtered.length ? filtered.map((item) => <tr key={item.id}><td>{new Date(item.createdAt).toLocaleString("ko-KR")}</td><td>{item.actor}</td><td className="mono">{item.action}</td><td>{item.targetType}:{item.targetId}</td><td className="mono">{item.detail ? JSON.stringify(item.detail) : "-"}</td></tr>) : <tr><td colSpan={5}>감사 로그가 없습니다.</td></tr>}</tbody></table></div></div></section>;
}

type ApiTokenSummary = { id: string; name: string; serviceId?: string; active: boolean; createdAt: string };

function SettingsPage({ users, services, tokens, dtrackStatus, onChanged }: { users: UserSummary[]; services: CatalogItem[]; tokens: ApiTokenSummary[]; dtrackStatus: DependencyTrackStatus | null; onChanged: () => void }) {
  const [mode, setMode] = useState<"user" | "token" | null>(null);
  const [message, setMessage] = useState("");
  const [issuedToken, setIssuedToken] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setMessage("");
    const values = new FormData(event.currentTarget);
    try {
      if (mode === "user") await createUser({ username: String(values.get("username")), password: String(values.get("password")), role: String(values.get("role")) });
      if (mode === "token") {
        const result = await createApiToken({ name: String(values.get("name")), serviceId: String(values.get("serviceId") || "") || undefined });
        setIssuedToken(result.token);
      } else { setMode(null); }
      setMessage(mode === "token" ? "토큰이 발급되었습니다. 지금 한 번만 복사하세요." : "사용자를 등록했습니다."); onChanged();
    } catch (error) { setMessage(error instanceof Error ? error.message : "처리에 실패했습니다"); } finally { setBusy(false); }
  }
  async function revoke(id: string) {
    setBusy(true); setMessage("");
    try { await revokeApiToken(id); setMessage("토큰을 폐기했습니다."); onChanged(); } catch (error) { setMessage(error instanceof Error ? error.message : "토큰 폐기에 실패했습니다"); } finally { setBusy(false); }
  }
  const dtrackLabel = !dtrackStatus
    ? "확인 중"
    : dtrackStatus.authenticated && dtrackStatus.missingPermissions.length === 0
      ? "정상"
      : dtrackStatus.configured
        ? "점검 필요"
        : "미설정";
  return <section className="page generic-page"><div className="page-heading"><div><h1>설정</h1><p>사용자, 역할, 환경, API 토큰과 Dependency-Track 연결을 관리합니다.</p></div><div className="button-row"><button className="secondary" onClick={() => { setIssuedToken(""); setMode("token"); }}>API 토큰 발급</button><button className="primary" onClick={() => setMode("user")}>사용자 추가</button></div></div>{message && <p className="form-message" role="status">{message}</p>}{issuedToken && <div className="token-reveal"><strong>새 토큰</strong><code>{issuedToken}</code></div>}<div className="table-frame dtrack-status"><h2 className="table-title">Dependency-Track 연결</h2><div className="dtrack-status-body"><strong className={`state ${dtrackLabel === "정상" ? "completed" : "partial"}`}>{dtrackLabel}</strong><span>버전 {dtrackStatus?.version || "-"}</span><span>팀 {dtrackStatus?.team || "-"}</span>{!dtrackStatus?.configured && <p>API 키를 설정하면 실제 BOM 업로드가 활성화됩니다.</p>}{Boolean(dtrackStatus?.missingPermissions.length) && <p>누락 권한: {dtrackStatus?.missingPermissions.join(", ")}</p>}{dtrackStatus?.error && <p>{dtrackStatus.error}</p>}</div></div><div className="settings-grid"><div className="table-frame"><h2 className="table-title">사용자 {users.length}명</h2><table><thead><tr><th>사용자</th><th>역할</th><th>상태</th></tr></thead><tbody>{users.length ? users.map((item) => <tr key={item.id || item.username}><td>{item.username}</td><td>{item.role}</td><td>{item.active ? "활성" : "비활성"}</td></tr>) : <tr><td colSpan={3}>등록된 사용자가 없습니다.</td></tr>}</tbody></table></div><div className="table-frame"><h2 className="table-title">API 토큰 {tokens.length}개</h2><table><thead><tr><th>이름</th><th>생성 시각</th><th>상태</th><th /></tr></thead><tbody>{tokens.length ? tokens.map((item) => <tr key={item.id}><td>{item.name}</td><td>{new Date(item.createdAt).toLocaleString("ko-KR")}</td><td>{item.active ? "활성" : "폐기"}</td><td>{item.active && <button className="secondary compact" onClick={() => void revoke(item.id)} disabled={busy}>폐기</button>}</td></tr>) : <tr><td colSpan={4}>발급된 토큰이 없습니다.</td></tr>}</tbody></table></div></div>{mode && <div className="modal-backdrop" role="presentation"><section className="modal" role="dialog" aria-modal="true"><header><h2>{mode === "user" ? "사용자 추가" : "API 토큰 발급"}</h2><button className="icon-button" onClick={() => setMode(null)}><Icon name="close" /></button></header><form onSubmit={submit}>{mode === "user" ? <><label>사용자 이름<input name="username" required autoFocus /></label><label>임시 비밀번호<input name="password" type="password" minLength={12} required /><small>최소 12자</small></label><label>역할<select name="role" defaultValue="viewer"><option value="admin">관리자</option><option value="analyst">분석자</option><option value="uploader">업로더</option><option value="viewer">조회자</option></select></label></> : <><label>토큰 이름<input name="name" required autoFocus /></label><label>허용 서비스<select name="serviceId"><option value="">전체 서비스</option>{services.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label><small>토큰 원문은 지금만 표시되며 서버에는 해시만 저장됩니다.</small></>}{message && <p className="form-message">{message}</p>}<footer><button type="button" className="secondary" onClick={() => setMode(null)}>닫기</button><button className="primary" disabled={busy}>{busy ? "처리 중…" : "확인"}</button></footer></form></section></div>}</section>;
}

function GenericPage({ rows }: { rows: string[][] }) {
  return <section className="page generic-page"><h1>대시보드</h1><p>서비스와 최신 SBOM 회차의 운영 상태를 확인합니다.</p><div className="table-frame"><table><thead><tr><th>이름</th><th>구분</th><th>값</th><th>상태/시각</th></tr></thead><tbody>{rows.length ? rows.map((row) => <tr key={row.join()}>{row.map((cell) => <td key={cell}>{cell}</td>)}</tr>) : <tr><td colSpan={4}>표시할 데이터가 없습니다.</td></tr>}</tbody></table></div></section>;
}

function LoginPage({ onAuthenticated }: { onAuthenticated: () => void }) {
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage("");
    const values = new FormData(event.currentTarget);
    try {
      await login(String(values.get("username") || ""), String(values.get("password") || ""));
      onAuthenticated();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "로그인에 실패했습니다");
    } finally {
      setBusy(false);
    }
  }
  return <main className="login-page"><section className="login-card">
    <span className="login-mark">K</span><p className="eyebrow">KODA SECURITY OPERATIONS</p>
    <h1>KODA SBOM Tracker</h1><p>폐쇄망 SBOM 회차·분석 운영 포털</p>
    <form onSubmit={submit}>
      <label>사용자 이름<input name="username" autoComplete="username" required autoFocus /></label>
      <label>비밀번호<input name="password" type="password" autoComplete="current-password" required /></label>
      {message && <p className="login-error" role="alert">{message}</p>}
      <button className="primary" disabled={busy}>{busy ? "확인 중…" : "로그인"}</button>
    </form>
    <small>내부망 전용 · 승인된 사용자만 접근할 수 있습니다.</small>
  </section></main>;
}

export default function App() {
  const demoServices = [...new Map(demoRuns.map((run) => [run.service.id, run.service])).values()];
  const demoEnvironments = [...new Map(demoRuns.map((run) => [run.environment.id, run.environment])).values()];
  const [page, setPage] = useState<Page>("runs");
  const [collapsed, setCollapsed] = useState(false);
  const [runs, setRuns] = useState<SbomRun[]>(demoMode ? demoRuns : []);
  const [services, setServices] = useState<CatalogItem[]>(demoMode ? demoServices : []);
  const [environments, setEnvironments] = useState<CatalogItem[]>(demoMode ? demoEnvironments : []);
  const [authenticated, setAuthenticated] = useState<boolean | null>(demoMode ? true : null);
  const [genericRows, setGenericRows] = useState<Record<string, string[][]>>({});
  const [bundles, setBundles] = useState<VulnerabilityBundle[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [users, setUsers] = useState<UserSummary[]>([]);
  const [tokens, setTokens] = useState<ApiTokenSummary[]>([]);
  const [dtrackStatus, setDtrackStatus] = useState<DependencyTrackStatus | null>(null);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [selectedRun, setSelectedRun] = useState<SbomRun | null>(null);
  const loadData = useCallback(async () => {
    const [nextRuns, catalogs] = await Promise.all([fetchRuns(), fetchCatalogs()]);
    setRuns(nextRuns);
    setServices(catalogs.services);
    setEnvironments(catalogs.environments);
    if (!demoMode) {
      const [auditResult, usersResult, bundlesResult, tokensResult, dtrackResult] = await Promise.allSettled([
        fetchAuditEvents(),
        fetchUsers(),
        fetchVulnerabilityBundles(),
        fetchApiTokens(),
        fetchDependencyTrackStatus(),
      ]);
      if (auditResult.status === "fulfilled") setAuditEvents(auditResult.value);
      if (usersResult.status === "fulfilled") setUsers(usersResult.value);
      if (bundlesResult.status === "fulfilled") setBundles(bundlesResult.value);
      if (tokensResult.status === "fulfilled") setTokens(tokensResult.value);
      if (dtrackResult.status === "fulfilled") setDtrackStatus(dtrackResult.value);
      setGenericRows({
        dashboard: [
          ["등록 서비스", "서비스", String(catalogs.services.length), "활성"],
          ["SBOM 회차", "회차", String(nextRuns.length), nextRuns[0]?.createdAt || "-"],
          ["일부 실패", "처리 상태", String(nextRuns.filter((run) => run.state === "partial" || run.state === "failed").length), "검토 필요"],
        ],
        services: catalogs.services.map((service) => [service.name, service.slug, service.id, "활성"]),
        audit: auditResult.status === "fulfilled" ? auditResult.value.map((item) => [item.actor, item.action, `${item.targetType}:${item.targetId}`, item.createdAt]) : [],
        settings: usersResult.status === "fulfilled" ? usersResult.value.map((item) => [item.username, item.role, item.active ? "활성" : "비활성", "-"]) : [],
        vuln: bundlesResult.status === "fulfilled" ? bundlesResult.value.map((item) => [item.version, `Grype schema ${item.grypeDbSchema}`, item.manifestSha256.slice(0, 16), `${item.active ? "활성" : "보관"} · ${item.dataAsOf}`]) : [],
      });
    }
  }, []);
  useEffect(() => {
    if (demoMode) return;
    resumeSession()
      .then(() => { setAuthenticated(true); return loadData(); })
      .catch(() => setAuthenticated(false));
  }, [loadData]);
  useEffect(() => {
    const listener = () => window.innerWidth <= 1024 && setCollapsed(true);
    listener(); window.addEventListener("resize", listener); return () => window.removeEventListener("resize", listener);
  }, []);
  const content = useMemo(() => {
    if (page === "runs") return <RunsPage runs={runs} onUpload={() => setUploadOpen(true)} onSelect={setSelectedRun} />;
    if (page === "compare") return <ComparePage runs={runs} />;
    if (page === "services") return <ServicesPage services={services} environments={environments} onChanged={() => void loadData()} />;
    if (page === "vuln") return <VulnerabilityPage bundles={bundles} onSync={async () => { const items = await syncVulnerabilityBundles(); setBundles(items); }} onActivate={async (version) => { await activateVulnerabilityBundle(version); const items = await fetchVulnerabilityBundles(); setBundles(items); }} />;
    if (page === "audit") return <AuditPage events={auditEvents} />;
    if (page === "settings") return <SettingsPage users={users} services={services} tokens={tokens} dtrackStatus={dtrackStatus} onChanged={() => void loadData()} />;
    return <GenericPage rows={genericRows.dashboard || []} />;
  }, [auditEvents, bundles, dtrackStatus, environments, genericRows, loadData, page, runs, services, tokens, users]);
  if (authenticated === null) return <div className="auth-loading">세션을 확인하고 있습니다…</div>;
  if (!authenticated) return <LoginPage onAuthenticated={() => { setAuthenticated(true); void loadData(); }} />;
  return <div className={`app-shell ${collapsed ? "is-collapsed" : ""}`}>
    <Sidebar page={page} collapsed={collapsed} onNavigate={setPage} />
    <Header collapsed={collapsed} dataAsOf={runs.map((run) => run.dataAsOf).filter(Boolean).sort().at(-1) || ""} onToggle={() => setCollapsed((value) => !value)} onLogout={() => { void logout().finally(() => setAuthenticated(false)); }} />
    <main>{content}</main>
    {uploadOpen && <UploadModal services={services} environments={environments} onClose={() => setUploadOpen(false)} onUploaded={() => { setUploadOpen(false); void loadData(); }} />}
    {selectedRun && <RunDetail run={selectedRun} onClose={() => setSelectedRun(null)} onChanged={() => void loadData()} />}
  </div>;
}

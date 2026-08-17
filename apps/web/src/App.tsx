import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { demoMode, previewMode, standaloneMode, activateVulnerabilityBundle, approveUser, archiveRun, createApiToken, createAnalysis, createEnvironment, createService, createUser, fetchAuditEvents, fetchApiTokens, fetchCatalogs, fetchComparison, fetchDependencyTrackStatus, fetchJob, fetchRun, fetchRuns, fetchUsers, fetchVulnerabilityBundles, login, patchEnvironment, patchService, patchUser, logout, register, resumeSession, retryDependencyTrack, revokeApiToken, uploadRun, syncVulnerabilityBundles, fetchRolePolicies, updateRolePolicies, setForbiddenHandler } from "./api";
import { demoChanges, demoRuns } from "./demo";
import { Icon } from "./icons";
import { dataAccess, hasPermissions, pageForPermissions, PAGE_PERMISSIONS, permissionSet, type Page } from "./permissions";
import type { AnalysisRevisionSummary, AuditEvent, AuthUser, CatalogItem, Comparison, ComponentChange, ComponentSnapshot, DependencyTrackStatus, RecordChange, RolePolicy, SbomRun, SbomRunDetail, UserSummary, VulnerabilityBundle } from "./types";

const nav: { id: Page; label: string; icon: string }[] = [
  { id: "dashboard", label: "대시보드", icon: "dashboard" },
  { id: "services", label: "서비스", icon: "service" },
  { id: "runs", label: "SBOM 회차", icon: "runs" },
  { id: "compare", label: "회차 비교", icon: "compare" },
  { id: "settings", label: "설정", icon: "settings" }];

type SettingsTab = "users" | "roles" | "vulnerability" | "audit" | "integration";

const ROLE_LABELS: Record<string, string> = {
  admin: "관리자",
  manager: "매니저",
  analyst: "분석자",
  uploader: "업로더",
  viewer: "조회자",
};

const PERMISSION_LABELS: Record<string, string> = {
  "dashboard.view": "대시보드 조회",
  "services.view": "서비스 조회",
  "runs.view": "SBOM 회차 조회",
  "compare.view": "회차 비교 조회",
  "vulnerability.view": "취약점 데이터 조회",
  "audit.view": "감사 로그 조회",
  "settings.view": "설정 조회",
  "sbom.upload": "SBOM 업로드",
  "artifact.download": "원본 SBOM 다운로드",
  "analysis.create": "분석 리비전 생성",
  "dtrack.retry": "Dependency-Track 재시도",
  "sbom.archive": "회차 보관",
  "catalog.manage": "서비스·환경 관리",
  "vulnerability.manage": "취약점 데이터 관리",
  "users.manage": "사용자 관리",
  "tokens.manage": "API 토큰 관리",
  "dtrack.settings": "Dependency-Track 연결 설정",
  "roles.manage": "권한 정책 관리",
};

const pageIds = new Set<Page>(nav.map((item) => item.id));
const EMPTY_RUNS: SbomRun[] = [];

function readPortalLink() {
  const params = new URLSearchParams(window.location.search);
  const requestedPage = params.get("page");
  return {
    page: requestedPage && pageIds.has(requestedPage as Page) ? (requestedPage as Page ): ("runs" as Page),
    runId: params.get("runId") || ""};}

function replacePortalLink(updates: { page?: Page; runId?: string | null }) {
  const url = new URL(window.location.href);
  if (updates.page) url.searchParams.set("page", updates.page);
  if (updates.runId === null) url.searchParams.delete("runId");
  if (updates.runId) url.searchParams.set("runId", updates.runId);
  window.history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);}

function stateLabel(state: SbomRun["state"]) {
  return { completed: "완료", processing: "처리 중", partial: "일부 실패", failed: "실패", queued: "대기", archived: "보관" }[state];}

function jobStateLabel(state?: string | null) {
  if (!state) return "-";
  return { completed: "완료", running: "실행 중", failed: "실패", queued: "대기", processing: "처리 중" }[state] || state;
}

function userStatusLabel(user: UserSummary) {
  if (user.status === "pending") return "승인 대기";
  if (user.status === "inactive" || !user.active) return "비활성";
  return "활성";
}

function roleLabel(role: string) {
  return ROLE_LABELS[role] || role || "-";
}

function permissionLabel(permission: string) {
  return PERMISSION_LABELS[permission] || permission;
}

function redactSha256(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactSha256);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).filter(([key]) => !/sha[-_]?256/i.test(key)).map(([key, nested]) => [key, redactSha256(nested)]));
  }
  return value;
}

function auditDetailLabel(detail?: Record<string, unknown>) {
  return detail ? JSON.stringify(redactSha256(detail)) : "-";
}

function Header({ collapsed, onToggle, onLogout, dataAsOf, search, onSearch, preview, user }: { collapsed: boolean; onToggle: () => void; onLogout: () => void; dataAsOf: string; search: string; onSearch: (value: string) => void; preview: boolean; user: AuthUser | null;}) {
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  const displayName = user?.displayName || user?.username || (preview ? "미리보기 사용자" : "사용자");
  const department = user?.department || "보안운영팀";
  const accountLabel = department;

  useEffect(() => {
    if (!menuOpen) return;
    const closeOnOutsidePointer = (event: PointerEvent) => {
      if (event.target instanceof Node && !menuRef.current?.contains(event.target)) setMenuOpen(false);
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setMenuOpen(false);
        menuButtonRef.current?.focus();
      }
    };
    document.addEventListener("pointerdown", closeOnOutsidePointer);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("pointerdown", closeOnOutsidePointer);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, [menuOpen]);

  return (
    <header className="topbar">
      <button type="button" className="icon-button menu-button" onClick={onToggle} aria-label={collapsed ? "사이드바 펼치기" : "사이드바 접기"}>
        <Icon name="menu" />
      </button>
      <label className="global-search">
        <Icon name="search" />
        <input aria-label="전체 검색" value={search} onChange={(event) => onSearch(event.target.value)} placeholder="서비스, 릴리스, 구성요소 검색" />
        <kbd>/</kbd>
      </label>
      <div className="topbar-spacer" />
      <div className="freshness"><span className="online-dot" />오프라인 데이터 기준일: {dataAsOf || "미반입"} {" "}<span className="info">i</span></div>
      <span className="divider" />
      <div className="account-menu" ref={menuRef}>
        <button
          ref={menuButtonRef}
          className={`user-menu ${menuOpen ? "is-open" : ""}`}
          onClick={() => setMenuOpen((value) => !value)}
          aria-controls="account-menu-panel"
          aria-expanded={menuOpen}
          aria-haspopup="true"
          title="계정 메뉴"
        >
          <Icon name="user" /><span>{accountLabel}</span><Icon name="chevron" />
        </button>
        {menuOpen && (
          <div className="account-panel" id="account-menu-panel" aria-label="계정 메뉴">
            <div className="account-summary">
              <span className="account-avatar" aria-hidden="true"><Icon name="user" /></span>
              <div><strong>{displayName}</strong><span>{department}</span></div>
            </div>
            <dl className="account-details">
              <div><dt>아이디</dt><dd>{user?.username || "-"}</dd></div>
              <div><dt>역할</dt><dd>{roleLabel(user?.role || "")}</dd></div>
            </dl>
            {preview && <p className="account-note">로컬 미리보기 모드에서는 서버 세션을 사용하지 않습니다.</p>}
            <button type="button" className="account-logout" onClick={() => { setMenuOpen(false); onLogout(); }}>
              로그아웃
            </button>
          </div>
        )}
      </div>
    </header>
  );}

export function KodaPortalLink() {
  return <a className="portal-link" href="/koda/" target="_blank" rel="noopener noreferrer" aria-label="KODA 보안 분석" title="KODA 보안 분석"><Icon name="koda" /><span>KODA 보안 분석</span></a>;
}

function Sidebar({ page, collapsed, onNavigate,
  can}: { page: Page; collapsed: boolean; onNavigate: (page: Page) => void;
  can: (permission: string) => boolean;}) {
  return (
    <aside className={`sidebar ${collapsed ? "collapsed" : ""}`}>
      <div className="brand"><span className="brand-mark">K</span><strong>KODA SBOM Tracker</strong></div>
      <nav aria-label="주 메뉴">
        {nav.filter((item) => can(PAGE_PERMISSIONS[item.id])).map((item) => (
          <button type="button" key={item.id} className={page === item.id ? "active" : ""} onClick={() => onNavigate(item.id)} title={item.label}>
            <Icon name={item.icon} /><span>{item.label}</span>
          </button>
        ))}
        {!previewMode && <KodaPortalLink />}
      </nav>
      <div className="connection"><span className="online-dot" /><span><strong>연결 상태: 오프라인</strong><small>내부망 전용</small></span></div>
    </aside>
  );}

function SelectFilter({ label, value, values, onChange, formatValue }: { label: string; value: string; values: string[]; onChange: (value: string) => void; formatValue?: (value: string) => string;}) {
  return (
    <label className="select-filter"><span>{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        <option value="">전체</option>
        {values.map((item) => (<option key={item} value={item}>{formatValue ? formatValue(item) : item}</option>))}
      </select>
    </label>
  );}

function chartPoints(values: number[], width: number, height: number, padding = 4) {
  const maximum = Math.max(1, ...values);
  const plotWidth = width - padding * 2;
  const plotHeight = height - padding * 2;
  return values.map((value, index) => ({
    x: values.length === 1 ? width / 2 : padding + (index / (values.length - 1)) * plotWidth,
    y: padding + (1 - value / maximum) * plotHeight}));}

function pathFor(values: number[], width: number, height: number) {
  return chartPoints(values, width, height).map((point, index) => `${index ? "L" : "M"}${point.x.toFixed(1)},${point.y.toFixed(1)}`).join(" ");}

function Sparkline({ values, color, label }: { values: number[]; color: string; label: string;}) {
  const points = chartPoints(values, 100, 28, 3);
  return (<svg className="preview-sparkline" viewBox="0 0 100 28" role="img" aria-label={`${label} 추이`}>
    <path d={pathFor(values, 100, 28)} fill="none" stroke={color} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
    {points.slice(-1).map((point) => (<circle key={`${point.x}-${point.y}`} cx={point.x} cy={point.y} r="2.5" fill={color} />))}
  </svg>);}

function PreviewMetric({ label, value, description, values, color }: { label: string; value: string; description: string; values: number[]; color: string;}) {
  return (<article className="preview-metric-card">
    <div><span className="preview-metric-label">{label}</span><strong>{value}</strong><small>{description}</small></div>
    <Sparkline values={values} color={color} label={label} />
  </article>);}

function PreviewBars({ items, emptyLabel }: { items: { label: string; value: number; tone?: string }[]; emptyLabel: string;}) {
  const maximum = Math.max(1, ...items.map((item) => item.value));
  if (!items.some((item) => item.value)) return <p className="preview-chart-empty">{emptyLabel}</p>;
  return (<div className="preview-bars">{items.map((item) => (<div className="preview-bar-row" key={item.label}>
    <span>{item.label}</span><div className="preview-bar-track"><i className={item.tone || ""} style={{ width: `${(item.value / maximum) * 100}%` }} /></div><strong>{item.value}</strong>
  </div>))}</div>);}

function Dashboard({ runs, onUpload,
  standalone,
  canUpload}: { runs: SbomRun[]; onUpload: () => void;
  standalone: boolean;
  canUpload: boolean;}) {
  const uploadedRuns = useMemo(() => runs
    .filter((run) => run.state !== "archived" &&
            (!standalone ||
              run.service.id === "standalone-service" || run.id.startsWith("standalone-")))
    .sort((left, right) => left.createdAt.localeCompare(right.createdAt)), [runs, standalone]);
  // ponytail: chart the latest 12 uploads to keep the local preview readable; add pagination when history needs to scale.
  const chartRuns = useMemo(() => uploadedRuns.slice(-12), [uploadedRuns]);
  const [details, setDetails] = useState<Record<string, SbomRunDetail>>({});

  useEffect(() => {
    let cancelled = false;
    if (!chartRuns.length) {
      return () => { cancelled = true;};}
    void Promise.all(chartRuns.map(async (run) => [run.id, await fetchRun(run.id)] as const))
      .then((items) => {
        if (!cancelled) setDetails(Object.fromEntries(items));})
      .catch(() => undefined);
    return () => { cancelled = true;};}, [chartRuns]);

  const latest = uploadedRuns.at(-1);
  const latestDetail = latest ? details[latest.id] : undefined;
  const findings = latestDetail?.analyses?.[0]?.findings || [];
  const kevCount = findings.filter((finding) => finding.kev === true).length;
  const severityItems = [
    { label: "Critical", value: findings.filter((finding) => String(finding.severity || "").toLowerCase() === "critical").length, tone: "critical" },
    { label: "High", value: findings.filter((finding) => String(finding.severity || "").toLowerCase() === "high").length, tone: "high" },
    { label: "Medium", value: findings.filter((finding) => String(finding.severity || "").toLowerCase() === "medium").length, tone: "medium" },
    { label: "Low", value: findings.filter((finding) => String(finding.severity || "").toLowerCase() === "low").length, tone: "low" },
    { label: "Unknown", value: findings.filter((finding) => !["critical", "high", "medium", "low"].includes(String(finding.severity || "").toLowerCase())).length, tone: "unknown" }];
  const componentTypes = [...(latestDetail?.components || []).reduce((counts, component) => {
    const label = component.componentType || "library";
    counts.set(label, (counts.get(label) || 0) + 1);
    return counts;}, new Map<string, number>())].map(([label, value]) => ({ label, value }));

  if (!uploadedRuns.length) return (<section className="page preview-dashboard-page">
    <div className="page-heading"><div><p className="preview-eyebrow">{standalone ? "LOCAL" : "OPERATIONS"} SBOM PORTFOLIO
            </p><h1>대시보드</h1><p className="preview-dashboard-subtitle">등록된 SBOM의 구성요소와 취약점 흐름을 확인합니다.
            </p></div>{canUpload && (<button className="primary" onClick={onUpload}><Icon name="upload" />SBOM 업로드
            </button>)}
        </div>
    <div className="preview-empty"><Icon name="upload" /><h2>아직 업로드한 SBOM이 없습니다.</h2><p>SBOM 회차에서 CycloneDX JSON/XML을 업로드하면 이 화면에 분석
            그래프가 표시됩니다.
          </p>{canUpload && (<button className="primary" onClick={onUpload}>첫 SBOM 업로드
            </button>)}
        </div>
  </section>);

  const series = [
    { label: "구성요소", color: "#32c6d1", values: chartRuns.map((run) => run.componentCount) },
    { label: "취약점", color: "#a970ff", values: chartRuns.map((run) => run.vulnerabilityCount) }];
  return (<section className="page preview-dashboard-page">
    <div className="page-heading"><div><p className="preview-eyebrow">{standalone ? "LOCAL" : "OPERATIONS"} SBOM PORTFOLIO
          </p><h1>대시보드</h1><p className="preview-dashboard-subtitle">등록된 SBOM {uploadedRuns.length}건의 분석 결과입니다.{" "}
            {standalone ? "브라우저 내 미리보기 데이터" : "최신 분석 리비전"}을
            집계합니다.
          </p></div>{canUpload && (<button className="primary" onClick={onUpload}><Icon name="upload" />SBOM 업로드
          </button>)}
      </div>
    <div className="preview-metrics">
      <PreviewMetric label="업로드 회차" value={uploadedRuns.length.toLocaleString()} description={
            standalone ?"브라우저에 보관된 SBOM" : "등록된 SBOM 회차"
          }values={uploadedRuns.map((_, index) => index + 1)} color="#32c6d1" />
      <PreviewMetric label="구성요소" value={(latest?.componentCount || 0).toLocaleString()} description={`최신 · ${latest?.filename || "SBOM"}`} values={chartRuns.map((run) => run.componentCount)} color="#32c6d1" />
      <PreviewMetric label="취약점" value={(latest?.vulnerabilityCount || 0).toLocaleString()} description={standalone ?"CycloneDX 내장 레코드" : "최신 분석 결과"}values={chartRuns.map((run) => run.vulnerabilityCount)} color="#a970ff" />
      <PreviewMetric label="KEV" value={kevCount.toLocaleString()} description={standalone ?"내장 KEV 플래그" : "분석 결과 KEV 플래그"}values={chartRuns.map((run) => details[run.id]?.analyses?.[0]?.findings?.filter((finding) => finding.kev === true).length || 0)} color="#ff8b8b" />
    </div>
    <div className="preview-chart-grid">
      <article className="preview-chart-card preview-trend-card"><header><div><h2>업로드별 분석 추이</h2><p>최근 SBOM 회차의 구성요소·취약점 변화</p></div><span className="preview-chart-meta">{latest?.dataAsOf || "기준일 미상"}</span></header>
        <div className="preview-legend">{series.map((item) => (<span key={item.label}><i style={{ background: item.color }} />{item.label}</span>))}</div>
        <div className="preview-chart-scroll"><svg className="preview-chart" viewBox="0 0 760 250" role="img" aria-label="업로드별 구성요소와 취약점 추이">
          <title>업로드별 구성요소와 취약점 추이</title>
          {[50, 105, 160, 215].map((y) => (<line key={y} x1="36" x2="744" y1={y} y2={y} className="preview-grid-line" />))}
          {series.map((item) => (<g key={item.label}><path d={pathFor(item.values, 708, 165)} transform="translate(36 45)" fill="none" stroke={item.color} strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />{chartPoints(item.values, 708, 165).map((point, index) => (<circle key={`${item.label}-${index}`} cx={point.x + 36} cy={point.y + 45} r="4" fill={item.color} />))}</g>))}
          {chartRuns.map((run, index) => (<text key={run.id} x={chartRuns.length === 1 ? 390 : 36 + (index / (chartRuns.length - 1)) * 708} y="238" textAnchor="middle" className="preview-axis-label">#{uploadedRuns.length - chartRuns.length + index + 1}</text>))}
        </svg></div>
      </article>
      <article className="preview-chart-card"><header><div><h2>최신 SBOM 심각도</h2><p>{latest?.filename || "업로드 파일"}</p></div><span className="preview-chart-total">{findings.length}건</span></header>
        <PreviewBars items={severityItems} emptyLabel="최신 분석에 취약점 레코드가 없습니다." />
        <div className="preview-chart-footnote">분석 기준일 {latest?.dataAsOf || "미상"} · KEV {kevCount}건
          </div>
      </article>
    </div>
    <div className="preview-lower-grid">
      <article className="preview-chart-card"><header><div><h2>구성요소 유형</h2><p>최신 업로드 기준</p></div><span className="preview-chart-total">{latest?.componentCount || 0}개
            </span></header><PreviewBars items={componentTypes} emptyLabel="구성요소 상세를 불러오는 중입니다." /></article>
      <article className="preview-upload-summary"><span className="preview-eyebrow">LATEST UPLOAD</span><h2>{latest?.filename || "SBOM 파일"}</h2><dl><dt>릴리스</dt><dd>{latest?.releaseVersion}</dd><dt>업로드 시각</dt><dd>{latest ? new Date(latest.createdAt).toLocaleString("ko-KR") : "-"}</dd></dl></article>
    </div>
  </section>);}

function RunsPage({ runs, onUpload, onSelect, searching,
  canUpload}: { runs: SbomRun[]; onUpload: () => void; onSelect: (run: SbomRun) => void; searching: boolean;
  canUpload: boolean;}) {
  const [service, setService] = useState("");
  const [environment, setEnvironment] = useState("");
  const [state, setState] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const filtered = runs.filter((run) =>
    (!service || run.service.name === service) &&
    (!environment || run.environment.name === environment) &&
    (!state || run.state === state)
  );
  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const visible = filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const dataAsOf = runs.map((run) => run.dataAsOf).filter(Boolean).sort().at(-1) || "미반입";
  const queued = runs.filter((run) => run.state === "queued" || run.state === "processing").length;
  const failed = runs.filter((run) => run.state === "failed" || run.state === "partial").length;
  return (
    <section className="page runs-page">
      <div className="page-heading">
        <div><h1>SBOM 회차</h1>{canUpload && (<button className="primary" onClick={onUpload}><Icon name="upload" />SBOM 업로드
            </button>)}
        </div>
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
        <SelectFilter label="상태" value={state} values={["completed", "processing", "partial", "failed", "queued", "archived"]} onChange={setState} formatValue={(value) => stateLabel(value as SbomRun["state"])} />
        <button className="secondary reset" onClick={() => { setService(""); setEnvironment(""); setState(""); setPage(1);}}>초기화 <Icon name="reset" /></button>
      </div>
      <div className="table-frame">
        <div className="table-scroll">
          <table className="runs-table">
            <thead><tr><th>서비스</th><th>환경</th><th>릴리스</th><th>회차</th><th>분석 기준일</th><th>구성요소</th><th>취약점</th><th>정책 위반</th><th>처리 상태</th><th>업로드 시각</th></tr></thead>
            <tbody>
              {visible.map((run) => (
                <tr key={run.id} onClick={() => onSelect(run)} tabIndex={0}>
                  <td className="sticky-name">{run.service.name}</td><td>{run.environment.name}</td><td>{run.releaseVersion}</td>
                  <td>{run.roundNumber}차</td><td>{run.dataAsOf || "-"}</td><td>{run.componentCount.toLocaleString()}</td>
                  <td>{run.vulnerabilityCount}</td><td>{run.policyViolationCount}</td>
                  <td><span className={`state ${run.state}`}>{stateLabel(run.state)}</span></td>
                  <td>{new Date(run.createdAt).toISOString().replace("T", " ").slice(0, 16)}</td>
                </tr>
              ))}
              {!visible.length && (<tr><td colSpan={10}>{searching ? "구성요소와 회차를 검색하고 있습니다…" : "조건에 맞는 회차가 없습니다."}</td></tr>)}
            </tbody>
          </table>
        </div>
        <div className="table-footer"><span>전체 {filtered.length}건 · {currentPage}/{pageCount}페이지
          </span><div><select aria-label="페이지당 행 수" value={pageSize} onChange={(event) => { setPageSize(Number(event.target.value)); setPage(1);}}><option value={20}>20개씩 보기</option><option value={50}>50개씩 보기</option><option value={100}>100개씩 보기</option></select><button aria-label="첫 페이지" disabled={currentPage === 1} onClick={() => setPage(1)}>|‹
            </button><button aria-label="이전 페이지" disabled={currentPage === 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>‹
            </button>{Array.from({ length: Math.min(pageCount, 5) }, (_, index) => { const first = Math.min(Math.max(1, currentPage - 2), Math.max(1, pageCount - 4)); const value = first + index; return (<button key={value} className={currentPage === value ? "current" : ""} onClick={() => setPage(value)}>{value}</button>);})}<button aria-label="다음 페이지" disabled={currentPage === pageCount} onClick={() => setPage((value) => Math.min(pageCount, value + 1))}>›
            </button><button aria-label="마지막 페이지" disabled={currentPage === pageCount} onClick={() => setPage(pageCount)}>›|
            </button></div></div>
      </div>
    </section>
  );}

function changeLabel(change: ComponentChange) {
  if (change.change === "added") return "추가";
  if (change.change === "removed") return "제거";
  if (change.fields.includes("sha256")) return "내용 변경";
  return "버전 변경";}

function severityValue(record: Record<string, unknown>) {
  return String(record.severity || record.status || "검토 필요");
}

function severityLabel(value: string) {
  return ({ critical: "치명", high: "높음", medium: "중간", low: "낮음", info: "정보", unknown: "미확인" } as Record<string, string>)[value.toLowerCase()] || value;
}

function severityClass(value: string) {
  const normalized = value.toLowerCase();
  return ["critical", "high", "medium", "low", "info"].includes(normalized) ? normalized : "unknown";
}

function ComparePage({ runs, can }: { runs: SbomRun[]; can: (permission: string) => boolean }) {
  const defaultTarget = runs.find((run) => run.state === "completed") || runs[0];
  const defaultBase = runs.find(
    (run) =>
      run.id !== defaultTarget?.id &&
      run.state === "completed" &&
      run.service.id === defaultTarget?.service.id &&
      run.environment.id === defaultTarget?.environment.id) || runs.find((run) => run.id !== defaultTarget?.id && run.state === "completed") || runs[1];
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
      return;}
    setMessage("비교 중…");
    try {
      const result = await fetchComparison(baseId, targetId, baseAnalysisId || undefined, targetAnalysisId || undefined);
      setComparison(result);
      setSelected(result.components[0] || null);
      setMessage("");} catch (error) {
      setMessage(error instanceof Error ? error.message : "비교에 실패했습니다.");}
  }
  useEffect(() => {
    if (!targetId && defaultTarget) setTargetId(defaultTarget.id);
    if (!baseId && defaultBase) setBaseId(defaultBase.id);}, [baseId, defaultBase, defaultTarget, targetId]);
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
        setTargetAnalysisId((current) => current && targetDetail.analyses.some((item) => item.id === current) ? current : targetDetail.analyses[0]?.id || "");} catch (error) {
        if (!cancelled) setMessage(error instanceof Error ? error.message : "분석 리비전을 불러오지 못했습니다.");}
    }
    void loadAnalyses();
    return () => { cancelled = true;};}, [baseId, targetId]);
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
        <label><span>기준 회차</span><select value={baseId} onChange={(event) => { setBaseId(event.target.value); setComparison(null);}}>{options.map((run) => (<option value={run.id} key={run.id}>{label(run)}</option>))}</select></label>
        <span className="swap" aria-hidden="true"><Icon name="swap" /></span>
        <label><span>비교 회차</span><select value={targetId} onChange={(event) => { setTargetId(event.target.value); setComparison(null);}}>{options.map((run) => (<option value={run.id} key={run.id}>{label(run)}</option>))}</select></label>
        <button className="primary compare-action" onClick={() => void compare()}>비교
        </button>
      </div>
      <div className="analysis-pickers"><label><span>기준 분석 리비전</span><select value={baseAnalysisId} onChange={(event) => { setBaseAnalysisId(event.target.value); setComparison(null);}}><option value="">최신 리비전</option>{baseAnalyses.map((item) => (<option key={item.id} value={item.id}>r{item.sequence} · {item.dataAsOf || "기준일 미상"}</option>))}</select></label><label><span>비교 분석 리비전</span><select value={targetAnalysisId} onChange={(event) => { setTargetAnalysisId(event.target.value); setComparison(null);}}><option value="">최신 리비전</option>{targetAnalyses.map((item) => (<option key={item.id} value={item.id}>r{item.sequence} · {item.dataAsOf || "기준일 미상"}</option>))}</select></label></div>
      {message && (<p className="form-message" role="status">{message}</p>)}
      <div className="diff-summary">
        {[
          ["구성요소 추가", summary?.componentsAdded ?? 0, "teal"],
          ["구성요소 제거", summary?.componentsRemoved ?? 0, "red"],
          ["구성요소 변경", summary?.componentsChanged ?? 0, "amber"],
          ["신규 취약점", summary?.vulnerabilitiesAdded ?? 0, "red"],
          ["해소 취약점", summary?.vulnerabilitiesRemoved ?? 0, "teal"],
          ["정책 변화", summary?.policiesChanged ?? 0, "red"]].map((item) => (<div key={item[0]}><span>{item[0]}</span><strong className={String(item[2])}>{item[1]}</strong></div>))}
      </div>
      <div className="tabs" role="tablist">
        <button role="tab" aria-selected={tab === "components"} className={tab === "components" ? "active" : ""} onClick={() => setTab("components")}>구성요소
        </button>
        <button role="tab" aria-selected={tab === "vulnerabilities"} className={tab === "vulnerabilities" ? "active" : ""} onClick={() => setTab("vulnerabilities")}>취약점
        </button>
        <button role="tab" aria-selected={tab === "policies"} className={tab === "policies" ? "active" : ""} onClick={() => setTab("policies")}>정책 위반
        </button>
      </div>
      {tab === "components" ? (
        <>
          <div className="table-frame diff-table-frame"><div className="table-scroll"><table className="diff-table">
            <thead><tr><th>변화</th><th>구성요소</th><th>기준 버전</th><th>비교 버전</th><th>PURL</th></tr></thead>
            <tbody>{changes.map((change) => (<tr key={change.identityKey} className={selected?.identityKey === change.identityKey ? "selected" : ""} onClick={() => setSelected(change)}>
              <td><span className={`change ${changeLabel(change).replace(" ", "-")}`}>{changeLabel(change)}</span></td><td>{change.name}</td><td>{change.baseVersion ?? "-"}</td><td>{change.targetVersion ?? "-"}</td><td className="mono">{change.purl}</td>
            </tr>))}</tbody>
          </table></div></div>
          {selected ? (<ComponentInspector change={selected} comparison={comparison} can={can} /> ): (<EmptyComparison kind="구성요소" rows={[]} />)}
        </>
      ) : (
        <ComparisonRecordsTable
          kind={tab === "vulnerabilities" ? "취약점" : "정책 위반"}
          rows={tab === "vulnerabilities" ? comparison?.vulnerabilities || [] : comparison?.policies || []}
        />
      )}
    </section>
  );}

export function ComponentInspector({ change, comparison, can }: { change: ComponentChange; comparison: Comparison | null; can: (permission: string) => boolean;}) {
  const licenses = (change.targetLicenses || change.baseLicenses || []).map((license) => typeof license === "string" ? license : String((license as { license?: { id?: string; name?: string } }).license?.id || (license as { license?: { id?: string; name?: string } }).license?.name || "식별 불가"));
  const related = (comparison?.vulnerabilities || []).filter((item) => {
    const record = item.record || item.target || item.base || {};
    return (String(record.component || "").toLowerCase() === change.name.toLowerCase() || String(record.purl || "") === change.purl);});
  const propertyEntries = Object.entries(change.targetLicenses ? { 라이선스: licenses.join(", ") || "없음" } : {}).filter(([, value]) => value);
  return (
    <div className="inspector">
      <div><h3>구성요소 상세</h3><dl><dt>구성요소</dt><dd>{change.name}</dd><dt>PURL</dt><dd className="mono wrap">{change.purl || "식별자 없음"}</dd><dt>그룹</dt><dd>{change.group || "-"}</dd><dt>타입</dt><dd>{change.componentType || "-"}</dd><dt>bom-ref</dt><dd className="mono wrap">{change.bomRef || "-"}</dd><dt>라이선스</dt><dd>{licenses.length ? licenses.join(", ") : "식별되지 않음"}</dd><dt>식별 상태</dt><dd>{change.identityStatus || "정상"}</dd></dl></div>
      <div><h3>의존성 경로</h3><p className="muted">CycloneDX 원본에 별도 의존성 그래프가 기록되지 않은 경우 구성요소 자체
          정보만 표시합니다.
        </p><ul className="paths"><li>{change.group ? `${change.group}:` : ""}{change.name}:
            {change.targetVersion || change.baseVersion || "버전 없음"}{change.bomRef ? ` · ${change.bomRef}` : ""}</li></ul>
        <h3>연관 취약점</h3><ul className="vulnerabilities">{related.length ? (related.map((item, index) => { const record = item.record || item.target || item.base || {}; return (<li key={`${item.change}-${index}`}><b>{item.change === "added" ? "신규" : item.change === "removed" ? "해소" : "변경"}</b> {" "}{String(record.canonicalId || record.id || "식별자 없음")}{" "} <em>{String(record.severity || "UNKNOWN")}</em>{record.kev ? <span> · KEV</span> : null}</li>);}) ): (<li>이 비교에서 직접 연관된 취약점이 없습니다.</li>)}</ul>
      </div>
      <div><h3>변경 정보</h3>{propertyEntries.map(([key, value]) => (<p key={key} className="muted">{key}: {value}</p>))}<h3>변경 내용</h3><p>{change.fields.length ? change.fields.filter((field) => field !== "sha256").join(", ") || "내용 변경" : "변경 필드 없음"}</p><div className="inspector-actions">{can("artifact.download") && comparison?.base.artifactUrl && (<a className="secondary" href={comparison.base.artifactUrl}>기준 원본 보기
            </a>)}{can("artifact.download") && comparison?.target.artifactUrl && (<a className="secondary" href={comparison.target.artifactUrl}>비교 원본 보기
            </a>)}{can("dtrack.retry") && (<a className="primary" href="/dependency-track/" target="_blank" rel="noreferrer">Dependency-Track에서 열기 <Icon name="external" /></a>)}</div></div>
    </div>
  );}

function ComparisonRecordsTable({ kind, rows }: { kind: string; rows: RecordChange[];}) {
  const isVulnerability = kind === "취약점";
  return (<div className="table-frame diff-table-frame"><div className="table-scroll"><table className="diff-table records-table"><thead><tr><th>변화</th><th>{isVulnerability ? "식별자" : "규칙"}</th><th>구성요소</th><th>상태</th></tr></thead><tbody>{rows.length ? (rows.map((row, index) => {
    const record = row.record || row.target || row.base || {};
    const status = severityValue(record);
    return (<tr key={`${row.change}-${index}`}><td><span className={`change ${row.change === "added" ? "추가" : row.change === "removed" ? "제거" : "버전-변경"}`}>{row.change === "added" ? "신규" : row.change === "removed" ? "해소" : "변경"}</span></td><td className="mono">{String(record.id || record.rule || "-")}</td><td>{String(record.component || "-")}</td><td>{isVulnerability ? <span className={`severity-pill ${severityClass(status)}`}>{severityLabel(status)}</span> : String(status)}</td></tr>);}) ): (<tr><td colSpan={4}>변화가 없습니다.</td></tr>)}</tbody></table></div></div>);}

function EmptyComparison({ kind, rows }: { kind: string; rows: RecordChange[];}) {
  return <ComparisonRecordsTable kind={kind} rows={rows} />;
}

function UploadModal({
  services,
  environments,
  onClose,
  onUploaded}: {
  services: CatalogItem[];
  environments: CatalogItem[];
  onClose: () => void;
  onUploaded: (runId: string) => void;}) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [jobId, setJobId] = useState("");
  const [runId, setRunId] = useState("");
  const [jobState, setJobState] = useState<"queued" | "running" | "completed" | "failed" | "">("");
  const notified = useRef(false);
  useEffect(() => {
    if (!jobId) return;
    let cancelled = false;
    const poll = async () => {
      try {
        const job = await fetchJob(jobId);
        if (cancelled) return;
        setJobState(job.state);
        if (job.state === "completed" && !notified.current) {
          notified.current = true;
          setBusy(false);
          setMessage("SBOM 분석이 완료되었습니다.");
          setTimeout(() => { if (!cancelled) onUploaded(runId);}, 250);} else if (job.state === "failed") {
          setBusy(false);
          setMessage(job.error || "SBOM 처리 작업이 실패했습니다.");}
      } catch (error) {
        if (!cancelled) { setBusy(false); setMessage(error instanceof Error ? error.message : "작업 상태를 확인하지 못했습니다.");}
      }
    };
    void poll();
    const timer = window.setInterval(() => void poll(), 1200);
    return () => { cancelled = true; window.clearInterval(timer);};}, [jobId, onUploaded, runId]);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true); setMessage("");
    try {
      const result = await uploadRun(new FormData(event.currentTarget));
      notified.current = false;
      setRunId(result.runId);
      setJobId(result.jobId);
      setJobState("queued");
      setMessage("SBOM을 접수했습니다. 분석 작업 상태를 확인하고 있습니다…");} catch (error) {
      setMessage(error instanceof Error ? error.message : "업로드에 실패했습니다");
      setBusy(false);}
  }
  return (<div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}><section className="modal" role="dialog" aria-modal="true" aria-labelledby="upload-title">
    <header><h2 id="upload-title">SBOM 업로드</h2><button type="button" className="icon-button" aria-label="SBOM 업로드 창 닫기" onClick={onClose}><Icon name="close" /></button></header>
    <form onSubmit={submit}>
      {standaloneMode ? (<p className="preview-note">로그인·서버 없이 브라우저에서 CycloneDX 구조와 파일에 포함된
              취약점 레코드만 분석합니다.
            </p> ): (<label>서비스
              <select name="serviceId" required>{services.map((service) => (<option key={service.id} value={service.id}>{service.name}</option>))}</select></label>)}
      <div className="form-row">{!standaloneMode && (<label>환경
                <select name="environmentId" required>{environments.map((environment) => (<option key={environment.id} value={environment.id}>{environment.name}</option>))}</select></label>)}<label>{standaloneMode ? "릴리스 (선택)" : "릴리스"}<input name="releaseVersion" placeholder="예: 1.4.2" defaultValue={standaloneMode ? "preview" : undefined} required={!standaloneMode} /></label></div>
      <label>SBOM 파일
            <input name="sbom" type="file" accept=".json,.xml,application/json,application/xml" required /><small>CycloneDX JSON/XML, 최대 100 MiB</small></label>
      <label>메모
            <textarea name="note" rows={3} placeholder="변경 사유 또는 배포 식별자" /></label>
      {message && (<p className="form-message" role="status">{message}{jobState && <small> · 작업 상태: {jobStateLabel(jobState)}</small>}</p>)}
      <footer><button type="button" className="secondary" onClick={onClose}>취소
            </button><button disabled={busy} className="primary">{busy ? "업로드 중…" : "업로드"}</button></footer>
    </form>
  </section></div>);}

function DetailPagination({ total, page, pageSize, onPage, onPageSize }: { total: number; page: number; pageSize: number; onPage: (page: number) => void; onPageSize: (size: number) => void;}) {
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  return (<div className="detail-pagination"><span>전체 {total.toLocaleString()}건 · {page}/{pageCount}페이지</span><div><select aria-label="상세 페이지당 행 수" value={pageSize} onChange={(event) => onPageSize(Number(event.target.value))}><option value={25}>25개씩 보기</option><option value={50}>50개씩 보기</option><option value={100}>100개씩 보기</option></select><button type="button" aria-label="상세 이전 페이지" disabled={page <= 1} onClick={() => onPage(page - 1)}>‹</button><button type="button" aria-label="상세 다음 페이지" disabled={page >= pageCount} onClick={() => onPage(page + 1)}>›</button></div></div>);
}

function RunDetail({ run, onClose, onChanged,
  can}: { run: SbomRun; onClose: () => void; onChanged: () => void;
  can: (permission: string) => boolean;}) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [archiveReason, setArchiveReason] = useState("");
  const [detail, setDetail] = useState<SbomRunDetail | null>(null);
  const [componentQuery, setComponentQuery] = useState("");
  const [componentPage, setComponentPage] = useState(1);
  const [componentPageSize, setComponentPageSize] = useState(25);
  const [findingPage, setFindingPage] = useState(1);
  const [findingPageSize, setFindingPageSize] = useState(25);
  useEffect(() => {
    let cancelled = false;
    void fetchRun(run.id).then((result) => { if (!cancelled) setDetail(result);}).catch((error) => { if (!cancelled) setMessage(error instanceof Error ? error.message : "회차 상세를 불러오지 못했습니다.");});
    return () => { cancelled = true;};}, [run.id]);
  async function runAction(action: () => Promise<unknown>, success: string) {
    setBusy(true); setMessage("");
    try { await action(); const refreshed = await fetchRun(run.id); setDetail(refreshed); setMessage(success); onChanged();} catch (error) { setMessage(error instanceof Error ? error.message : "작업에 실패했습니다");} finally { setBusy(false);}
  }
  const current = detail || run;
  const components: ComponentSnapshot[] = detail?.components || [];
  const findings = detail?.analyses?.[0]?.findings || [];
  const filteredComponents = useMemo(() => {
    const source = detail?.components || [];
    const term = componentQuery.trim().toLowerCase();
    if (!term) return source;
    return source.filter((component) => [component.group, component.name, component.version, component.purl, component.bomRef].filter(Boolean).join(" ").toLowerCase().includes(term));
  }, [componentQuery, detail?.components]);
  const componentPageCount = Math.max(1, Math.ceil(filteredComponents.length / componentPageSize));
  const currentComponentPage = Math.min(componentPage, componentPageCount);
  const visibleComponents = filteredComponents.slice((currentComponentPage - 1) * componentPageSize, currentComponentPage * componentPageSize);
  const findingPageCount = Math.max(1, Math.ceil(findings.length / findingPageSize));
  const currentFindingPage = Math.min(findingPage, findingPageCount);
  const visibleFindings = findings.slice((currentFindingPage - 1) * findingPageSize, currentFindingPage * findingPageSize);
  return (<div className="drawer-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}><section className="detail-modal" role="dialog" aria-modal="true" aria-labelledby="run-detail-title"><header><div><span>{current.service.name}</span><h2 id="run-detail-title">{current.releaseVersion} · {current.roundNumber}차
            </h2></div><button type="button" className="icon-button" aria-label="회차 상세 닫기" onClick={onClose}><Icon name="close" /></button></header>
    <div className="detail-status"><span className={`state ${current.state}`}>{stateLabel(current.state)}</span><span>{current.environment.name}</span><span>CycloneDX {current.specVersion}</span></div>
    <dl><dt>원본 파일</dt><dd>{current.filename || "-"}</dd><dt>분석 기준일</dt><dd>{current.dataAsOf || "-"}</dd><dt>오프라인 분석</dt><dd>{jobStateLabel(current.analysisState)}</dd><dt>Dependency-Track</dt><dd>{jobStateLabel(current.dependencyTrackState)}</dd><dt>구성요소</dt><dd>{current.componentCount.toLocaleString()}개</dd><dt>취약점</dt><dd>{current.vulnerabilityCount}건</dd><dt>정책 위반</dt><dd>{current.policyViolationCount}건</dd></dl>
    <h3>분석 리비전</h3><ul className="paths">{detail?.analyses?.length ? (detail.analyses.map((analysis) => (<li key={analysis.id}>r{analysis.sequence} · {jobStateLabel(analysis.state)} ·{" "}
                {analysis.dataAsOf || "기준일 미상"}{analysis.error ? ` · ${analysis.error}` : ""}</li>) )
          ): (<li>상세를 불러오는 중이거나 분석 리비전이 없습니다.</li>)}</ul>
    <div className="detail-table-heading"><h3>구성요소 검사기 ({filteredComponents.length.toLocaleString()}/{components.length.toLocaleString()})</h3><label className="detail-search"><Icon name="search" /><input aria-label="구성요소 검색" value={componentQuery} onChange={(event) => { setComponentQuery(event.target.value); setComponentPage(1); }} placeholder="이름, 버전, PURL 검색" /></label></div><div className="table-scroll"><table><thead><tr><th>이름</th><th>버전</th><th>PURL</th><th>라이선스</th></tr></thead><tbody>{visibleComponents.map((component) => (<tr key={component.identityKey}><td>{component.name}</td><td>{component.version || "-"}</td><td className="mono">{component.purl || component.bomRef || "-"}</td><td>{component.licenses?.length ? component.licenses.map((license) => typeof license === "string" ? license : String((license as { license?: { id?: string; name?: string };}).license?.id || (license as { license?: { id?: string; name?: string;};}).license?.name || "식별 불가")).join(", ") : "-"}</td></tr>))}{!visibleComponents.length && (<tr><td colSpan={4}>{components.length ? "검색 조건에 맞는 구성요소가 없습니다." : "구성요소 상세가 없습니다."}</td></tr>)}</tbody></table></div><DetailPagination total={filteredComponents.length} page={currentComponentPage} pageSize={componentPageSize} onPage={setComponentPage} onPageSize={(size) => { setComponentPageSize(size); setComponentPage(1); }} />
    <h3>취약점 검사기 ({findings.length.toLocaleString()})</h3><div className="table-scroll"><table><thead><tr><th>식별자</th><th>심각도</th><th>구성요소</th><th>KEV</th></tr></thead><tbody>{visibleFindings.map((finding, index) => (<tr key={`${String(finding.canonicalId || finding.id || "finding")}-${(currentFindingPage - 1) * findingPageSize + index}`}><td className="mono">{String(finding.canonicalId || finding.id || "식별자 없음")}</td><td>{String(finding.severity || "Unknown")}</td><td className="mono">{String(finding.component || "-")}</td><td>{finding.kev ? "KEV" : "-"}</td></tr>))}{!findings.length && (<tr><td colSpan={4}>취약점 결과가 없습니다.</td></tr>)}</tbody></table></div><DetailPagination total={findings.length} page={currentFindingPage} pageSize={findingPageSize} onPage={setFindingPage} onPageSize={(size) => { setFindingPageSize(size); setFindingPage(1); }} />
    <div className="drawer-actions">{message && (<p className="form-message" role="status">{message}</p>)}{standaloneMode ? (<p className="preview-note">미리보기 모드에서는 원본 파일을 저장하거나
              Grype·Dependency-Track을 실행하지 않습니다.
            </p> ): (<>{current.dependencyTrackError && (<p className="drawer-error">{current.dependencyTrackError}</p>)}<div className="drawer-action-row">{can("dtrack.retry") && (<button className="secondary" disabled={busy || current.state === "archived"} onClick={() => void runAction(() => retryDependencyTrack(current.id), "Dependency-Track 재시도를 접수했습니다.")}>DTrack 재시도
                  </button>)}
                {can("analysis.create") && (<button className="secondary" disabled={busy || current.state === "archived"} onClick={() => void runAction(() => createAnalysis(current.id), "새 분석 리비전을 접수했습니다.")}>새 분석 리비전
                  </button>)}
              </div><div className="drawer-action-row">{can("artifact.download") && (<a className="secondary" href={`/api/v1/sbom-runs/${current.id}/artifact`}>원본 SBOM 내려받기
                  </a>)}
                {can("dtrack.retry") && (<a className="primary" href="/dependency-track/" target="_blank" rel="noreferrer">Dependency-Track에서 열기 <Icon name="external" /></a>)}</div>{can("sbom.archive") &&current.state !== "archived" && (<form className="archive-form" onSubmit={(event) => { event.preventDefault(); if (archiveReason.trim()) void runAction(() => archiveRun(current.id, archiveReason.trim()), "회차를 논리 보관했습니다.");}}><input aria-label="보관 사유" placeholder="보관 사유" value={archiveReason} onChange={(event) => setArchiveReason(event.target.value)} /><button className="secondary" disabled={busy || !archiveReason.trim()}>논리 보관
                  </button></form>)}</>)}</div>
  </section></div>);}

function ServicesPage({
  services,
  environments,
  canManage,
  onChanged}: {
  services: CatalogItem[];
  environments: CatalogItem[];
  canManage: boolean;
  onChanged: () => void;}) {
  const [mode, setMode] = useState<"service" | "environment" | null>(null);
  const [editingEnvironment, setEditingEnvironment] = useState<CatalogItem | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true); setMessage("");
    const values = new FormData(event.currentTarget);
    try {
      if (mode === "service") {
        await createService({ slug: String(values.get("slug")), name: String(values.get("name")) });} else if (mode === "environment") {
        await createEnvironment({ slug: String(values.get("slug")), name: String(values.get("name")), sortOrder: Number(values.get("sortOrder") || 0) });}
      setMode(null); setMessage("새 항목을 등록했습니다."); onChanged();} catch (error) {
      setMessage(error instanceof Error ? error.message : "등록에 실패했습니다");} finally { setBusy(false);}
  }
  async function editService(item: CatalogItem) {
    const name = window.prompt("서비스 표시명", item.name);
    if (name === null || !name.trim()) return;
    setBusy(true); setMessage("");
    try { await patchService(item.id, { name: name.trim() }); setMessage("서비스를 변경했습니다."); onChanged();} catch (error) { setMessage(error instanceof Error ? error.message : "서비스 변경에 실패했습니다");} finally { setBusy(false);}
  }
  async function toggleService(item: CatalogItem) {
    setBusy(true); setMessage("");
    try { await patchService(item.id, { active: item.active === false }); setMessage("서비스 상태를 변경했습니다."); onChanged();} catch (error) { setMessage(error instanceof Error ? error.message : "서비스 상태 변경에 실패했습니다");} finally { setBusy(false);}
  }
  async function submitEnvironmentEdit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!editingEnvironment) return;
    setBusy(true); setMessage("");
    const values = new FormData(event.currentTarget);
    try {
      await patchEnvironment(editingEnvironment.id, {
        name: String(values.get("name") || "").trim(),
        slug: String(values.get("slug") || "").trim(),
        sortOrder: Number(values.get("sortOrder") || 0),
      });
      setEditingEnvironment(null); setMessage("환경을 변경했습니다."); onChanged();
    } catch (error) { setMessage(error instanceof Error ? error.message : "환경 변경에 실패했습니다");} finally { setBusy(false);}
  }
  return (<section className="page generic-page">
    <div className="page-heading"><div><h1>서비스</h1><p>서비스·환경·릴리스 구조와 업로드 권한을 관리합니다.</p></div>{canManage && (<div className="button-row"><button className="secondary" onClick={() => setMode("environment")}>환경 추가
            </button><button className="primary" onClick={() => setMode("service")}>서비스 추가
            </button></div>)}
      </div>
    {message && (<p className="form-message" role="status">{message}</p>)}
    <div className="settings-grid"><div className="table-frame"><h2 className="table-title">서비스 {services.length}개</h2><table><thead><tr><th>서비스</th><th>식별자</th><th>상태</th><th>작업</th></tr></thead><tbody>{services.length ? (services.map((item) => (<tr key={item.id}><td>{item.name}</td><td className="mono">{item.slug}</td><td>{item.active === false ? "비활성" : "활성"}</td><td>{canManage && (
                        <>
                          <button className="secondary compact" disabled={busy} onClick={() => void editService(item)}>이름 변경
                          </button> {" "}<button className="secondary compact" disabled={busy} onClick={() => void toggleService(item)}>{item.active === false ? "활성화" : "비활성화"}</button></>
                      )}
    </td></tr>) )
              ): (<tr><td colSpan={4}>등록된 서비스가 없습니다.</td></tr>)}</tbody></table></div><div className="table-frame"><h2 className="table-title">환경 {environments.length}개</h2><table><thead><tr><th>환경</th><th>식별자</th><th>정렬</th><th>작업</th></tr></thead><tbody>{environments.length ? (environments.map((item) => (<tr key={item.id}><td>{item.name}</td><td className="mono">{item.slug}</td><td>{item.sortOrder ?? "-"}</td><td>{canManage && (<button className="secondary compact" disabled={busy} onClick={() => setEditingEnvironment(item)}>변경
                        </button>)}
                    </td></tr>) )
              ): (<tr><td colSpan={4}>등록된 환경이 없습니다.</td></tr>)}</tbody></table></div></div>
    {mode && (<div className="modal-backdrop" role="presentation"><section className="modal" role="dialog" aria-modal="true"><header><h2>{mode === "service" ? "서비스 추가" : "환경 추가"}</h2><button type="button" className="icon-button" aria-label="추가 창 닫기" onClick={() => setMode(null)}><Icon name="close" /></button></header><form onSubmit={submit}><label>이름
                <input name="name" required autoFocus /></label><label>식별자
                <input name="slug" pattern="[a-z0-9][a-z0-9-]{1,126}[a-z0-9]" required /><small>영문 소문자, 숫자, 하이픈만 사용합니다.</small></label>{mode === "environment" && (<label>정렬 순서
                  <input name="sortOrder" type="number" defaultValue="50" /></label>)}{" "} {message && <p className="form-message">{message}</p>}<footer><button type="button" className="secondary" onClick={() => setMode(null)}>취소
                </button><button className="primary" disabled={busy}>{busy ? "등록 중…" : "등록"}</button></footer></form></section></div>)}
    {editingEnvironment && (<div className="modal-backdrop" role="presentation"><section className="modal" role="dialog" aria-modal="true" aria-labelledby="environment-edit-title"><header><h2 id="environment-edit-title">환경 변경</h2><button type="button" className="icon-button" aria-label="환경 변경 창 닫기" onClick={() => setEditingEnvironment(null)}><Icon name="close" /></button></header><form onSubmit={submitEnvironmentEdit}><label>이름
                <input name="name" defaultValue={editingEnvironment.name} required autoFocus /></label><label>식별자
                <input name="slug" defaultValue={editingEnvironment.slug} pattern="[a-z0-9][a-z0-9-]{1,126}[a-z0-9]" required /><small>영문 소문자, 숫자, 하이픈만 사용합니다.</small></label><label>정렬 순서
                <input name="sortOrder" type="number" defaultValue={editingEnvironment.sortOrder ?? 0} required /></label>{message && <p className="form-message">{message}</p>}<footer><button type="button" className="secondary" onClick={() => setEditingEnvironment(null)}>취소
                </button><button className="primary" disabled={busy}>{busy ? "변경 중…" : "변경"}</button></footer></form></section></div>)}
  </section>);}

function VulnerabilityPage({ bundles, onSync, onActivate, canManage, embedded = false }: { bundles: VulnerabilityBundle[]; onSync: () => Promise<void>; onActivate: (version: string) => Promise<void>; canManage: boolean; embedded?: boolean; }) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  async function sync() {
    setBusy(true); setMessage("");
    try { await onSync(); setMessage("파일시스템의 반입 상태를 동기화했습니다.");} catch (error) { setMessage(error instanceof Error ? error.message : "동기화에 실패했습니다");} finally { setBusy(false);}
  }
  async function activate(version: string) {
    setBusy(true); setMessage("");
    try { await onActivate(version); setMessage(`${version} 번들을 활성 상태로 기록했습니다.`);} catch (error) { setMessage(error instanceof Error ? error.message : "활성화에 실패했습니다");} finally { setBusy(false);}
  }
  return (<section className={embedded ? "settings-panel generic-page" : "page generic-page"}><div className="page-heading"><div><h1>취약점 데이터</h1><p>폐쇄망에 반입한 Grype·NVD·CISA KEV 데이터의 무결성과 기준일을
            확인합니다.
          </p></div>{canManage && (<button className="primary" onClick={() => void sync()} disabled={busy}>{busy ? "확인 중…" : "반입 상태 동기화"}</button>)}
      </div>{message && (<p className="form-message" role="status">{message}</p>)}<div className="table-frame"><div className="table-scroll"><table><thead><tr><th>번들</th><th>Grype</th><th>NVD 기준일</th><th>KEV 기준일</th><th>별칭 / KEV</th><th>상태</th><th>반입 시각</th></tr></thead><tbody>{bundles.length ? (bundles.map((item) => (<tr key={item.id}><td>{item.version}</td><td>{item.dataAsOf}<br /><small>schema {item.grypeDbSchema}</small></td><td>{item.nvdDataAsOf}</td><td>{item.kevDataAsOf}</td><td>{item.aliasCount} / {item.kevCount}</td><td>{item.active ? (<span className="state completed">활성</span> ): canManage ? (<button className="secondary compact" onClick={() => void activate(item.version)} disabled={busy}>활성 기록
                        </button>) : (
                        <span>보관</span>
                      )}</td><td>{new Date(item.importedAt).toLocaleString("ko-KR")}</td></tr>) )
              ): (<tr><td colSpan={7}>등록된 취약점 데이터 번들이 없습니다. 반입 후 동기화하세요.
                  </td></tr>)}</tbody></table></div></div></section>);}

function AuditPage({ events, embedded = false }: { events: AuditEvent[]; embedded?: boolean }) {
  const [query, setQuery] = useState("");
  const filtered = events.filter((item) => `${item.actor} ${item.action} ${item.targetId}`.toLowerCase().includes(query.toLowerCase()));
  return (<section className={embedded ? "settings-panel generic-page" : "page generic-page"}><h1>감사 로그</h1><p>업로드·재분석·설정 변경과 관리자 작업을 불변 이력으로 조회합니다.</p><div className="generic-toolbar"><label className="global-search"><Icon name="search" /><input aria-label="감사 로그 검색" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="행위자, 작업, 대상 검색" /></label><span>{filtered.length}건</span></div><div className="table-frame"><div className="table-scroll"><table><thead><tr><th>시각</th><th>행위자</th><th>작업</th><th>대상</th><th>상세</th></tr></thead><tbody>{filtered.length ? (filtered.map((item) => (<tr key={item.id}><td>{new Date(item.createdAt).toLocaleString("ko-KR")}</td><td>{item.actor}</td><td className="mono">{item.action}</td><td>{item.targetType}:{item.targetId}</td><td className="mono">{auditDetailLabel(item.detail)}</td></tr>) )
              ): (<tr><td colSpan={5}>감사 로그가 없습니다.</td></tr>)}</tbody></table></div></div></section>);}

type ApiTokenSummary = { id: string; name: string; serviceId?: string; active: boolean; createdAt: string;};

export function SettingsPage({ users, services, tokens, dtrackStatus, policies, roleCatalog, bundles, auditEvents, isAdmin, canVulnerability, canVulnerabilityManage, canAudit, canUsers, canTokens, canDtrack, canPolicyEdit, canRoles, onSync, onActivate, onPolicyChanged, onChanged }: {
  users: UserSummary[];
  services: CatalogItem[];
  tokens: ApiTokenSummary[];
  dtrackStatus: DependencyTrackStatus | null;
  policies: RolePolicy[];
  roleCatalog: string[];
  bundles: VulnerabilityBundle[];
  auditEvents: AuditEvent[];
  isAdmin: boolean;
  canVulnerability: boolean;
  canVulnerabilityManage: boolean;
  canAudit: boolean;
  canUsers: boolean;
  canTokens: boolean;
  canDtrack: boolean;
  canPolicyEdit: boolean;
  canRoles: boolean;
  onSync: () => Promise<void>;
  onActivate: (version: string) => Promise<void>;
  onPolicyChanged: (policies: RolePolicy[]) => Promise<void>;
  onChanged: () => void;
}) {
  const [mode, setMode] = useState<"user" | "token" | null>(null);
  const [activeTab, setActiveTab] = useState<SettingsTab>("users");
  const [message, setMessage] = useState("");
  const [issuedToken, setIssuedToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [policyDraft, setPolicyDraft] = useState<Record<string, Set<string>>>(
    () =>
      Object.fromEntries(
        policies.map((item) => [item.role, new Set(item.permissions)])));
  const settingsTabs = useMemo(() => {
    const tabs: { id: SettingsTab; label: string; icon: string }[] = [];
    if (canUsers || canTokens) tabs.push({ id: "users", label: "사용자 관리", icon: "user" });
    if (canRoles || canPolicyEdit) tabs.push({ id: "roles", label: "권한 관리", icon: "settings" });
    if (isAdmin && canVulnerability) tabs.push({ id: "vulnerability", label: "취약점 데이터", icon: "shield" });
    if (isAdmin && canAudit) tabs.push({ id: "audit", label: "감사 로그", icon: "audit" });
    if (canDtrack) tabs.push({ id: "integration", label: "연동 설정", icon: "external" });
    return tabs;
  }, [canAudit, canDtrack, canPolicyEdit, canRoles, canTokens, canUsers, canVulnerability, isAdmin]);
  useEffect(
    () =>
      setPolicyDraft(
        Object.fromEntries(
          policies.map((item) => [item.role, new Set(item.permissions)]))),
    [policies]);
  useEffect(() => {
    if (!settingsTabs.some((tab) => tab.id === activeTab)) setActiveTab(settingsTabs[0]?.id || "users");
  }, [activeTab, settingsTabs]);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setMessage("");
    const values = new FormData(event.currentTarget);
    try {
      if (mode === "user") await createUser({ username: String(values.get("username")), password: String(values.get("password")), role: String(values.get("role")) });
      if (mode === "token") {
        const result = await createApiToken({ name: String(values.get("name")), serviceId: String(values.get("serviceId") || "") });
        setIssuedToken(result.token);} else { setMode(null);}
      setMessage(mode === "token" ? "토큰이 발급되었습니다. 지금 한 번만 복사하세요." : "사용자를 등록했습니다."); onChanged();} catch (error) { setMessage(error instanceof Error ? error.message : "처리에 실패했습니다");} finally { setBusy(false);}
  }
  async function revoke(id: string) {
    setBusy(true); setMessage("");
    try { await revokeApiToken(id); setMessage("토큰을 폐기했습니다."); onChanged();} catch (error) { setMessage(error instanceof Error ? error.message : "토큰 폐기에 실패했습니다");} finally { setBusy(false);}
  }
  async function updateUser(item: UserSummary, field: "role" | "active", value: string | boolean) {
    if (!item.id) return;
    setBusy(true); setMessage("");
    try { await patchUser(item.id, field === "role" ? { role: String(value) } : { active: Boolean(value) }); setMessage("사용자 권한을 변경했습니다."); onChanged();} catch (error) { setMessage(error instanceof Error ? error.message : "사용자 변경에 실패했습니다");} finally { setBusy(false);}
  }
  async function approve(item: UserSummary) {
    if (!item.id) return;
    setBusy(true); setMessage("");
    try { await approveUser(item.id); setMessage("가입 신청을 승인했습니다."); onChanged();} catch (error) { setMessage(error instanceof Error ? error.message : "가입 승인에 실패했습니다");} finally { setBusy(false);}
  }
  const dtrackLabel = !dtrackStatus
    ? "확인 중"
    : dtrackStatus.authenticated && dtrackStatus.missingPermissions.length === 0
      ? "정상"
      : dtrackStatus.configured
        ? "점검 필요"
        : "미설정";
  const roles = policies.map((item) => item.role);
  const permissionNames = roleCatalog;
  return (<section className="page generic-page">
    <div className="page-heading"><div><h1>설정</h1><p>사용자·권한·취약점 데이터·감사 로그와 연동을 관리합니다.</p></div>{activeTab === "users" && (<div className="button-row">{canTokens && (<button type="button" className="secondary" onClick={() => { setIssuedToken(""); setMode("token"); }}>API 토큰 발급</button>)}{canUsers && (<button type="button" className="primary" onClick={() => setMode("user")}>사용자 추가</button>)}</div>)}</div>
    <div className="settings-tabs" role="tablist" aria-label="설정 하위 메뉴">
      {settingsTabs.map((tab) => (<button type="button" role="tab" id={`settings-tab-${tab.id}`} aria-controls={`settings-panel-${tab.id}`} aria-selected={activeTab === tab.id} className={activeTab === tab.id ? "active" : ""} key={tab.id} onClick={() => setActiveTab(tab.id)}><Icon name={tab.icon} /><span>{tab.label}</span></button>))}
    </div>
    {message && (<p className="form-message" role="status">{message}</p>)}
    {issuedToken && activeTab === "users" && (<div className="token-reveal"><strong>새 토큰</strong><code>{issuedToken}</code></div>)}
    {activeTab === "users" && canUsers && (<p className="form-message">가입 신청 계정은 승인 대기로 구분됩니다. 역할을 확인한 뒤 승인하세요.</p>)}
    {activeTab === "integration" && canDtrack && (<div className="settings-panel" id="settings-panel-integration" role="tabpanel" aria-labelledby="settings-tab-integration"><div className="table-frame dtrack-status"><h2 className="table-title">Dependency-Track 연결</h2><div className="dtrack-status-body"><strong className={`state ${dtrackLabel === "정상" ? "completed" : "partial"}`}>{dtrackLabel}</strong><span>버전 {dtrackStatus?.version || "-"}</span><span>팀 {dtrackStatus?.team || "-"}</span>{!dtrackStatus?.configured && (<p>API 키를 설정하면 실제 BOM 업로드가 활성화됩니다.</p>)}{Boolean(dtrackStatus?.missingPermissions.length) && (<p>누락 권한: {(dtrackStatus?.missingPermissions || []).map(permissionLabel).join(", ")}</p>)}{dtrackStatus?.error && <p>{dtrackStatus.error}</p>}</div></div></div>)}
    {activeTab === "users" && (canUsers || canTokens) && (<div className="settings-panel" id="settings-panel-users" role="tabpanel" aria-labelledby="settings-tab-users"><div className="settings-grid">{canUsers && (<div className="table-frame"><h2 className="table-title">사용자 {users.length}명</h2><table><thead><tr><th>사용자</th><th>역할</th><th>상태</th><th>작업</th></tr></thead><tbody>{users.length ? users.map((item) => (<tr key={item.id || item.username} className={item.status === "pending" ? "pending-user" : ""}><td>{item.username}</td><td><select aria-label={`${item.username} 역할`} value={item.role} disabled={busy} onChange={(event) => void updateUser(item, "role", event.target.value)}>{canRoles && (<><option value="admin">관리자</option><option value="manager">매니저</option></>)}<option value="analyst">분석자</option><option value="uploader">업로더</option><option value="viewer">조회자</option></select></td><td><span className={`user-status ${item.status || (item.active ? "active" : "inactive")}`}>{userStatusLabel(item)}</span></td><td>{item.id && (item.status === "pending" ? (<button type="button" className="primary compact" disabled={busy} onClick={() => void approve(item)}>승인</button>) : (<button type="button" className="secondary compact" disabled={busy} onClick={() => void updateUser(item, "active", !item.active)}>{item.active ? "비활성화" : "활성화"}</button>))}</td></tr>)) : (<tr><td colSpan={4}>등록된 사용자가 없습니다.</td></tr>)}</tbody></table></div>)}{canTokens && (<div className="table-frame"><h2 className="table-title">API 토큰 {tokens.length}개</h2><table><thead><tr><th>이름</th><th>서비스</th><th>생성 시각</th><th>상태</th><th /></tr></thead><tbody>{tokens.length ? tokens.map((item) => (<tr key={item.id}><td>{item.name}</td><td>{services.find((service) => service.id === item.serviceId)?.name || item.serviceId || "-"}</td><td>{new Date(item.createdAt).toLocaleString("ko-KR")}</td><td>{item.active ? "활성" : "폐기"}</td><td>{item.active && (<button type="button" className="secondary compact" onClick={() => void revoke(item.id)} disabled={busy}>폐기</button>)}</td></tr>)) : (<tr><td colSpan={5}>발급된 토큰이 없습니다.</td></tr>)}</tbody></table></div>)}</div></div>)}
    {activeTab === "roles" && canPolicyEdit && policies.length > 0 && (<div className="settings-panel" id="settings-panel-roles" role="tabpanel" aria-labelledby="settings-tab-roles"><div className="table-frame"><h2 className="table-title">권한 정책</h2><div className="role-policy-grid">{roles.map((role) => (<fieldset key={role}><legend>{roleLabel(role)}</legend>{permissionNames.map((permission) => (<label key={permission}><input type="checkbox" checked={policyDraft[role]?.has(permission) || false} disabled={!canPolicyEdit || busy} onChange={() => setPolicyDraft((current) => { const next = new Set(current[role] || []); if (next.has(permission)) next.delete(permission); else next.add(permission); return { ...current, [role]: next }; })} />{permissionLabel(permission)}</label>))}</fieldset>))}</div>{canPolicyEdit && (<button type="button" className="primary" onClick={async () => { setBusy(true); setMessage(""); try { const changed = roles.filter((role) => { const before = policies.find((item) => item.role === role)?.permissions || []; const after = [...(policyDraft[role] || [])]; return before.length !== after.length || before.some((item) => !policyDraft[role]?.has(item)); }); if (!changed.length) { setMessage("변경된 역할 정책이 없습니다."); return; } const updated = await updateRolePolicies(changed.map((role) => ({ role, permissions: [...(policyDraft[role] || [])] }))); const next = policies.map((item) => updated.find((changedPolicy) => changedPolicy.role === item.role) || item); await onPolicyChanged(next); setMessage("역할 정책을 저장했습니다."); } catch (error) { setMessage(error instanceof Error ? error.message : "역할 정책 저장에 실패했습니다."); } finally { setBusy(false); } }}>권한 정책 저장</button>)}</div></div>)}
    {activeTab === "vulnerability" && isAdmin && canVulnerability && (<div id="settings-panel-vulnerability" role="tabpanel" aria-labelledby="settings-tab-vulnerability"><VulnerabilityPage embedded bundles={bundles} canManage={isAdmin && canVulnerabilityManage} onSync={onSync} onActivate={onActivate} /></div>)}
    {activeTab === "audit" && isAdmin && canAudit && (<div id="settings-panel-audit" role="tabpanel" aria-labelledby="settings-tab-audit"><AuditPage embedded events={auditEvents} /></div>)}
    {!settingsTabs.length && (<div className="empty-state"><Icon name="settings" /><h2>관리 가능한 설정이 없습니다.</h2><p>현재 계정에 허용된 설정 권한이 없습니다.</p></div>)}
    {mode && (<div className="modal-backdrop" role="presentation"><section className="modal" role="dialog" aria-modal="true" aria-labelledby="settings-modal-title"><header><h2 id="settings-modal-title">{mode === "user" ? "사용자 추가" : "API 토큰 발급"}</h2><button type="button" className="icon-button" aria-label="설정 창 닫기" onClick={() => setMode(null)}><Icon name="close" /></button></header><form onSubmit={submit}>{mode === "user" ? (<><label>사용자 이름<input name="username" required autoFocus /></label><label>임시 비밀번호<input name="password" type="password" minLength={12} required /><small>최소 12자</small></label><label>역할<select name="role" defaultValue="viewer">{canRoles && (<><option value="admin">관리자</option><option value="manager">매니저</option></>)}<option value="analyst">분석자</option><option value="uploader">업로더</option><option value="viewer">조회자</option></select></label></>) : (<><label>토큰 이름<input name="name" required autoFocus /></label><label>허용 서비스<select name="serviceId" required><option value="" disabled>서비스를 선택하세요</option>{services.map((item) => (<option key={item.id} value={item.id}>{item.name}</option>))}</select></label><small>서비스 범위 토큰입니다. 토큰 원문은 지금만 표시되며 서버에는 해시만 저장됩니다.</small></>)}{message && <p className="form-message">{message}</p>}<footer><button type="button" className="secondary" onClick={() => setMode(null)}>닫기</button><button className="primary" disabled={busy}>{busy ? "처리 중…" : "확인"}</button></footer></form></section></div>)}
  </section>);
}

function GenericPage({ rows }: { rows: string[][] }) {
  return (<section className="page generic-page"><h1>대시보드</h1><p>서비스와 최신 SBOM 회차의 운영 상태를 확인합니다.</p><div className="table-frame"><table><thead><tr><th>이름</th><th>구분</th><th>값</th><th>상태/시각</th></tr></thead><tbody>{rows.length ? (rows.map((row) => (<tr key={row.join()}>{row.map((cell) => (<td key={cell}>{cell}</td>))}</tr>) )
            ): (<tr><td colSpan={4}>표시할 데이터가 없습니다.</td></tr>)}</tbody></table></div></section>);}

export function LoginPage({ onAuthenticated }: { onAuthenticated: (user: AuthUser) => void;}) {
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [mode, setMode] = useState<"login" | "register">("login");
  const [notice, setNotice] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage("");
    setNotice(false);
    const values = new FormData(event.currentTarget);
    try {
      if (mode === "register") {
        const result = await register(String(values.get("username") || ""), String(values.get("password") || ""), String(values.get("passwordConfirm") || ""));
        setMode("login");
        setNotice(true);
        setMessage(result.detail);
        return;
      }
      const result =await login(String(values.get("username") || ""), String(values.get("password") || ""), values.get("useLdap") === "on");
      onAuthenticated(result.user as AuthUser);} catch (error) {
      setMessage(error instanceof Error ? error.message : "로그인에 실패했습니다");} finally {
      setBusy(false);}
  }
  return (<main className="login-page"><section className="login-card">
    <span className="login-mark">K</span><p className="eyebrow">KODA SECURITY OPERATIONS</p>
    <h1>KODA SBOM Tracker</h1><p>{mode === "login" ? "폐쇄망 SBOM 회차·분석 운영 포털" : "로컬 계정 가입 신청"}</p>
    <form onSubmit={submit}>
      <label>사용자 이름
            <input name="username" autoComplete="username" required autoFocus /></label>
      <label>비밀번호
            <input name="password" type="password" minLength={mode === "register" ? 12 : undefined} autoComplete={mode === "register" ? "new-password" : "current-password"} required /></label>
      {mode === "register" && (<label>비밀번호 확인
            <input name="passwordConfirm" type="password" minLength={12} autoComplete="new-password" required /></label>)}
      {mode === "login" && (<label className="login-checkbox">
            <input name="useLdap" type="checkbox" /> LDAP 사용</label>)}
      {message && (<p className={notice ? "login-notice" : "login-error"} role={notice ? "status" : "alert"}>{message}</p>)}
      <button className="primary" disabled={busy}>{busy ? "확인 중…" : mode === "login" ? "로그인" : "가입 신청"}</button>
    </form>
    <button type="button" className="secondary login-switch" disabled={busy} onClick={() => { setMode(mode === "login" ? "register" : "login"); setMessage(""); setNotice(false); }}>{mode === "login" ? "회원가입" : "로그인으로 돌아가기"}</button>
    <small>{mode === "login" ? "내부망 전용 · 승인된 사용자만 접근할 수 있습니다." : "가입 후 관리자가 승인하면 Tracker와 KODA에 로그인할 수 있습니다."}</small>
  </section></main>);}

export default function App() {
  const demoServices = [...new Map(demoRuns.map((run) => [run.service.id, run.service])).values()];
  const demoEnvironments = [...new Map(demoRuns.map((run) => [run.environment.id, run.environment])).values()];
  const [initialLink] = useState(readPortalLink);
  const [page, setPage] = useState<Page>(initialLink.page);
  const [collapsed, setCollapsed] = useState(false);
  const [globalSearch, setGlobalSearch] = useState("");
  const [runs, setRuns] = useState<SbomRun[]>(previewMode ? demoRuns : []);
  const [searchedRuns, setSearchedRuns] = useState<{ query: string; runs: SbomRun[] } | null>(null);
  const [services, setServices] = useState<CatalogItem[]>(previewMode ? demoServices : []);
  const [environments, setEnvironments] = useState<CatalogItem[]>(previewMode ? demoEnvironments : []);
  const [authenticated, setAuthenticated] = useState<boolean | null>(previewMode ? true : null);
  const [authUser, setAuthUser] = useState<AuthUser | null>(
    previewMode
      ? {
          id: "preview",
          username: "preview",
          displayName: "미리보기 사용자",
          department: "보안운영팀",
          role: "admin",
          active: true,
          status: "active",
          permissions: ["*"]}
      : null);
  const [rolePolicyCatalog, setRolePolicyCatalog] = useState<string[]>([]);
  const [rolePolicies, setRolePolicies] = useState<RolePolicy[]>([]);
  const [genericRows, setGenericRows] = useState<Record<string, string[][]>>({});
  const [bundles, setBundles] = useState<VulnerabilityBundle[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [users, setUsers] = useState<UserSummary[]>([]);
  const [tokens, setTokens] = useState<ApiTokenSummary[]>([]);
  const [dtrackStatus, setDtrackStatus] = useState<DependencyTrackStatus | null>(null);
  const [loadError, setLoadError] = useState("");
  const [uploadOpen, setUploadOpen] = useState(false);
  const [selectedRun, setSelectedRun] = useState<SbomRun | null>(() =>
    initialLink.runId ? demoRuns.find((run) => run.id === initialLink.runId) || null : null);
  const openRun = useCallback((run: SbomRun) => {
    setPage("runs");
    setSelectedRun(run);
    replacePortalLink({ page: "runs", runId: run.id });}, []);
  const closeRun = useCallback(() => {
    setSelectedRun(null);
    replacePortalLink({ runId: null });}, []);
  const navigate = useCallback((nextPage: Page) => {
    setPage(nextPage);
    if (nextPage !== "runs") setSelectedRun(null);
    replacePortalLink(nextPage === "runs" ? { page: nextPage } : { page: nextPage, runId: null });}, []);
  const permissions = useMemo(() => permissionSet(authUser), [authUser]);
  const can = useCallback(
    (permission: string) => permissions.has("*") || permissions.has(permission),
    [permissions]);
  const canUpload = hasPermissions(authUser, "sbom.upload", "services.view");
  const loadData = useCallback(async (loadedUser: AuthUser | null) => {
    setLoadError("");
    const loadedPermissions = permissionSet(loadedUser);
    const loadCan = (permission: string) => loadedPermissions.has("*") || loadedPermissions.has(permission);
    const access = dataAccess(loadedUser);
    let nextRuns: SbomRun[];
    let catalogs: { services: CatalogItem[]; environments: CatalogItem[] };
    try {
      [nextRuns, catalogs] = await Promise.all([
        access.runs ? fetchRuns() : Promise.resolve([] as SbomRun[]),
        access.catalogs ? fetchCatalogs() : Promise.resolve({ services: [], environments: [] }),
      ]);
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "데이터를 불러오지 못했습니다.");
      return [];
    }
    setRuns(nextRuns);
    setServices(catalogs.services);
    setEnvironments(catalogs.environments);
    if (initialLink.runId) {
      const linkedRun = nextRuns.find((run) => run.id === initialLink.runId);
      if (linkedRun) {
        setPage("runs");
        setSelectedRun(linkedRun);}
    }
    if (!demoMode && !standaloneMode) {
      const [auditResult, usersResult, bundlesResult, tokensResult, dtrackResult] = await Promise.allSettled([
        loadedUser?.role === "admin" && loadCan("audit.view") ? fetchAuditEvents(): Promise.resolve([]),
        loadCan("users.manage") ?fetchUsers(): Promise.resolve([]),
        loadedUser?.role === "admin" && loadCan("vulnerability.view")
          ?fetchVulnerabilityBundles(): Promise.resolve([]),
        loadCan("tokens.manage") ?fetchApiTokens(): Promise.resolve([]),
        loadCan("dtrack.settings")
          ?fetchDependencyTrackStatus()
          : Promise.resolve(null)]);
      if (auditResult.status === "fulfilled") setAuditEvents(auditResult.value);
      if (usersResult.status === "fulfilled") setUsers(usersResult.value);
      if (bundlesResult.status === "fulfilled") setBundles(bundlesResult.value);
      if (tokensResult.status === "fulfilled") setTokens(tokensResult.value);
      if (dtrackResult.status === "fulfilled") setDtrackStatus(dtrackResult.value);
      setGenericRows({
        dashboard: [
          ["등록 서비스", "서비스", String(catalogs.services.length), "활성"],
          ["SBOM 회차", "회차", String(nextRuns.length), nextRuns[0]?.createdAt || "-"],
          ["일부 실패", "처리 상태", String(nextRuns.filter((run) => run.state === "partial" || run.state === "failed").length), "검토 필요"]],
        services: catalogs.services.map((service) => [service.name, service.slug, service.id, "활성"]),
        audit: auditResult.status === "fulfilled" ? auditResult.value.map((item) => [item.actor, item.action, `${item.targetType}:${item.targetId}`, item.createdAt]) : [],
        settings: usersResult.status === "fulfilled" ? usersResult.value.map((item) => [item.username, item.role, item.active ? "활성" : "비활성", "-"]) : [],
        vuln: []});}
    if (standaloneMode) {
      setGenericRows({
        dashboard: [
          ["로컬 미리보기", "실행 모드", "standalone", "브라우저 분석"],
          ["업로드 회차", "SBOM", String(nextRuns.filter((run) => run.id.startsWith("standalone-")).length), "확인 가능"],
          ["서버 연동", "Docker·로그인·Dependency-Track", "사용 안 함", "미리보기"]]});}
    if (loadCan("roles.manage")) {
      try {
        const result = await fetchRolePolicies();
        setRolePolicyCatalog(result.catalog);
        setRolePolicies(result.roles);
      } catch (error) {
        setLoadError(error instanceof Error ? error.message : "역할 정책을 불러오지 못했습니다.");
      }}
    return nextRuns;}, [initialLink.runId]);
  useEffect(() => {
    if (demoMode) return;
    if (standaloneMode) {
      void resumeSession().then((session) => loadData(session.user));
      return;}
    resumeSession()
      .then((session) => { setAuthUser(session.user);setAuthenticated(true); return loadData(session.user);})
      .catch(() => setAuthenticated(false));}, [loadData]);
  useEffect(() => {
    setForbiddenHandler(async () => {
      try {
        const session = await resumeSession();
        setAuthUser(session.user);
        await loadData(session.user);
        const nextPage = pageForPermissions(session.user, page);
        if (nextPage && nextPage !== page) navigate(nextPage);} catch {
        setAuthenticated(false);}
    });
    return () => setForbiddenHandler(undefined);}, [loadData, navigate, page]);
  useEffect(() => {
    const listener = () => window.innerWidth <= 1024 && setCollapsed(true);
    listener(); window.addEventListener("resize", listener); return () => window.removeEventListener("resize", listener);}, []);
  useEffect(() => {
    const term = authenticated === true && page === "runs" ? globalSearch.trim() : "";
    if (!term) return;
    let cancelled = false;
    const timer = window.setTimeout(() => {
      void fetchRuns(term)
        .then((items) => { if (!cancelled) setSearchedRuns({ query: term, runs: items }); })
        .catch((error) => { if (!cancelled) setLoadError(error instanceof Error ? error.message : "검색에 실패했습니다."); })
    }, 250);
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [authenticated, globalSearch, page]);
  const searchQuery = authenticated === true && page === "runs" ? globalSearch.trim() : "";
  const searchingRuns = Boolean(searchQuery && searchedRuns?.query !== searchQuery);
  const displayedRuns = !searchQuery ? runs : searchedRuns?.query === searchQuery ? searchedRuns.runs : EMPTY_RUNS;
  const content = useMemo(() => {
    if (page === "dashboard" ) return (<Dashboard runs={runs} onUpload={() => setUploadOpen(true)} canUpload={canUpload}
          standalone={standaloneMode}/>);
    if (page === "runs") return (<RunsPage runs={displayedRuns} searching={searchingRuns}
          canUpload={canUpload} onUpload={() => setUploadOpen(true)} onSelect={openRun} />);
    if (page === "compare") return <ComparePage runs={runs} can={can} />;
    if (page === "services") return (<ServicesPage services={services} environments={environments} onChanged={() => void loadData(authUser)} canManage={can("catalog.manage")}/>);
    if (page === "settings") return (<SettingsPage users={users} services={services} tokens={tokens} dtrackStatus={dtrackStatus} policies={rolePolicies}
          roleCatalog={rolePolicyCatalog}
          bundles={bundles}
          auditEvents={auditEvents}
          isAdmin={authUser?.role === "admin"}
          canVulnerability={can("vulnerability.view")}
          canVulnerabilityManage={can("vulnerability.manage")}
          canAudit={can("audit.view")}
          canUsers={can("users.manage")}
          canTokens={hasPermissions(authUser, "tokens.manage", "services.view")}
          canDtrack={can("dtrack.settings")}
          canRoles={can("roles.manage")}
          canPolicyEdit={can("roles.manage")}
          onSync={async () => { const items = await syncVulnerabilityBundles(); setBundles(items);}}
          onActivate={async (version) => { await activateVulnerabilityBundle(version); const items = await fetchVulnerabilityBundles(); setBundles(items);}}
          onPolicyChanged={async (next) => {
            setRolePolicies(next);
            const session = await resumeSession();
            setAuthUser(session.user);
            await loadData(session.user);
            const nextPage = pageForPermissions(session.user, page);
            if (nextPage && nextPage !== page) navigate(nextPage);
          }}onChanged={() => void loadData(authUser)} />);
    return <GenericPage rows={genericRows.dashboard || []} />;}, [auditEvents, bundles, can,dtrackStatus, displayedRuns, environments, genericRows, loadData, openRun, page, runs, searchingRuns, services, tokens, users,
    rolePolicyCatalog,
    rolePolicies, authUser, navigate, canUpload]);
  useEffect(() => {
    const nextPage = pageForPermissions(authUser, page);
    if (nextPage && nextPage !== page) queueMicrotask(() => navigate(nextPage));}, [authUser, navigate, page]);
  if (authenticated === null) return <div className="auth-loading">세션을 확인하고 있습니다…</div>;
  if (!authenticated) return (<LoginPage onAuthenticated={(user) => { setAuthUser(user);setAuthenticated(true); void loadData(user);}} />);
  const permittedPage = pageForPermissions(authUser, page);
  if (!permittedPage) return <div className="auth-loading">허용된 화면이 없습니다.</div>;
  if (permittedPage !== page) return null;
  return (<div className={`app-shell ${collapsed ? "is-collapsed" : ""}`}>
    <Sidebar page={page} collapsed={collapsed} can={can}onNavigate={(next) => can(PAGE_PERMISSIONS[next]) &&navigate(next)} />
    <Header collapsed={collapsed} search={globalSearch} onSearch={(value) => { setGlobalSearch(value); if (value.trim() && page !== "runs" && can("runs.view")) navigate("runs"); }} dataAsOf={runs.map((run) => run.dataAsOf).filter(Boolean).sort().at(-1) || ""} onToggle={() => setCollapsed((value) => !value)} onLogout={() => {
      void logout()
        .then(() => {
          setAuthUser(null);
          setSelectedRun(null);
          replacePortalLink({ runId: null });
          setAuthenticated(false);
        })
        .catch((error) => setLoadError(error instanceof Error ? error.message : "로그아웃에 실패했습니다."));
    }} preview={previewMode} user={authUser} />
    <main>{loadError && <p className="form-message" role="alert">{loadError}</p>}{standaloneMode && (<div className="standalone-banner" role="status"><strong>로컬 미리보기 모드</strong><span>로그인·Docker 없이 CycloneDX 구조와 파일 내장 취약점 레코드만
              표시합니다.
            </span></div>)}{content}</main>
    {uploadOpen && canUpload && (<UploadModal services={services} environments={environments} onClose={() => setUploadOpen(false)} onUploaded={(runId) => { setUploadOpen(false); void loadData(authUser).then((nextRuns) => { const uploaded = nextRuns.find((run) => run.id === runId); if (uploaded) openRun(uploaded);});}} />)}
    {selectedRun && (<RunDetail run={selectedRun}
          can={can} onClose={closeRun} onChanged={() => void loadData(authUser)} />)}
  </div>);}

import { useCallback, useDeferredValue, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { demoMode, previewMode, standaloneMode, activateVulnerabilityBundle, approveUser, archiveRun, createApiToken, createAnalysis, createEnvironment, createService, createUser, deleteRun, deleteUser, fetchAuditEvents, fetchApiTokens, fetchCatalogs, fetchComparison, fetchDependencyTrackStatus, fetchJob, fetchLdapSettings, fetchRun, fetchRunComponents, fetchRunFindings, fetchRuns, fetchUsers, fetchVulnerabilityBundles, login, patchEnvironment, patchService, patchUser, logout, register, resumeSession, retryDependencyTrack, revokeApiToken, updateLdapSettings, uploadRun, syncVulnerabilityBundles, fetchRolePolicies, updateRolePolicies, setForbiddenHandler, uploadVulnerabilityData, fetchVulnerabilityDataJob, applyVulnerabilityDataJob, rollbackVulnerabilityData } from "./api";
import { demoChanges, demoLdapSettings, demoRolePolicyCatalog, demoRuns } from "./demo";
import { formatSeoulDateTime } from "./format";
import { Icon } from "./icons";
import { ReanalysisSchedulePanel } from "./ReanalysisSchedule";
import { PackageMetadataPanel, LegacyMigrationPanel } from "./OperationsData";
import { ProjectCatalogPanel } from "./ProjectCatalog";
import { PrivateVulnerabilitiesPanel } from "./PrivateVulnerabilities";
import { NotificationsPanel } from "./Notifications";
import { VexReviewsPanel } from "./VexReviews";
import { SbomQualityPanel } from "./SbomQuality";
import { SbomPoliciesPanel } from "./SbomPolicies";
import { AnalysisPolicyHistory, NativePolicyResult } from "./NativePolicyResult";
import { policyCountLabel } from "./policy";
import { canPage, dataAccess, hasPermissions, pageForPermissions, permissionSet, type Page } from "./permissions";
import type { AnalysisRevisionSummary, AuditEvent, AuthUser, CatalogItem, Comparison, ComponentChange, ComponentSnapshot, DependencyTrackStatus, LdapSettings, RecordChange, RolePolicy, SbomRun, SbomRunDetail, UserSummary, VulnerabilityBundle } from "./types";

const nav: { id: Page; label: string; icon: string }[] = [
  { id: "dashboard", label: "대시보드", icon: "dashboard" },
  { id: "runs", label: "SBOM 회차", icon: "runs" },
  { id: "compare", label: "회차 비교", icon: "compare" },
  { id: "settings", label: "설정", icon: "settings" }];
const guideNav = { id: "guide" as Page, label: "사용 가이드", icon: "guide" };

type SettingsTab = "private-vulnerabilities" | "metadata" | "migration" | "reanalysis" | "notifications" | "sbom-policies" | "users" | "roles" | "vulnerability" | "audit" | "integration" | "ldap" | "services";

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
  "dtrack.retry": "기존 외부 시스템 재시도",
  "sbom.archive": "회차 보관",
  "sbom.delete": "회차 영구 삭제",
  "catalog.manage": "서비스·환경 관리",
  "vulnerability.manage": "취약점 데이터 관리",
  "users.manage": "사용자 관리",
  "tokens.manage": "API 토큰 관리",
  "dtrack.settings": "기존 외부 시스템 연결 설정",
  "roles.manage": "권한 정책 관리",
  "policies.view": "SBOM 정책 조회",
  "policies.manage": "SBOM 정책 관리",
  "reanalysis.view": "재분석 일정 조회", "reanalysis.manage": "재분석 일정 관리",
  "vex.view": "VEX 검토 조회", "vex.manage": "VEX 검토 요청", "vex.approve": "VEX 검토 승인",
  "metadata.view": "패키지 메타데이터 조회", "metadata.manage": "패키지 메타데이터 수집", "migrations.manage": "기존 시스템 이관",
  "notifications.view": "알림 조회", "notifications.manage": "알림 전송 관리",
};

const PERMISSION_GROUPS: { label: string; permissions: string[] }[] = [
  { label: "화면 조회", permissions: ["dashboard.view", "runs.view", "compare.view", "settings.view"] },
  { label: "SBOM·분석", permissions: ["sbom.upload", "artifact.download", "analysis.create", "dtrack.retry", "sbom.archive", "sbom.delete"] },
  { label: "운영 관리", permissions: ["catalog.manage", "vulnerability.manage", "metadata.view", "metadata.manage", "migrations.manage", "policies.view", "policies.manage", "reanalysis.view", "reanalysis.manage", "vex.view", "vex.manage", "vex.approve", "notifications.view", "notifications.manage", "dtrack.settings"] },
  { label: "계정·권한", permissions: ["users.manage", "tokens.manage", "roles.manage"] },
];

const POLICY_SECTIONS = [
  { label: "화면 접근 권한", description: "역할별로 접근할 수 있는 화면을 설정합니다.", groups: PERMISSION_GROUPS.slice(0, 1) },
  { label: "기능 제어", description: "화면 안에서 실행할 수 있는 작업을 설정합니다.", groups: PERMISSION_GROUPS.slice(1) },
];

const pageIds = new Set<Page>([...nav.map((item) => item.id), guideNav.id]);
function readPortalLink() {
  const params = new URLSearchParams(window.location.search);
  const requestedPage = params.get("page");
  const requestedSettingsTab = params.get("settingsTab");
  const legacyServices = requestedPage === "services";
  return {
    page: legacyServices ? "settings" as Page : requestedPage && pageIds.has(requestedPage as Page) ? (requestedPage as Page ): ("dashboard" as Page),
    settingsTab: legacyServices ? "services" as SettingsTab : requestedSettingsTab === "gitlab" ? "integration" as SettingsTab : (requestedSettingsTab as SettingsTab | null),
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
  if (user.status === "deleted") return "삭제됨";
  if (user.status === "inactive" || !user.active) return "비활성";
  return "활성";
}

function roleLabel(role: string) {
  return ROLE_LABELS[role] || role || "-";
}

function permissionLabel(permission: string) {
  return PERMISSION_LABELS[permission] || permission;
}

async function copyOrShow(label: string, value: string) {
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    window.prompt(label, value);
  }
}

function dataBaselineLabel(value: string | null | undefined, empty = "아직 반입된 분석 데이터 없음") {
  return value && value !== "unknown" ? value : empty;
}

function preferredCveDate(cveDataAsOf: string | null | undefined, dataAsOf: string | null | undefined) {
  return cveDataAsOf && cveDataAsOf !== "unknown" ? cveDataAsOf : dataAsOf;
}

function cveBaseline(run: Pick<SbomRun, "cveDataAsOf" | "dataAsOf"> | null | undefined) {
  return dataBaselineLabel(preferredCveDate(run?.cveDataAsOf, run?.dataAsOf), "CVE 기준일 확인 필요");
}

function cvssScore(record: Record<string, unknown>) {
  if (record.cvssScore !== undefined && record.cvssScore !== null && !["", "-"].includes(String(record.cvssScore).trim())) return String(record.cvssScore);
  const payload = record.nvdCvss;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return "-";
  const score = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(score).find((item) => item !== undefined && item !== null && String(item) !== "");
    if (!value || typeof value !== "object") return undefined;
    const values = value as Record<string, unknown>;
    for (const key of ["baseScore", "base_score"]) {
      if (values[key] !== undefined && values[key] !== null && !["", "-"].includes(String(values[key]).trim())) return values[key];
    }
    return score(values.cvssData);
  };
  const values = payload as Record<string, unknown>;
  for (const key of ["cvssV4", "cvssV4_0", "cvssV40", "cvssV4.0", "cvssMetricV40", "cvssMetricV4", "cvssV3", "cvssV31", "cvssV3_1", "cvssV3.1", "cvssV30", "cvssMetricV31", "cvssMetricV30", "cvssV2", "cvssMetricV2"]) {
    const found = score(values[key]);
    if (found !== undefined) return String(found);
  }
  const found = score(values);
  return found === undefined ? "-" : String(found);
}

function fixedInLabel(record: Record<string, unknown>) {
  const value = record.fixedIn;
  return Array.isArray(value) ? value.filter(Boolean).join(", ") || "-" : value ? String(value) : "-";
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
  const accountLabel = user?.username || (preview ? "preview" : "사용자");

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
      <div className="freshness">CVE 기준일: {dataBaselineLabel(dataAsOf, "확인 필요")}</div>
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
              <div><strong>{displayName}</strong></div>
            </div>
            <dl className="account-details">
              <div><dt>아이디</dt><dd>{user?.username || "-"}</dd></div>
              <div><dt>역할</dt><dd>{roleLabel(user?.role || "")}</dd></div>
            </dl>
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

function Sidebar({ page, collapsed, onNavigate, onExpand,
  canNavigatePage}: { page: Page; collapsed: boolean; onNavigate: (page: Page) => void; onExpand: () => void;
  canNavigatePage: (page: Page) => boolean;}) {
  return (
    <aside className={`sidebar ${collapsed ? "collapsed" : ""}`}>
      <div className="brand"><button type="button" className="brand-logo-toggle" onClick={onExpand} aria-label="KODA 로고로 사이드바 펼치기" aria-expanded={!collapsed}><img className="brand-mark" src="/KODA.ico" alt="" /></button><strong>KODA SBOM Tracker</strong></div>
      <nav aria-label="주 메뉴">
        {nav.filter((item) => canNavigatePage(item.id)).map((item) => (
          <button type="button" key={item.id} className={page === item.id ? "active" : ""} onClick={() => onNavigate(item.id)} title={item.label}>
            <Icon name={item.icon} /><span>{item.label}</span>
          </button>
        ))}
        {!previewMode && <KodaPortalLink />}
      </nav>
      <nav className="sidebar-guide" aria-label="도움말 메뉴">
        <button type="button" className={page === guideNav.id ? "active" : ""} onClick={() => onNavigate(guideNav.id)} title={guideNav.label}>
          <Icon name={guideNav.icon} /><span>{guideNav.label}</span>
        </button>
      </nav>
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

function chartPoints(values: number[], width: number, height: number, padding = 4, maximum = Math.max(1, ...values)) {
  const plotWidth = width - padding * 2;
  const plotHeight = height - padding * 2;
  return values.map((value, index) => ({
    x: values.length === 1 ? width / 2 : padding + (index / (values.length - 1)) * plotWidth,
    y: padding + (1 - value / maximum) * plotHeight}));}

function pathFor(values: number[], width: number, height: number, maximum?: number) {
  return chartPoints(values, width, height, 4, maximum).map((point, index) => `${index ? "L" : "M"}${point.x.toFixed(1)},${point.y.toFixed(1)}`).join(" ");}

type ChartTooltip = { x: number; y: number; text: string };

function ImmediateChartTooltip({ tooltip }: { tooltip: ChartTooltip | null }) {
  if (!tooltip) return null;
  return <span className="preview-chart-tooltip" role="tooltip" style={{ left: `${tooltip.x}%`, top: `${tooltip.y}%` }}>{tooltip.text}</span>;
}

function Sparkline({ values, color, label, pointLabels = [] }: { values: number[]; color: string; label: string; pointLabels?: string[];}) {
  const points = chartPoints(values, 100, 28, 3);
  const [tooltip, setTooltip] = useState<ChartTooltip | null>(null);
  return (<div className="preview-sparkline-wrap"><svg className="preview-sparkline" viewBox="0 0 100 28" role="img" aria-label={`${label} 추이`}>
    <path d={pathFor(values, 100, 28)} fill="none" stroke={color} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
    {points.map((point, index) => { const text = `${pointLabels[index] || label}: ${values[index] ?? 0}`; const show = () => setTooltip({ x: Math.max(16, Math.min(84, point.x)), y: (point.y / 28) * 100, text }); return (<circle className="preview-chart-point" key={`${point.x}-${point.y}`} cx={point.x} cy={point.y} r="2.5" fill={color} role="img" aria-label={text} tabIndex={0} onMouseEnter={show} onMouseLeave={() => setTooltip(null)} onFocus={show} onBlur={() => setTooltip(null)} />);})}
  </svg><ImmediateChartTooltip tooltip={tooltip} /></div>);}

function PreviewMetric({ label, value, description, values, color, pointLabels }: { label: string; value: string; description: string; values: number[]; color: string; pointLabels?: string[];}) {
  return (<article className="preview-metric-card">
    <div><span className="preview-metric-label">{label}</span><strong>{value}</strong><small>{description}</small></div>
    <Sparkline values={values} color={color} label={label} pointLabels={pointLabels} />
  </article>);}

function PreviewBars({ items, emptyLabel }: { items: { label: string; value: number; tone?: string }[]; emptyLabel: string;}) {
  const maximum = Math.max(1, ...items.map((item) => item.value));
  if (!items.some((item) => item.value)) return <p className="preview-chart-empty">{emptyLabel}</p>;
  return (<div className="preview-bars">{items.map((item) => (<div className="preview-bar-row" key={item.label}>
    <span>{item.label}</span><div className="preview-bar-track"><i className={item.tone || ""} style={{ width: `${(item.value / maximum) * 100}%` }} /></div><strong>{item.value}</strong>
  </div>))}</div>);}

export function Dashboard({ runs, onUpload,
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
  const [trendTooltip, setTrendTooltip] = useState<ChartTooltip | null>(null);

  const latest = uploadedRuns.at(-1);
  const severityCounts = latest?.severityCounts || {};
  const kevCount = latest?.kevCount || 0;
  const severityItems = [
    { label: "Critical", value: severityCounts.critical || 0, tone: "critical" },
    { label: "High", value: severityCounts.high || 0, tone: "high" },
    { label: "Medium", value: severityCounts.medium || 0, tone: "medium" },
    { label: "Low", value: severityCounts.low || 0, tone: "low" },
    { label: "Unknown", value: severityCounts.unknown || 0, tone: "unknown" }];
  const componentTypes = Object.entries(latest?.componentTypeCounts || {}).map(([label, value]) => ({ label, value }));
  const pointLabel = (run: SbomRun) => `#${run.roundNumber} · ${run.service.name}/${run.environment.name} · CVE 기준일 ${cveBaseline(run)}`;
  const componentTypeCount = Object.keys(latest?.componentTypeCounts || {}).length;
  const vulnerableComponents = (run: SbomRun) => run.vulnerableComponentCount ?? run.vulnerabilityCount;

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
    { label: "취약 구성요소", color: "#a970ff", values: chartRuns.map(vulnerableComponents) }];
  const trendMaximum = Math.max(1, ...series.flatMap((item) => item.values));
  return (<section className="page preview-dashboard-page">
    <div className="page-heading"><div><p className="preview-eyebrow">{standalone ? "LOCAL" : "OPERATIONS"} SBOM PORTFOLIO
          </p><h1>대시보드</h1><p className="preview-dashboard-subtitle">등록된 SBOM {uploadedRuns.length}건의 분석 결과입니다.{" "}
            {standalone ? "브라우저 내 미리보기 데이터" : "최신 분석 리비전"}을
            집계합니다.
          </p></div>{canUpload && (<button className="primary" onClick={onUpload}><Icon name="upload" />SBOM 업로드
          </button>)}
      </div>
    <div className="preview-metrics">
      <PreviewMetric label="구성요소 유형" value={componentTypeCount.toLocaleString()} description="최신 SBOM의 고유 유형" values={chartRuns.map((run) => Object.keys(run.componentTypeCounts || {}).length)} color="#32c6d1" pointLabels={chartRuns.map(pointLabel)} />
      <PreviewMetric label="구성요소" value={(latest?.componentCount || 0).toLocaleString()} description={`최신 · ${latest?.filename || "SBOM"}`} values={chartRuns.map((run) => run.componentCount)} color="#32c6d1" pointLabels={chartRuns.map(pointLabel)} />
      <PreviewMetric label="취약 구성요소" value={(latest ? vulnerableComponents(latest) : 0).toLocaleString()} description="취약점이 있는 고유 구성요소" values={chartRuns.map(vulnerableComponents)} color="#a970ff" pointLabels={chartRuns.map(pointLabel)} />
      <PreviewMetric label="KEV" value={kevCount.toLocaleString()} description={standalone ?"내장 KEV 플래그" : "분석 결과 KEV 플래그"} values={chartRuns.map((run) => run.kevCount || 0)} color="#ff8b8b" pointLabels={chartRuns.map(pointLabel)} />
    </div>
    <div className="preview-chart-grid">
      <article className="preview-chart-card preview-trend-card"><header><div><h2>업로드별 분석 추이</h2><p>최근 SBOM 회차의 구성요소·취약 구성요소 변화</p></div><span className="preview-chart-meta">{cveBaseline(latest)}</span></header>
        <div className="preview-legend">{series.map((item) => (<span key={item.label}><i style={{ background: item.color }} />{item.label}</span>))}</div>
        <div className="preview-chart-scroll"><div className="preview-chart-canvas"><svg className="preview-chart" viewBox="0 0 760 250" role="img" aria-label="업로드별 구성요소와 취약 구성요소 추이">
          <title>업로드별 구성요소와 취약 구성요소 추이</title>
          {[50, 105, 160, 215].map((y) => (<line key={y} x1="36" x2="744" y1={y} y2={y} className="preview-grid-line" />))}
          {series.map((item) => (<g key={item.label}><path d={pathFor(item.values, 708, 165, trendMaximum)} transform="translate(36 45)" fill="none" stroke={item.color} strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />{chartPoints(item.values, 708, 165, 4, trendMaximum).map((point, index) => { const run = chartRuns[index]; const x = point.x + 36; const y = point.y + 45; const text = `${item.label} · #${run.roundNumber} · ${run.service.name}/${run.environment.name} · ${item.values[index]} · CVE 기준일 ${cveBaseline(run)}`; const show = () => setTrendTooltip({ x: Math.max(14, Math.min(86, (x / 760) * 100)), y: (y / 250) * 100, text }); return (<circle className="preview-chart-point" key={`${item.label}-${index}`} cx={x} cy={y} r="4" fill={item.color} role="img" aria-label={text} tabIndex={0} onMouseEnter={show} onMouseLeave={() => setTrendTooltip(null)} onFocus={show} onBlur={() => setTrendTooltip(null)} />); })}</g>))}
          {chartRuns.map((run, index) => (<text key={run.id} x={chartRuns.length === 1 ? 390 : 36 + (index / (chartRuns.length - 1)) * 708} y="238" textAnchor="middle" className="preview-axis-label">#{uploadedRuns.length - chartRuns.length + index + 1}</text>))}
        </svg><ImmediateChartTooltip tooltip={trendTooltip} /></div></div>
      </article>
      <article className="preview-chart-card"><header><div><h2>최신 SBOM 심각도</h2><p>{latest?.filename || "업로드 파일"}</p></div><span className="preview-chart-total">{latest?.vulnerabilityCount || 0}건</span></header>
        <PreviewBars items={severityItems} emptyLabel="최신 분석에 취약점 레코드가 없습니다." />
        <div className="preview-chart-footnote">CVE 기준일 {cveBaseline(latest)} · KEV {kevCount}건
          </div>
      </article>
    </div>
    <div className="preview-lower-grid">
      <article className="preview-chart-card"><header><div><h2>구성요소 유형</h2><p>최신 업로드 기준</p></div><span className="preview-chart-total">{latest?.componentCount || 0}개
            </span></header><PreviewBars items={componentTypes} emptyLabel="구성요소 상세를 불러오는 중입니다." /></article>
      <article className="preview-upload-summary"><span className="preview-eyebrow">LATEST UPLOAD</span><h2>{latest?.filename || "SBOM 파일"}</h2><dl><dt>릴리스</dt><dd>{latest?.releaseVersion}</dd><dt>CVE 기준일</dt><dd>{cveBaseline(latest)}</dd><dt>업로드 시각</dt><dd>{latest ? formatSeoulDateTime(latest.createdAt) : "-"}</dd></dl></article>
    </div>
  </section>);}

function RunsPage({ runs, services, environments, search, onUpload, onSelect,
  canUpload}: { runs: SbomRun[]; services: CatalogItem[]; environments: CatalogItem[]; search: string; onUpload: () => void; onSelect: (run: SbomRun) => void;
  canUpload: boolean;}) {
  const [service, setService] = useState("");
  const [environment, setEnvironment] = useState("");
  const [state, setState] = useState("");
  const [source, setSource] = useState<"manual" | "scheduled">("manual");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [result, setResult] = useState({ items: runs.slice(0, 10), page: 1, size: 10, total: runs.length });
  const [searching, setSearching] = useState(false);
  const [error, setError] = useState("");
  const deferredSearch = useDeferredValue(search.trim());
  useEffect(() => { queueMicrotask(() => setPage(1)); }, [deferredSearch]);
  useEffect(() => {
    let cancelled = false;
    queueMicrotask(() => {
      if (!cancelled) {
        setSearching(true);
        setError("");
      }
    });
    void fetchRuns({ page, size: pageSize, q: deferredSearch, serviceId: service, environmentId: environment, state, source })
      .then((next) => { if (!cancelled) setResult(next); })
      .catch((reason) => { if (!cancelled) setError(reason instanceof Error ? reason.message : "회차를 불러오지 못했습니다."); })
      .finally(() => { if (!cancelled) setSearching(false); });
    return () => { cancelled = true; };
  }, [deferredSearch, environment, page, pageSize, runs, service, source, state]);
  const pageCount = Math.max(1, Math.ceil(result.total / pageSize));
  const currentPage = Math.min(page, pageCount);
  const visible = result.items;
  const dataAsOf = visible.map((run) => preferredCveDate(run.cveDataAsOf, run.dataAsOf)).filter((value): value is string => Boolean(value) && value !== "unknown").sort().at(-1);
  const queued = visible.filter((run) => run.state === "queued" || run.state === "processing").length;
  const failed = visible.filter((run) => run.state === "failed" || run.state === "partial").length;
  return (
    <section className="page runs-page">
      <div className="page-heading">
        <div><h1>SBOM 회차</h1>{canUpload && (<button className="primary" onClick={onUpload}><Icon name="upload" />SBOM 업로드
            </button>)}
        </div>
        <div className="status-summary">
          <span>최신 CVE 기준일 <strong>{dataBaselineLabel(dataAsOf, "CVE 기준일 확인 필요")}</strong></span>
          <i />
          <span>대기 작업 <strong className="warning">{queued}건</strong></span>
          <i />
          <span>실패 작업 <strong className="danger">{failed}건</strong></span>
        </div>
      </div>
      <div className="filters">
        <SelectFilter label="서비스" value={service} values={services.filter((item) => item.active !== false).map((item) => item.id)} onChange={(value) => { setService(value); setPage(1); }} formatValue={(value) => services.find((item) => item.id === value)?.name || value} />
        <SelectFilter label="환경" value={environment} values={environments.filter((item) => item.active !== false).map((item) => item.id)} onChange={(value) => { setEnvironment(value); setPage(1); }} formatValue={(value) => environments.find((item) => item.id === value)?.name || value} />
        <SelectFilter label="상태" value={state} values={["completed", "processing", "partial", "failed", "queued", "archived"]} onChange={(value) => { setState(value); setPage(1); }} formatValue={(value) => stateLabel(value as SbomRun["state"])} />
        <button className="secondary reset" onClick={() => { setService(""); setEnvironment(""); setState(""); setSource("manual"); setPage(1);}}>초기화</button>
      </div>
      <div className="tabs" role="tablist" aria-label="점검 출처">
        <button role="tab" aria-selected={source === "manual"} className={source === "manual" ? "active" : ""} onClick={() => { setSource("manual"); setPage(1); }}>수동 점검 결과</button>
        <button role="tab" aria-selected={source === "scheduled"} className={source === "scheduled" ? "active" : ""} onClick={() => { setSource("scheduled"); setPage(1); }}>스케줄 점검 결과</button>
      </div>
      <div className="table-frame">
        <div className="table-scroll">
          <table className="runs-table">
            <thead><tr><th>서비스</th><th>환경</th><th>릴리스</th><th>회차</th><th>CVE 기준일</th><th>구성요소</th><th>취약점</th><th>정책 위반</th><th>처리 상태</th><th>업로드 시각</th></tr></thead>
            <tbody>
              {visible.map((run) => (
                <tr key={run.id} onClick={() => onSelect(run)} tabIndex={0}>
                  <td className="sticky-name">{run.service.name}</td><td>{run.environment.name}</td><td>{run.releaseVersion}</td>
                  <td>{run.roundNumber}차</td><td>{cveBaseline(run)}</td><td>{run.componentCount.toLocaleString()}</td>
                  <td>{run.vulnerabilityCount}</td><td>{policyCountLabel(run)}</td>
                  <td><span className={`state ${run.state}`}>{stateLabel(run.state)}</span></td>
                  <td>{formatSeoulDateTime(run.createdAt)}</td>
                </tr>
              ))}
              {!visible.length && (<tr><td colSpan={10}>{searching ? "구성요소와 회차를 검색하고 있습니다…" : error || "조건에 맞는 회차가 없습니다."}</td></tr>)}
            </tbody>
          </table>
        </div>
        <div className="table-footer"><span>전체 {result.total}건 · {currentPage}/{pageCount}페이지
          </span><div><select aria-label="페이지당 행 수" value={pageSize} onChange={(event) => { setPageSize(Number(event.target.value)); setPage(1);}}><option value={10}>10개씩 보기</option><option value={20}>20개씩 보기</option><option value={50}>50개씩 보기</option><option value={100}>100개씩 보기</option></select><button aria-label="첫 페이지" disabled={currentPage === 1} onClick={() => setPage(1)}>|‹
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
  const baseRun = options.find((run) => run.id === baseId);
  const targetRun = options.find((run) => run.id === targetId);
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
        <label><span>기준 회차</span><select value={baseId} title={baseRun ? label(baseRun) : undefined} onChange={(event) => { setBaseId(event.target.value); setComparison(null);}}>{options.map((run) => (<option value={run.id} key={run.id}>{label(run)}</option>))}</select></label>
        <span className="swap" aria-hidden="true"><Icon name="swap" /></span>
        <label><span>비교 회차</span><select value={targetId} title={targetRun ? label(targetRun) : undefined} onChange={(event) => { setTargetId(event.target.value); setComparison(null);}}>{options.map((run) => (<option value={run.id} key={run.id}>{label(run)}</option>))}</select></label>
        <button className="primary compare-action" onClick={() => void compare()}>비교
        </button>
      </div>
      <div className="analysis-pickers"><label><span>기준 분석 리비전</span><select value={baseAnalysisId} onChange={(event) => { setBaseAnalysisId(event.target.value); setComparison(null);}}><option value="">최신 리비전</option>{baseAnalyses.map((item) => (<option key={item.id} value={item.id}>r{item.sequence} · {dataBaselineLabel(preferredCveDate(item.cveDataAsOf, item.dataAsOf), "CVE 기준일 확인 필요")}</option>))}</select></label><label><span>비교 분석 리비전</span><select value={targetAnalysisId} onChange={(event) => { setTargetAnalysisId(event.target.value); setComparison(null);}}><option value="">최신 리비전</option>{targetAnalyses.map((item) => (<option key={item.id} value={item.id}>r{item.sequence} · {dataBaselineLabel(preferredCveDate(item.cveDataAsOf, item.dataAsOf), "CVE 기준일 확인 필요")}</option>))}</select></label></div>
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
      {tab === "policies" && comparison && <p className="form-message">기준 정책: {comparison.base.policyVersion ? `v${comparison.base.policyVersion}` : "기존 결과"} · {comparison.base.policyState === "completed" ? "평가 완료" : comparison.base.policyState === "failed" ? "평가 실패" : "KODA 정책 미평가"} / 비교 정책: {comparison.target.policyVersion ? `v${comparison.target.policyVersion}` : "기존 결과"} · {comparison.target.policyState === "completed" ? "평가 완료" : comparison.target.policyState === "failed" ? "평가 실패" : "KODA 정책 미평가"}</p>}
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
            </a>)}{comparison?.target.dependencyTrackEnabled && can("dtrack.retry") && (<a className="primary" href="/dependency-track/" target="_blank" rel="noreferrer">기존 외부 시스템에서 열기 <Icon name="external" /></a>)}</div></div>
    </div>
  );}

function ComparisonRecordsTable({ kind, rows }: { kind: string; rows: RecordChange[];}) {
  const isVulnerability = kind === "취약점";
  return (<><>{kind === "정책 위반" && <p className="form-message">정책 위반은 분석 리비전에 저장된 판정 결과의 추가·해소·변경 내역입니다. KODA 정책 버전과 예외 변경도 비교에 반영됩니다. 기존 기존 외부 시스템 결과는 과거 리비전에 보존됩니다.</p>}</><div className="table-frame diff-table-frame"><div className="table-scroll"><table className="diff-table records-table"><thead><tr><th>변화</th><th>{isVulnerability ? "식별자" : "규칙"}</th><th>구성요소</th>{isVulnerability && <><th>CVSS</th><th>KEV</th></>}<th>상태</th></tr></thead><tbody>{rows.length ? (rows.map((row, index) => {
    const record = row.record || row.target || row.base || {};
    const status = severityValue(record);
    return (<tr key={`${row.change}-${index}`}><td><span className={`change ${row.change === "added" ? "추가" : row.change === "removed" ? "제거" : "버전-변경"}`}>{row.change === "added" ? "신규" : row.change === "removed" ? "해소" : "변경"}</span></td><td className="mono">{String(record.canonicalId || record.id || record.policyName || record.policyId || record.rule || "-")}</td><td>{String(record.component || "-")}</td>{isVulnerability && <><td>{cvssScore(record)}</td><td>{record.kev ? "KEV" : "-"}</td></>}<td>{isVulnerability ? <span className={`severity-pill ${severityClass(status)}`}>{severityLabel(status)}</span> : record.suppressed ? "기한부 예외" : record.action === "fail" ? "위반" : record.action === "warn" ? "경고" : String(status)}</td></tr>);}) ): (<tr><td colSpan={isVulnerability ? 6 : 4}>변화가 없습니다.</td></tr>)}</tbody></table></div></div></>);}

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
              <select name="serviceId" required>{services.filter((service) => service.active !== false).map((service) => (<option key={service.id} value={service.id}>{service.name}</option>))}</select></label>)}
      <div className="form-row">{!standaloneMode && (<label>환경
                <select name="environmentId" required>{environments.filter((environment) => environment.active !== false).map((environment) => (<option key={environment.id} value={environment.id}>{environment.name}</option>))}</select></label>)}<label>{standaloneMode ? "릴리스 (선택)" : "릴리스"}<input name="releaseVersion" placeholder="예: 1.4.2" defaultValue={standaloneMode ? "preview" : undefined} required={!standaloneMode} /></label></div>
      <label>SBOM 파일
            <input name="sbom" type="file" accept=".json,.xml,application/json,application/xml" required /><small>CycloneDX JSON/XML, 최대 {standaloneMode ? "100 MiB" : "500 MiB"}</small></label>
      <label>메모
            <textarea name="note" rows={3} placeholder="변경 사유 또는 배포 식별자" /></label>
      {message && (<p className="form-message" role="status">{message}{jobState && <small> · 작업 상태: {jobStateLabel(jobState)}</small>}</p>)}
      <footer><button type="button" className="secondary" onClick={onClose}>취소
            </button><button disabled={busy} className="primary">{busy ? "업로드 중…" : "업로드"}</button></footer>
    </form>
  </section></div>);}

function DetailPagination({ total, page, pageSize, onPage, onPageSize, label = "상세 페이지당 행 수" }: { total: number; page: number; pageSize: number; onPage: (page: number) => void; onPageSize: (size: number) => void; label?: string;}) {
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  return (<div className="detail-pagination"><span>전체 {total.toLocaleString()}건 · {page}/{pageCount}페이지</span><div><select aria-label={label} value={pageSize} onChange={(event) => onPageSize(Number(event.target.value))}><option value={10}>10개씩 보기</option><option value={25}>25개씩 보기</option><option value={50}>50개씩 보기</option><option value={100}>100개씩 보기</option></select><button type="button" aria-label="상세 이전 페이지" disabled={page <= 1} onClick={() => onPage(page - 1)}>‹</button><button type="button" aria-label="상세 다음 페이지" disabled={page >= pageCount} onClick={() => onPage(page + 1)}>›</button></div></div>);
}

function RunDetail({ run, onClose, onChanged, username,
  can}: { run: SbomRun; onClose: () => void; onChanged: () => void;
  can: (permission: string) => boolean; username?: string;}) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [archiveReason, setArchiveReason] = useState("");
  const [detail, setDetail] = useState<SbomRunDetail | null>(null);
  const [componentQuery, setComponentQuery] = useState("");
  const [componentPage, setComponentPage] = useState(1);
  const [componentPageSize, setComponentPageSize] = useState(10);
  const [findingPage, setFindingPage] = useState(1);
  const [findingPageSize, setFindingPageSize] = useState(10);
  const [componentResult, setComponentResult] = useState<{ items: ComponentSnapshot[]; total: number }>({ items: [], total: 0 });
  const [findingResult, setFindingResult] = useState<{ items: Record<string, unknown>[]; total: number }>({ items: [], total: 0 });
  const deferredComponentQuery = useDeferredValue(componentQuery.trim());
  const latestAnalysisId = detail?.analyses?.[0]?.id || "";
  useEffect(() => {
    let cancelled = false;
    void fetchRun(run.id).then((result) => { if (!cancelled) setDetail(result);}).catch((error) => { if (!cancelled) setMessage(error instanceof Error ? error.message : "회차 상세를 불러오지 못했습니다.");});
    return () => { cancelled = true;};}, [run.id]);
  useEffect(() => {
    let cancelled = false;
    void fetchRunComponents(run.id, componentPage, componentPageSize, deferredComponentQuery)
      .then((result) => { if (!cancelled) setComponentResult(result); })
      .catch((error) => { if (!cancelled) setMessage(error instanceof Error ? error.message : "구성요소를 불러오지 못했습니다."); });
    return () => { cancelled = true; };
  }, [componentPage, componentPageSize, deferredComponentQuery, run.id]);
  useEffect(() => {
    let cancelled = false;
    void fetchRunFindings(run.id, findingPage, findingPageSize, latestAnalysisId)
      .then((result) => { if (!cancelled) setFindingResult(result); })
      .catch((error) => { if (!cancelled) setMessage(error instanceof Error ? error.message : "취약점을 불러오지 못했습니다."); });
    return () => { cancelled = true; };
  }, [findingPage, findingPageSize, latestAnalysisId, run.id]);
  async function runAction(action: () => Promise<unknown>, success: string) {
    setBusy(true); setMessage("");
    try { await action(); const refreshed = await fetchRun(run.id); setDetail(refreshed); setMessage(success); onChanged();} catch (error) { setMessage(error instanceof Error ? error.message : "작업에 실패했습니다");} finally { setBusy(false);}
  }
  async function removeRun() {
    if (!window.confirm(`이 SBOM 회차와 Tracker 원본을 영구 삭제하시겠습니까?${current.dependencyTrackEnabled ? " 기존 외부 시스템 프로젝트는 보존됩니다." : ""}`)) return;
    setBusy(true); setMessage("");
    try { await deleteRun(current.id); onChanged(); onClose(); }
    catch (error) { setMessage(error instanceof Error ? error.message : "회차 삭제에 실패했습니다"); }
    finally { setBusy(false); }
  }
  const current = detail || run;
  const scheduled = current.source === "scheduled";
  const sourceMetadata = current.sourceMetadata || {};
  const components = componentResult.items;
  const findings = findingResult.items;
  const componentPageCount = Math.max(1, Math.ceil(componentResult.total / componentPageSize));
  const currentComponentPage = Math.min(componentPage, componentPageCount);
  const findingPageCount = Math.max(1, Math.ceil(findingResult.total / findingPageSize));
  const currentFindingPage = Math.min(findingPage, findingPageCount);
  return (<div className="drawer-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}><section className="detail-modal" role="dialog" aria-modal="true" aria-labelledby="run-detail-title"><header><div><span>{current.service.name}</span><h2 id="run-detail-title">{current.releaseVersion} · {current.roundNumber}차
            </h2></div><button type="button" className="icon-button" aria-label="회차 상세 닫기" onClick={onClose}><Icon name="close" /></button></header>
    <div className="detail-status"><span className={`state ${current.state}`}>{stateLabel(current.state)}</span><span>{scheduled ? "스케줄 점검" : "수동/API 점검"}</span><span>{current.environment.name}</span><span>CycloneDX {current.specVersion}</span></div>
    <dl><dt>원본 파일</dt><dd>{current.filename || "-"}</dd>{scheduled && (<><dt>대상 서버</dt><dd>{String(sourceMetadata.server || sourceMetadata.remoteServer || "-")}</dd><dt>대상 디렉토리</dt><dd className="mono wrap">{String(sourceMetadata.directory || sourceMetadata.remoteDirectory || "-")}</dd><dt>점검 방식</dt><dd>{String(sourceMetadata.mode || "-")}</dd><dt>예약 실행 ID</dt><dd className="mono wrap">{String(sourceMetadata.scheduleRunId || "-")}</dd><dt>규칙 버전</dt><dd>{String(sourceMetadata.rulePolicyVersion ?? "-")}</dd></>)}<dt>CVE 기준일</dt><dd>{cveBaseline(current)}</dd><dt>오프라인 분석</dt><dd>{jobStateLabel(current.analysisState)}</dd>{current.dependencyTrackEnabled && <><dt>기존 외부 시스템 (선택 연동)</dt><dd>{jobStateLabel(current.dependencyTrackState)}</dd></>}<dt>구성요소</dt><dd>{current.componentCount.toLocaleString()}개</dd><dt>취약점</dt><dd>{current.vulnerabilityCount}건</dd><dt>정책 위반·경고·정보</dt><dd>{policyCountLabel(current)}{current.policyState === "completed" ? "건" : ""}</dd></dl>
    <NativePolicyResult result={current} runId={current.id} />
    <SbomQualityPanel runId={current.id} analysisId={latestAnalysisId} canRerun={can("analysis.create")} canViewProfiles={can("policies.view") || can("policies.manage")} canManage={can("policies.manage")} archived={current.state === "archived"} />
    <h3>분석 리비전</h3><ul className="paths">{detail?.analyses?.length ? (detail.analyses.map((analysis) => (<li key={analysis.id}>r{analysis.sequence} · {jobStateLabel(analysis.state)} ·{" "}
                {dataBaselineLabel(preferredCveDate(analysis.cveDataAsOf, analysis.dataAsOf), "CVE 기준일 확인 필요")}{analysis.error ? ` · ${analysis.error}` : ""} · 정책 {analysis.policyVersion ? `v${analysis.policyVersion}` : "-"} · {analysis.policyState === "completed" ? "평가 완료" : analysis.policyState === "failed" ? "평가 실패" : "미평가"}{analysis.policyError ? ` · ${analysis.policyError}` : ""}<AnalysisPolicyHistory analysis={analysis} runId={current.id} /></li>) )
          ): (<li>상세를 불러오는 중이거나 분석 리비전이 없습니다.</li>)}</ul>
    <div className="detail-table-heading"><h3>구성요소 검사기 ({componentResult.total.toLocaleString()})</h3><label className="detail-search"><Icon name="search" /><input aria-label="구성요소 검색" value={componentQuery} onChange={(event) => { setComponentQuery(event.target.value); setComponentPage(1); }} placeholder="이름, 버전, PURL 검색" /></label></div><div className="table-scroll"><table><thead><tr><th>이름</th><th>버전</th><th>PURL</th><th>라이선스</th></tr></thead><tbody>{components.map((component) => (<tr key={component.identityKey}><td>{component.name}</td><td>{component.version || "-"}</td><td className="mono">{component.purl || component.bomRef || "-"}</td><td>{component.licenses?.length ? component.licenses.map((license) => typeof license === "string" ? license : String((license as { license?: { id?: string; name?: string };}).license?.id || (license as { license?: { id?: string; name?: string;};}).license?.name || "식별 불가")).join(", ") : "-"}</td></tr>))}{!components.length && (<tr><td colSpan={4}>{deferredComponentQuery ? "검색 조건에 맞는 구성요소가 없습니다." : "구성요소 상세가 없습니다."}</td></tr>)}</tbody></table></div><DetailPagination total={componentResult.total} page={currentComponentPage} pageSize={componentPageSize} onPage={setComponentPage} onPageSize={(size) => { setComponentPageSize(size); setComponentPage(1); }} />
    <h3>취약점 검사기 ({findingResult.total.toLocaleString()})</h3><div className="table-scroll"><table><thead><tr><th>취약점 ID</th><th>심각도</th><th>구성요소</th><th>CVSS</th><th>KEV</th><th>CWE / EPSS</th><th>제안 버전</th><th>VEX 검토</th></tr></thead><tbody>{findings.map((finding, index) => { const severity = String(finding.severity || "unknown"); return (<tr key={`${String(finding.canonicalId || finding.id || "finding")}-${(currentFindingPage - 1) * findingPageSize + index}`}><td className="mono">{String(finding.canonicalId || finding.id || "식별자 없음")}{finding.sourceKind === "private_vulnerability" && <small className="workflow-id">사내 취약점 · {String(finding.title || "")}<br/>{String(finding.description || "")}</small>}</td><td><span className={`severity-pill ${severityClass(severity)}`}>{severityLabel(severity)}</span></td><td className="mono">{String(finding.component || "-")}</td><td>{cvssScore(finding)}</td><td>{finding.kev ? "KEV" : "-"}</td><td>{Array.isArray(finding.cwes) && finding.cwes.length ? finding.cwes.map(value=>`CWE-${value}`).join(", ") : "CWE 확인 안 됨"}<br/>{typeof finding.epssScore === "number" ? `EPSS ${(finding.epssScore*100).toFixed(2)}% · ${String(finding.epssDate || "")}` : `EPSS ${String(finding.epssStatus || "수집 전")}`}</td><td>{fixedInLabel(finding)}</td><td>{finding.vex && typeof finding.vex === "object" ? <span title={String((finding.vex as Record<string, unknown>).detail || "")}>{(finding.vex as Record<string, unknown>).suppressed ? "승인된 영향 없음·오탐 (원시 발견 보존)" : `승인된 ${String((finding.vex as Record<string, unknown>).state || "검토")}`}</span> : "미검토"}</td></tr>);})}{!findings.length && (<tr><td colSpan={8}>취약점 결과가 없습니다.</td></tr>)}</tbody></table></div><DetailPagination total={findingResult.total} page={currentFindingPage} pageSize={findingPageSize} onPage={setFindingPage} onPageSize={(size) => { setFindingPageSize(size); setFindingPage(1); }} />
              {(can("metadata.view") || can("metadata.manage")) && <PackageMetadataPanel runId={current.id} canManage={can("metadata.manage")} />}
    {(can("vex.view") || can("vex.manage") || can("vex.approve")) && <VexReviewsPanel runId={current.id} findings={findings} username={username} canManage={can("vex.manage")} canApprove={can("vex.approve")} />}
    <div className="drawer-actions">{message && (<p className="form-message" role="status">{message}</p>)}{standaloneMode ? (<p className="preview-note">미리보기 모드에서는 원본 파일을 저장하거나
              Grype 분석·KODA 정책 평가를 실행하지 않습니다.
            </p> ): (<>{current.dependencyTrackEnabled && current.dependencyTrackError && (<p className="drawer-error">{current.dependencyTrackError}</p>)}<div className="drawer-action-row">{current.dependencyTrackEnabled && can("dtrack.retry") && (<button className="secondary" disabled={busy || current.state === "archived"} onClick={() => void runAction(() => retryDependencyTrack(current.id), "기존 외부 시스템 재시도를 접수했습니다.")}>기존 시스템 재시도
                  </button>)}
                {can("analysis.create") && (<button className="secondary" disabled={busy || current.state === "archived"} onClick={() => void runAction(() => createAnalysis(current.id), "새 분석 리비전을 접수했습니다.")}>새 분석 리비전
                  </button>)}
              </div><div className="drawer-action-row">{can("artifact.download") && (<a className="secondary" href={`/api/v1/sbom-runs/${current.id}/artifact`}>원본 SBOM 내려받기
                  </a>)}
                {current.dependencyTrackEnabled && can("dtrack.retry") && (<a className="primary" href={current.dependencyTrackUrl || "/dependency-track/"} target="_blank" rel="noreferrer">기존 외부 시스템에서 열기 <Icon name="external" /></a>)}</div>{can("sbom.archive") && current.state !== "archived" && (<form className="archive-form" onSubmit={(event) => { event.preventDefault(); if (archiveReason.trim()) void runAction(() => archiveRun(current.id, archiveReason.trim()), "회차를 논리 보관했습니다.");}}><input aria-label="보관 사유" placeholder="보관 사유" value={archiveReason} onChange={(event) => setArchiveReason(event.target.value)} /><button className="secondary" disabled={busy || !archiveReason.trim()}>논리 보관
                  </button></form>)}{can("sbom.delete") && (<button type="button" className="danger" disabled={busy || !["completed", "failed", "archived"].includes(current.state)} onClick={() => void removeRun()}>회차 영구 삭제</button>)}</>)}</div>
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
  const [servicePage, setServicePage] = useState(1);
  const [environmentPage, setEnvironmentPage] = useState(1);
  const [catalogPageSize, setCatalogPageSize] = useState(10);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [deletedServiceIds, setDeletedServiceIds] = useState(() => new Set<string>());
  const [deletedEnvironmentIds, setDeletedEnvironmentIds] = useState(() => new Set<string>());
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
  async function removeEnvironment(item: CatalogItem) {
    if (!window.confirm(`${item.name} 환경을 삭제하시겠습니까? 과거 회차의 환경명은 유지됩니다.`)) return;
    setBusy(true); setMessage("");
    try {
      if (!previewMode) await patchEnvironment(item.id, { active: false });
      setDeletedEnvironmentIds((current) => new Set(current).add(item.id));
      setMessage("환경을 삭제했습니다.");
      if (!previewMode) onChanged();
    }
    catch (error) { setMessage(error instanceof Error ? error.message : "환경 삭제에 실패했습니다"); }
    finally { setBusy(false); }
  }
  async function removeService(item: CatalogItem) {
    if (!window.confirm(`${item.name} 서비스를 삭제하시겠습니까? 과거 회차의 서비스명은 유지됩니다.`)) return;
    setBusy(true); setMessage("");
    try {
      if (!previewMode) await patchService(item.id, { active: false });
      setDeletedServiceIds((current) => new Set(current).add(item.id));
      setMessage("서비스를 삭제했습니다.");
      if (!previewMode) onChanged();
    } catch (error) { setMessage(error instanceof Error ? error.message : "서비스 삭제에 실패했습니다");} finally { setBusy(false);}
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
  const activeServices = services.filter((item) => item.active !== false && !deletedServiceIds.has(item.id));
  const activeEnvironments = environments.filter((item) => item.active !== false && !deletedEnvironmentIds.has(item.id));
  const servicePageCount = Math.max(1, Math.ceil(activeServices.length / catalogPageSize));
  const environmentPageCount = Math.max(1, Math.ceil(activeEnvironments.length / catalogPageSize));
  const currentServicePage = Math.min(servicePage, servicePageCount);
  const currentEnvironmentPage = Math.min(environmentPage, environmentPageCount);
  const visibleServices = activeServices.slice((currentServicePage - 1) * catalogPageSize, currentServicePage * catalogPageSize);
  const visibleEnvironments = activeEnvironments.slice((currentEnvironmentPage - 1) * catalogPageSize, currentEnvironmentPage * catalogPageSize);
  return (<section className="page generic-page">
    <div className="page-heading"><div><h1>서비스</h1><p>서비스·환경·릴리스 구조와 업로드 권한을 관리합니다. GitLab 저장소 연동에는 저장소별 서비스와 gitlab-source 환경의 연동 ID를 사용합니다.</p></div>{canManage && (<div className="button-row"><button className="primary" onClick={() => setMode("service")}>서비스 추가
            </button><button className="secondary" onClick={() => setMode("environment")}>환경 추가
            </button></div>)}
      </div>
    {message && (<p className="form-message" role="status">{message}</p>)}
    <div className="settings-grid catalog-grid"><div className="table-frame"><h2 className="table-title">서비스 {activeServices.length}개</h2><table><thead><tr><th>서비스</th><th>식별자</th><th>작업</th></tr></thead><tbody>{activeServices.length ? (visibleServices.map((item) => (<tr key={item.id}><td>{item.name}</td><td className="mono">{item.slug}</td><td><button type="button" className="secondary compact" title={item.id} onClick={() => void copyOrShow("서비스 연동 ID", item.id)}>연동 ID 복사</button>{canManage && (
                        <>
                          {" "}
                          <button className="secondary compact" disabled={busy} onClick={() => void editService(item)}>이름 변경
                          </button> {" "}<button className="danger compact" disabled={busy} onClick={() => void removeService(item)}>삭제</button></>
                      )}
    </td></tr>) )
              ): (<tr><td colSpan={3}>등록된 서비스가 없습니다.</td></tr>)}</tbody></table><DetailPagination total={activeServices.length} page={currentServicePage} pageSize={catalogPageSize} label="서비스 페이지당 행 수" onPage={setServicePage} onPageSize={(size) => { setCatalogPageSize(size); setServicePage(1); setEnvironmentPage(1); }} /></div><div className="table-frame"><h2 className="table-title">환경 {activeEnvironments.length}개</h2><table><thead><tr><th>환경</th><th>식별자</th><th>정렬</th><th>작업</th></tr></thead><tbody>{activeEnvironments.length ? (visibleEnvironments.map((item) => (<tr key={item.id}><td>{item.name}</td><td className="mono">{item.slug}</td><td>{item.sortOrder ?? "-"}</td><td><button type="button" className="secondary compact" title={item.id} onClick={() => void copyOrShow("환경 연동 ID", item.id)}>연동 ID 복사</button>{canManage && (<>{" "}<button className="secondary compact" disabled={busy} onClick={() => setEditingEnvironment(item)}>변경
                        </button> <button className="danger compact" disabled={busy} onClick={() => void removeEnvironment(item)}>삭제</button></>)}</td></tr>) )
              ): (<tr><td colSpan={4}>등록된 환경이 없습니다.</td></tr>)}</tbody></table><DetailPagination total={activeEnvironments.length} page={currentEnvironmentPage} pageSize={catalogPageSize} label="환경 페이지당 행 수" onPage={setEnvironmentPage} onPageSize={(size) => { setCatalogPageSize(size); setServicePage(1); setEnvironmentPage(1); }} /></div></div>
    {mode && (<div className="modal-backdrop" role="presentation"><section className="modal" role="dialog" aria-modal="true"><header><h2>{mode === "service" ? "서비스 추가" : "환경 추가"}</h2><button type="button" className="icon-button" aria-label="추가 창 닫기" onClick={() => setMode(null)}><Icon name="close" /></button></header><form onSubmit={submit}><label>이름
                <input name="name" required autoFocus /></label><label>식별자
                <input name="slug" pattern="[a-z0-9][a-z0-9-]{1,126}[a-z0-9]" required /><small>영문 소문자, 숫자, 하이픈만 사용합니다.</small></label>{mode === "environment" && (<label>정렬 순서
                  <input name="sortOrder" type="number" defaultValue="50" /></label>)}{" "} {message && <p className="form-message">{message}</p>}<footer><button type="button" className="secondary" onClick={() => setMode(null)}>취소
                </button><button className="primary" disabled={busy}>{busy ? "등록 중…" : "등록"}</button></footer></form></section></div>)}
    {editingEnvironment && (<div className="modal-backdrop" role="presentation"><section className="modal" role="dialog" aria-modal="true" aria-labelledby="environment-edit-title"><header><h2 id="environment-edit-title">환경 변경</h2><button type="button" className="icon-button" aria-label="환경 변경 창 닫기" onClick={() => setEditingEnvironment(null)}><Icon name="close" /></button></header><form onSubmit={submitEnvironmentEdit}><label>이름
                <input name="name" defaultValue={editingEnvironment.name} required autoFocus /></label><label>식별자
                <input name="slug" defaultValue={editingEnvironment.slug} maxLength={64} required /><small>환경 식별자는 변경할 수 있으며 중복은 사용할 수 없습니다.</small></label><label>정렬 순서
                <input name="sortOrder" type="number" defaultValue={editingEnvironment.sortOrder ?? 0} required /></label>{message && <p className="form-message">{message}</p>}<footer><button type="button" className="secondary" onClick={() => setEditingEnvironment(null)}>취소
                </button><button className="primary" disabled={busy}>{busy ? "변경 중…" : "변경"}</button></footer></form></section></div>)}
  </section>);}

function VulnerabilityPage({ bundles, onSync, onActivate, canManage, embedded = false }: { bundles: VulnerabilityBundle[]; onSync: () => Promise<void>; onActivate: (version: string) => Promise<void>; canManage: boolean; embedded?: boolean; }) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [dataKind, setDataKind] = useState<"grype-db" | "vuln-data">("grype-db");
  const [dataJob, setDataJob] = useState<Awaited<ReturnType<typeof fetchVulnerabilityDataJob>> | null>(null);
  const activeBundle = bundles.find((bundle) => bundle.active);
  async function uploadData(file: File) {
    setBusy(true); setMessage("");
    try { setDataJob(await uploadVulnerabilityData(dataKind, file)); setMessage("파일을 접수했습니다. 검증 작업이 대기 중입니다."); }
    catch (error) { setMessage(error instanceof Error ? error.message : "데이터 업로드에 실패했습니다"); }
    finally { setBusy(false); }
  }
  useEffect(() => {
    if (!dataJob || dataJob.state === "completed" || dataJob.state === "failed") return;
    const timer = window.setInterval(() => { void fetchVulnerabilityDataJob(dataJob.id).then((job) => { setDataJob(job); if (job.state === "completed" && job.action !== "validate") void onSync(); }).catch((error) => setMessage(error instanceof Error ? error.message : "작업 상태 조회에 실패했습니다")); }, 2000);
    return () => window.clearInterval(timer);
  }, [dataJob]);
  async function applyData() {
    if (!dataJob) return;
    setBusy(true); try { setDataJob(await applyVulnerabilityDataJob(dataJob.id)); setMessage("적용 작업을 접수했습니다."); }
    catch (error) { setMessage(error instanceof Error ? error.message : "적용에 실패했습니다"); }
    finally { setBusy(false); }
  }
  async function rollbackData(kind: "grype-db" | "vuln-data") {
    setBusy(true); setMessage("");
    try { setDataJob(await rollbackVulnerabilityData(kind)); setMessage(`${kind === "grype-db" ? "Grype DB" : "vuln-data"} 복원 작업을 접수했습니다.`); }
    catch (error) { setMessage(error instanceof Error ? error.message : "복원에 실패했습니다"); }
    finally { setBusy(false); }
  }
  async function sync() {
    setBusy(true); setMessage("");
    try { await onSync(); setMessage("파일시스템의 반입 상태를 동기화했습니다.");} catch (error) { setMessage(error instanceof Error ? error.message : "동기화에 실패했습니다");} finally { setBusy(false);}
  }
  async function activate(version: string) {
    setBusy(true); setMessage("");
    try { await onActivate(version); setMessage(`${version} 번들을 활성 상태로 기록했습니다.`);} catch (error) { setMessage(error instanceof Error ? error.message : "활성화에 실패했습니다");} finally { setBusy(false);}
  }
  const pageCount = Math.max(1, Math.ceil(bundles.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const visibleBundles = bundles.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  return (<section className={embedded ? "settings-panel generic-page" : "page generic-page"}><div className="page-heading"><div><h1>취약점 데이터</h1><p>폐쇄망에 반입한 Grype·NVD·CISA KEV 데이터의 무결성과 기준일을
            확인합니다.
          </p></div>{canManage && (<div className="button-row"><button className="primary" onClick={() => void sync()} disabled={busy}>{busy ? "확인 중…" : "반입 상태 동기화"}</button><select value={dataKind} onChange={(event) => setDataKind(event.target.value as typeof dataKind)} aria-label="취약점 데이터 종류"><option value="grype-db">Grype DB</option><option value="vuln-data">vuln-data</option></select><label className="secondary compact">압축파일 업로드<input type="file" accept=".tar.gz,.tgz,application/gzip" hidden onChange={(event) => { const file = event.target.files?.[0]; if (file) void uploadData(file); event.currentTarget.value = ""; }} /></label><button className="secondary compact" onClick={() => void rollbackData("grype-db")} disabled={busy}>Grype DB 복원</button><button className="secondary compact" onClick={() => void rollbackData("vuln-data")} disabled={busy}>vuln-data 복원</button></div>)}
      </div><p className="form-message">현재 Grype DB: {activeBundle?.grypeDbVersion || activeBundle?.version || "확인 불가"} · vuln-data: {activeBundle?.vulnDataVersion || activeBundle?.version || "확인 불가"}</p>{message && (<p className="form-message" role="status">{message}</p>)}<div className="table-frame"><div className="table-scroll"><table><thead><tr><th>번들</th><th>Grype</th><th>NVD 기준일</th><th>KEV 기준일</th><th>별칭 / KEV</th><th>상태</th><th>반입 시각</th></tr></thead><tbody>{bundles.length ? (visibleBundles.map((item) => (<tr key={item.id}><td>{item.version}</td><td>{item.dataAsOf}<br /><small>schema {item.grypeDbSchema}</small></td><td>{item.nvdDataAsOf}</td><td>{item.kevDataAsOf}</td><td>{item.aliasCount} / {item.kevCount}</td><td>{item.active ? (<span className="state completed">활성</span> ): canManage ? (<button className="secondary compact" onClick={() => void activate(item.version)} disabled={busy}>활성 기록
                        </button>) : (
                        <span>보관</span>
                      )}</td><td>{formatSeoulDateTime(item.importedAt)}</td></tr>) )
              ): (<tr><td colSpan={7}>등록된 취약점 데이터 번들이 없습니다. 반입 후 동기화하세요.
                  </td></tr>)}</tbody></table></div><DetailPagination total={bundles.length} page={currentPage} pageSize={pageSize} label="취약점 번들 페이지당 행 수" onPage={setPage} onPageSize={(size) => { setPageSize(size); setPage(1); }} /></div>{dataJob && (<p className="form-message" role="status">데이터 작업 {dataJob.state} · {dataJob.kind} · {dataJob.version || "버전 검증 중"} · 기준일 {dataJob.dataAsOf || "확인 중"}{dataJob.error ? `: ${dataJob.error}` : ""}{dataJob.state === "completed" && dataJob.action === "validate" && <button className="primary compact" onClick={() => void applyData()} disabled={busy}>검증 결과 적용</button>}</p>)}</section>);}

function AuditPage({ events, embedded = false }: { events: AuditEvent[]; embedded?: boolean }) {
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [result, setResult] = useState({ items: events.slice(0, 10), total: events.length });
  const deferredQuery = useDeferredValue(query.trim());
  useEffect(() => {
    let cancelled = false;
    if (previewMode) {
      const term = deferredQuery.toLowerCase();
      const filtered = events.filter((item) =>
        !term || `${item.actor} ${item.action} ${item.targetType} ${item.targetId} ${JSON.stringify(redactSha256(item.detail))}`
          .toLowerCase().includes(term));
      const start = (page - 1) * pageSize;
      queueMicrotask(() => {
        if (!cancelled) setResult({ items: filtered.slice(start, start + pageSize), total: filtered.length });
      });
      return () => { cancelled = true; };
    }
    void fetchAuditEvents(page, pageSize, deferredQuery)
      .then((next) => { if (!cancelled) setResult(next); })
      .catch(() => { if (!cancelled) setResult({ items: [], total: 0 }); });
    return () => { cancelled = true; };
  }, [deferredQuery, events, page, pageSize]);
  const exportHref = `/api/v1/audit-events?format=csv${query.trim() ? `&q=${encodeURIComponent(query.trim())}` : ""}`;
  return (<section className={embedded ? "settings-panel generic-page" : "page generic-page"}><div className="page-heading"><div><h1>감사 로그</h1><p>가입·LDAP·업로드·분석·관리 작업을 불변 이력으로 조회합니다.</p></div><a className="secondary" href={previewMode ? "#" : exportHref} download={previewMode ? undefined : "koda-audit-events.csv"} onClick={(event) => previewMode && event.preventDefault()}>Excel 다운로드</a></div><div className="generic-toolbar"><label className="global-search"><Icon name="search" /><input aria-label="감사 로그 검색" value={query} onChange={(event) => { setQuery(event.target.value); setPage(1); }} placeholder="행위자, 작업, 대상, 상세 검색" /></label><span>{result.total}건</span></div><div className="table-frame"><div className="table-scroll"><table><thead><tr><th>시각</th><th>행위자</th><th>작업</th><th>대상</th><th>상세</th></tr></thead><tbody>{result.items.length ? (result.items.map((item) => (<tr key={item.id}><td>{formatSeoulDateTime(item.createdAt)}</td><td>{item.actor}</td><td className="mono">{item.action}</td><td>{item.targetType}:{item.targetId}</td><td className="mono">{auditDetailLabel(item.detail)}</td></tr>) )
              ): (<tr><td colSpan={5}>감사 로그가 없습니다.</td></tr>)}</tbody></table></div><DetailPagination total={result.total} page={Math.min(page, Math.max(1, Math.ceil(result.total / pageSize)))} pageSize={pageSize} onPage={setPage} onPageSize={(size) => { setPageSize(size); setPage(1); }} /></div></section>);}

type ApiTokenSummary = { id: string; name: string; serviceId?: string; active: boolean; createdAt: string;};

type LdapForm = LdapSettings & { bindPassword: string };

function ldapFormFromSettings(settings: LdapSettings): LdapForm {
  return { ...settings, bindPassword: "" };
}

function LdapSettingsPanel({ settings, onChanged }: { settings: LdapSettings | null; onChanged: (settings: LdapSettings) => void }) {
  const [form, setForm] = useState<LdapForm | null>(() => settings ? ldapFormFromSettings(settings) : null);
  const [mappingText, setMappingText] = useState(() => settings ? Object.entries(settings.groupMappings).map(([group, role]) => `${group}=${role}`).join("\n") : "");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  useEffect(() => {
    if (!settings) return;
    setForm(ldapFormFromSettings(settings));
    setMappingText(Object.entries(settings.groupMappings).map(([group, role]) => `${group}=${role}`).join("\n"));
  }, [settings]);
  if (!form) return <div className="settings-panel"><p>LDAP 설정을 불러오는 중입니다…</p></div>;
  const change = <K extends keyof LdapForm>(key: K, value: LdapForm[K]) => setForm((current) => current ? { ...current, [key]: value } : current);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setMessage("");
    if (previewMode) { setMessage("샘플 화면에서는 LDAP 설정을 저장하거나 서버에 연결하지 않습니다."); return; }
    const current = form;
    if (!current) return;
    setBusy(true);
    const groupMappings = Object.fromEntries(mappingText.split("\n").map((line) => line.trim()).filter(Boolean).map((line) => {
      const separator = line.lastIndexOf("=");
      return separator > 0 ? [line.slice(0, separator).trim(), line.slice(separator + 1).trim()] : [line, "viewer"];
    }).filter(([, role]) => ["admin", "manager", "analyst", "uploader", "viewer"].includes(role)));
    try {
      const payload: Record<string, unknown> = { ...current, bindPassword: current.bindPassword || undefined, groupMappings };
      delete payload.hasBindPassword;
      delete payload.encryptionReady;
      const saved = await updateLdapSettings(payload);
      onChanged(saved); setMessage("LDAP 설정을 저장했습니다.");
    } catch (error) { setMessage(error instanceof Error ? error.message : "LDAP 설정 저장에 실패했습니다"); }
    finally { setBusy(false); }
  }
  return (<div className="settings-panel ldap-settings-panel" id="settings-panel-ldap" role="tabpanel" aria-labelledby="settings-tab-ldap">
    <div className="table-frame"><div className="settings-panel-heading"><div><h2 className="table-title">LDAP 로그인</h2><p>Tracker에서 LDAP을 인증하고 같은 세션으로 KODA에 접근합니다. 비밀번호는 서버의 암호화 키로 저장됩니다.</p></div><span className={`user-status ${form.enabled && form.hasBindPassword ? "active" : "inactive"}`}>{form.enabled && form.hasBindPassword ? "구성됨" : "미설정"}</span></div>
      {previewMode && <p className="form-message" role="note">디자인 점검용 샘플입니다. 아래 서버·계정·그룹은 가상 값이며 실제 연결·저장은 하지 않습니다.</p>}
      <form className="ldap-form" onSubmit={submit}>
        <label className="login-checkbox"><input type="checkbox" checked={form.enabled} onChange={(event) => setForm((current) => current ? { ...current, enabled: event.target.checked, verifyCertificate: true } : current)} /> LDAP 로그인 사용</label>
        <h3>연결</h3>
        <div className="form-row"><label>LDAP 서버<input value={form.host} onChange={(event) => change("host", event.target.value)} placeholder="ldap.example.or.kr" required={form.enabled} /></label><label>포트<input type="number" min={1} max={65535} value={form.port} onChange={(event) => change("port", Number(event.target.value))} /></label><label>TLS 방식<select value={form.tlsMode} onChange={(event) => change("tlsMode", event.target.value as LdapForm["tlsMode"])}><option value="starttls">StartTLS (389)</option><option value="ldaps">LDAPS (636)</option><option value="plain">LDAP 평문 (389, 현재 AI 호환)</option></select></label></div>
        <div className="form-row"><label>Bind DN / UPN<input value={form.bindDn} onChange={(event) => change("bindDn", event.target.value)} placeholder="admin@example.or.kr" required={form.enabled} /></label><label>Bind 비밀번호<input type="password" value={form.bindPassword} onChange={(event) => change("bindPassword", event.target.value)} placeholder={form.hasBindPassword ? "기존 값 유지" : "입력 필요"} autoComplete="new-password" required={form.enabled && !form.hasBindPassword} /></label></div>
        <h3>사용자 식별</h3>
        <div className="form-row"><label>검색 기준 DN<input value={form.baseDn} onChange={(event) => change("baseDn", event.target.value)} placeholder="DC=example,DC=or,DC=kr" required={form.enabled} /></label><label>CA 인증서 경로<input value={form.caCertPath} onChange={(event) => change("caCertPath", event.target.value)} placeholder="/run/secrets/ldap-ca.crt" /></label></div>
        <div className="form-row"><label>로그인 속성<input value={form.loginAttribute} onChange={(event) => change("loginAttribute", event.target.value)} /></label><label>Tracker 사용자 ID 속성<input value={form.usernameAttribute} onChange={(event) => change("usernameAttribute", event.target.value)} /></label><label>고유 식별자 속성<input value={form.subjectAttribute} onChange={(event) => change("subjectAttribute", event.target.value)} /><small>AD는 objectGUID, OpenLDAP은 entryUUID를 사용합니다.</small></label><label>그룹 속성<input value={form.groupAttribute} onChange={(event) => change("groupAttribute", event.target.value)} /></label></div>
        <label>사용자 검색 필터<input value={form.userFilter} onChange={(event) => change("userFilter", event.target.value)} placeholder="(sAMAccountName={username})" required={form.enabled} /><small>{`{username}`} 자리에 로그인 입력값을 안전하게 삽입합니다.</small></label>
        <h3>그룹·역할 매핑</h3>
        <label>그룹 → Tracker 역할 매핑<small>한 줄에 `그룹 DN=역할` 형식으로 입력합니다. 예: `CN=KODA-Admins,DC=example,DC=or,DC=kr=admin`</small><textarea rows={4} value={mappingText} onChange={(event) => setMappingText(event.target.value)} placeholder="CN=KODA-Admins,DC=example,DC=or,DC=kr=admin" /></label>
        <h3>승인 정책</h3>
        <div className="form-row"><label className="login-checkbox"><input type="checkbox" checked={form.tlsMode !== "plain" && form.verifyCertificate} disabled /> {form.tlsMode === "plain" ? "인증서 검증 없음" : "인증서 검증 (필수)"}</label><label className="login-checkbox"><input type="checkbox" checked={form.autoProvision} onChange={(event) => change("autoProvision", event.target.checked)} /> LDAP 사용자 자동 생성</label><label>기본 역할<select value={form.defaultRole} onChange={(event) => change("defaultRole", event.target.value)}>{Object.entries(ROLE_LABELS).map(([role, label]) => <option value={role} key={role}>{label}</option>)}</select></label></div>
        <p className="form-message">자동 생성된 신규 LDAP 사용자는 항상 승인 대기 상태로 생성되며, 관리자가 승인한 뒤에만 로그인할 수 있습니다.</p>
        {form.tlsMode === "plain" && <p className="form-message" role="alert">현재 AI 서버 호환 모드입니다. LDAP 자격증명이 네트워크에 평문으로 전달될 수 있으므로 내부망에서만 사용하고, 가능하면 StartTLS 또는 LDAPS로 전환하세요.</p>}
        {!form.encryptionReady && <p className="form-message" role="alert">서버에 TRACKER_LDAP_ENCRYPTION_KEY가 없거나 올바르지 않아 bind 비밀번호를 저장할 수 없습니다.</p>}
        {message && <p className="form-message" role="status">{message}</p>}
        <footer><button className="primary" disabled={previewMode || busy || (form.enabled && !form.encryptionReady)}>{previewMode ? "샘플 모드 · 저장 안 함" : busy ? "저장 중…" : "LDAP 설정 저장"}</button></footer>
      </form>
    </div>
  </div>);
}

export function SettingsPage({ users, services, environments = [], tokens, dtrackStatus, ldapSettings, policies, roleCatalog, bundles, auditEvents, isAdmin, canVulnerability, canVulnerabilityManage, canAudit, canUsers, canTokens, canDtrack, canPolicyEdit, canRoles, canSbomPolicies = false, canSbomPolicyManage = false, canReanalysis = false, canReanalysisManage = false, canNotifications = false, canNotificationManage = false, canMetadata = false, canMetadataManage = false, canMigrations = false, canServices = false, canCatalogManage = false, initialTab, onSync, onActivate, onPolicyChanged, onLdapChanged, onChanged }: {
  users: UserSummary[];
  services: CatalogItem[];
  environments?: CatalogItem[];
  tokens: ApiTokenSummary[];
  dtrackStatus: DependencyTrackStatus | null;
  ldapSettings: LdapSettings | null;
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
  canSbomPolicies?: boolean;
  canSbomPolicyManage?: boolean;
  canReanalysis?: boolean; canReanalysisManage?: boolean; canNotifications?: boolean; canNotificationManage?: boolean;
  canMetadata?: boolean; canMetadataManage?: boolean; canMigrations?: boolean;
  canServices?: boolean;
  canCatalogManage?: boolean;
  initialTab?: SettingsTab;
  onSync: () => Promise<void>;
  onActivate: (version: string) => Promise<void>;
  onPolicyChanged: (policies: RolePolicy[]) => Promise<void>;
  onLdapChanged: (settings: LdapSettings) => void;
  onChanged: () => void;
}) {
  const [mode, setMode] = useState<"user" | "token" | null>(null);
  const [activeTab, setActiveTab] = useState<SettingsTab>(initialTab || "users");
  const [message, setMessage] = useState("");
  const [issuedToken, setIssuedToken] = useState<{ name: string; token: string; serviceId: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [userPage, setUserPage] = useState(1);
  const [tokenPage, setTokenPage] = useState(1);
  const [gitlabServicePage, setGitlabServicePage] = useState(1);
  const [gitlabPageSize, setGitlabPageSize] = useState(10);
  const [accountPageSize, setAccountPageSize] = useState(10);
  const [policyDraft, setPolicyDraft] = useState<Record<string, Set<string>>>(
    () =>
      Object.fromEntries(
        policies.map((item) => [item.role, new Set(item.permissions)])));
  const settingsTabs = useMemo(() => {
    const tabs: { id: SettingsTab; label: string; icon: string }[] = [];
    if (canMigrations) tabs.push({ id: "migration", label: "기존 시스템 이관", icon: "integration" });
    if (isAdmin && (canMetadata || canMetadataManage)) tabs.push({ id: "private-vulnerabilities", label: "사내 취약점 DB", icon: "vulnerability" });
    if (canMetadata || canMetadataManage) tabs.push({ id: "metadata", label: "패키지 메타데이터", icon: "settings" });
    if (canSbomPolicies || canSbomPolicyManage) tabs.push({ id: "sbom-policies", label: "SBOM 정책", icon: "settings" });
    if (canReanalysis || canReanalysisManage) tabs.push({ id: "reanalysis", label: "재분석 일정", icon: "settings" });
    if (canNotifications || canNotificationManage) tabs.push({ id: "notifications", label: "알림함", icon: "audit" });
    if (canServices) tabs.push({ id: "services", label: "서비스·환경", icon: "service" });
    if (canUsers || canTokens) tabs.push({ id: "users", label: "사용자 관리", icon: "user" });
    if (canRoles || canPolicyEdit) tabs.push({ id: "roles", label: "권한 관리", icon: "settings" });
    if (isAdmin && canVulnerability) tabs.push({ id: "vulnerability", label: "취약점 데이터", icon: "vulnerability" });
    if (isAdmin && canAudit) tabs.push({ id: "audit", label: "감사 로그", icon: "audit" });
    if (canDtrack || (canServices && canTokens)) tabs.push({ id: "integration", label: "연동 설정", icon: "integration" });
    if (isAdmin) tabs.push({ id: "ldap", label: "LDAP 로그인", icon: "lock" });
    return tabs;
  }, [canMetadata, canMetadataManage, canMigrations, canReanalysis, canReanalysisManage, canNotifications, canNotificationManage, canSbomPolicies, canSbomPolicyManage, canAudit, canDtrack, canPolicyEdit, canRoles, canServices, canTokens, canUsers, canVulnerability, isAdmin]);
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
        setIssuedToken(result);} else { setMode(null);}
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
  async function removeUser(item: UserSummary) {
    if (!item.id || !window.confirm(`${item.username} 사용자를 삭제하시겠습니까? 기존 SBOM 회차의 업로더 이력은 감사 로그에 보존됩니다.`)) return;
    setBusy(true); setMessage("");
    try { await deleteUser(item.id); setMessage("사용자를 삭제했습니다."); onChanged(); }
    catch (error) { setMessage(error instanceof Error ? error.message : "사용자 삭제에 실패했습니다"); }
    finally { setBusy(false); }
  }
  const dtrackLabel = dtrackStatus?.enabled === false ? "사용 안 함 (KODA 자체 분석)" : !dtrackStatus
    ? "확인 중"
    : dtrackStatus.reachable && dtrackStatus.authenticated
      ? "연결됨"
      : dtrackStatus.configured
        ? "점검 필요"
        : "미설정";
  const roles = policies.map((item) => item.role);
  const permissionNames = roleCatalog;
  const userPageCount = Math.max(1, Math.ceil(users.length / accountPageSize));
  const tokenPageCount = Math.max(1, Math.ceil(tokens.length / accountPageSize));
  const currentUserPage = Math.min(userPage, userPageCount);
  const currentTokenPage = Math.min(tokenPage, tokenPageCount);
  const visibleUsers = users.slice((currentUserPage - 1) * accountPageSize, currentUserPage * accountPageSize);
  const visibleTokens = tokens.slice((currentTokenPage - 1) * accountPageSize, currentTokenPage * accountPageSize);
  const gitlabEnvironment = environments.find((item) => item.active !== false && item.slug === "gitlab-source");
  const gitlabServices = services.filter((item) => item.active !== false && item.slug.startsWith("gitlab-"));
  const gitlabServicePageCount = Math.max(1, Math.ceil(gitlabServices.length / gitlabPageSize));
  const currentGitlabServicePage = Math.min(gitlabServicePage, gitlabServicePageCount);
  const visibleGitlabServices = gitlabServices.slice((currentGitlabServicePage - 1) * gitlabPageSize, currentGitlabServicePage * gitlabPageSize);
  return (<section className="page generic-page">
    <div className="page-heading"><div><h1>설정</h1><p>사용자·권한·취약점 데이터·감사 로그와 연동을 관리합니다.</p></div>{activeTab === "users" && (<div className="button-row">{canTokens && (<button type="button" className="secondary" onClick={() => { setIssuedToken(null); setMode("token"); }}>API 토큰 발급</button>)}{canUsers && (<button type="button" className="primary" onClick={() => setMode("user")}>사용자 추가</button>)}</div>)}</div>
    <div className="settings-tabs" role="tablist" aria-label="설정 하위 메뉴">
      {settingsTabs.map((tab) => (<button type="button" role="tab" id={`settings-tab-${tab.id}`} aria-controls={`settings-panel-${tab.id}`} aria-selected={activeTab === tab.id} className={activeTab === tab.id ? "active" : ""} key={tab.id} onClick={() => setActiveTab(tab.id)}><Icon name={tab.icon} /><span>{tab.label}</span></button>))}
    </div>
    {message && (<p className="form-message" role="status">{message}</p>)}
    {activeTab === "private-vulnerabilities" && isAdmin && (canMetadata || canMetadataManage) && <PrivateVulnerabilitiesPanel canManage={canMetadataManage}/> }
    {activeTab === "metadata" && (canMetadata || canMetadataManage) && <PackageMetadataPanel canManage={canMetadataManage} />}
    {activeTab === "migration" && canMigrations && <><LegacyMigrationPanel canApply={isAdmin} /><ProjectCatalogPanel canManage={isAdmin} services={services} environments={environments}/></>}

    {issuedToken && activeTab === "users" && (<div className="token-reveal"><strong>{issuedToken.name}</strong><code>{issuedToken.token}</code><span>서비스 ID <code>{issuedToken.serviceId}</code></span><button type="button" className="secondary compact" onClick={() => void copyOrShow("KODA 서비스 토큰", issuedToken.token)}>토큰 복사</button><button type="button" className="secondary compact" onClick={() => void copyOrShow("서비스 연동 ID", issuedToken.serviceId)}>서비스 ID 복사</button></div>)}
    {activeTab === "users" && canUsers && (<p className="form-message">가입 신청 계정은 승인 대기로 구분됩니다. 역할을 확인한 뒤 승인하세요.</p>)}
    {activeTab === "integration" && (canDtrack || (canServices && canTokens)) && (<div className="settings-panel integration-settings-panel" id="settings-panel-integration" role="tabpanel" aria-labelledby="settings-tab-integration">
      {canServices && canTokens && (<>
        <div className="table-frame dtrack-status"><div className="settings-panel-heading"><div><h2 className="table-title">KODA GitLab 자동 연동</h2><p>GitLab 연결과 저장소 선택은 KODA에서만 설정합니다. Tracker는 KODA 요청을 받아 저장소별 서비스·환경·전송 토큰을 자동 생성하거나 재사용합니다.</p></div><span className={`user-status ${gitlabServices.length ? "active" : "inactive"}`}>{gitlabServices.length ? "저장소 연결됨" : "연결 대기"}</span></div><div className="dtrack-status-body"><p>GitLab 저장소 → KODA 점검·CycloneDX 생성 → Tracker 회차 수신·분석 → KODA가 GitLab 결과 MR·취약점 이슈 저장</p><p>{gitlabEnvironment ? "gitlab-source 환경이 자동 준비되었습니다." : "첫 저장소 연결 시 gitlab-source 환경이 자동 준비됩니다."}</p><div className="button-row"><button type="button" className="secondary" onClick={() => setActiveTab("services")}>자동 생성 항목 보기</button></div></div></div>
        <div className="table-frame"><h2 className="table-title">자동 생성된 저장소 서비스</h2><table><thead><tr><th>GitLab 저장소</th><th>Tracker 식별자</th><th>전송 토큰</th></tr></thead><tbody>{gitlabServices.length ? visibleGitlabServices.map((item) => { const tokenCount = tokens.filter((token) => token.active && token.serviceId === item.id).length; return (<tr key={item.id}><td>{item.name}</td><td className="mono">{item.slug}</td><td>{tokenCount ? "활성" : "확인 필요"}</td></tr>);}) : (<tr><td colSpan={3}>KODA에서 연결한 GitLab 저장소가 없습니다.</td></tr>)}</tbody></table><DetailPagination total={gitlabServices.length} page={currentGitlabServicePage} pageSize={gitlabPageSize} label="GitLab 서비스 페이지당 행 수" onPage={setGitlabServicePage} onPageSize={(size) => { setGitlabPageSize(size); setGitlabServicePage(1); }} /></div>
      </>)}
      {canDtrack && (<div className="table-frame dtrack-status"><h2 className="table-title">기존 외부 시스템 연결</h2><div className="dtrack-status-body"><strong className={`state ${dtrackLabel === "연결됨" ? "completed" : "partial"}`}>{dtrackLabel}</strong><span>버전 {dtrackStatus?.version || "-"}</span><span>팀 {dtrackStatus?.team || "-"}</span>{!dtrackStatus?.configured && (<p>KODA 자체 분석에는 필요하지 않습니다. 선택 연동을 명시적으로 활성화하고 API 키를 설정해야 BOM 업로드가 실행됩니다.</p>)}{dtrackStatus?.reachable && dtrackStatus?.authenticated && Boolean(dtrackStatus.missingPermissions.length) && (<p>연결은 되었지만 누락 권한을 확인하세요: {(dtrackStatus.missingPermissions || []).map(permissionLabel).join(", ")}</p>)}{dtrackStatus?.error && !dtrackStatus?.reachable && <p>{dtrackStatus.error}</p>}</div></div>)}
    </div>)}
    {activeTab === "reanalysis" && (canReanalysis || canReanalysisManage) && <ReanalysisSchedulePanel canManage={canReanalysisManage} services={services} environments={environments} />}
    {activeTab === "notifications" && (canNotifications || canNotificationManage) && <NotificationsPanel canManage={canNotificationManage} />}
    {activeTab === "sbom-policies" && (canSbomPolicies || canSbomPolicyManage) && <SbomPoliciesPanel canManage={canSbomPolicyManage} services={services} environments={environments} />}
    {activeTab === "services" && canServices && (<div id="settings-panel-services" role="tabpanel" aria-labelledby="settings-tab-services"><ServicesPage services={services} environments={environments} canManage={canCatalogManage} onChanged={onChanged} /></div>)}
    {activeTab === "ldap" && isAdmin && (<LdapSettingsPanel settings={ldapSettings} onChanged={onLdapChanged} />)}
    {activeTab === "users" && (canUsers || canTokens) && (<div className="settings-panel" id="settings-panel-users" role="tabpanel" aria-labelledby="settings-tab-users"><div className="settings-grid">{canUsers && (<div className="table-frame"><h2 className="table-title">사용자 {users.length}명</h2><table><thead><tr><th>사용자</th><th>역할</th><th>상태</th><th>작업</th></tr></thead><tbody>{users.length ? visibleUsers.map((item) => (<tr key={item.id || item.username} className={item.status === "pending" ? "pending-user" : ""}><td>{item.username}</td><td><select aria-label={`${item.username} 역할`} value={item.role} disabled={busy || item.status === "deleted"} onChange={(event) => void updateUser(item, "role", event.target.value)}>{canRoles && (<><option value="admin">관리자</option><option value="manager">매니저</option></>)}<option value="analyst">분석자</option><option value="uploader">업로더</option><option value="viewer">조회자</option></select></td><td><span className={`user-status ${item.status || (item.active ? "active" : "inactive")}`}>{userStatusLabel(item)}</span></td><td>{item.id && (item.status === "pending" ? (<button type="button" className="primary compact" disabled={busy} onClick={() => void approve(item)}>승인</button>) : item.status === "deleted" ? (<span>삭제됨</span>) : (<><button type="button" className="secondary compact" disabled={busy} onClick={() => void updateUser(item, "active", !item.active)}>{item.active ? "비활성화" : "활성화"}</button>{<button type="button" className="danger compact" disabled={busy} onClick={() => void removeUser(item)}>삭제</button>}</>))}</td></tr>)) : (<tr><td colSpan={4}>등록된 사용자가 없습니다.</td></tr>)}</tbody></table><DetailPagination total={users.length} page={currentUserPage} pageSize={accountPageSize} label="사용자 페이지당 행 수" onPage={setUserPage} onPageSize={(size) => { setAccountPageSize(size); setUserPage(1); setTokenPage(1); }} /></div>)}{canTokens && (<div className="table-frame"><h2 className="table-title">API 토큰 {tokens.length}개</h2><table><thead><tr><th>이름</th><th>서비스</th><th>생성 시각</th><th>상태</th><th /></tr></thead><tbody>{tokens.length ? visibleTokens.map((item) => (<tr key={item.id}><td>{item.name}</td><td>{services.find((service) => service.id === item.serviceId)?.name || item.serviceId || "-"}</td><td>{formatSeoulDateTime(item.createdAt)}</td><td>{item.active ? "활성" : "폐기"}</td><td>{item.active && (<button type="button" className="secondary compact" onClick={() => void revoke(item.id)} disabled={busy}>폐기</button>)}</td></tr>)) : (<tr><td colSpan={5}>발급된 토큰이 없습니다.</td></tr>)}</tbody></table><DetailPagination total={tokens.length} page={currentTokenPage} pageSize={accountPageSize} label="토큰 페이지당 행 수" onPage={setTokenPage} onPageSize={(size) => { setAccountPageSize(size); setUserPage(1); setTokenPage(1); }} /></div>)}</div></div>)}
    {activeTab === "roles" && canPolicyEdit && policies.length > 0 && (<div className="settings-panel" id="settings-panel-roles" role="tabpanel" aria-labelledby="settings-tab-roles"><div className="table-frame"><h2 className="table-title">권한 정책</h2>{POLICY_SECTIONS.map((section) => (<section className="role-policy-section" key={section.label}><div className="role-policy-section-heading"><h3>{section.label}</h3><p>{section.description}</p></div><div className="role-policy-grid">{roles.map((role) => (<fieldset key={role} aria-label={`${roleLabel(role)} ${section.label}`}><legend>{roleLabel(role)}</legend>{section.groups.map((group) => { const entries = group.permissions.filter((permission) => permissionNames.includes(permission)); return entries.length ? (<div className="permission-group" key={group.label}>{section.label === "기능 제어" && <h4>{group.label}</h4>}{entries.map((permission) => (<label key={permission}><input type="checkbox" checked={policyDraft[role]?.has(permission) || false} disabled={!canPolicyEdit || busy || (permission === "sbom.delete" && role !== "admin")} onChange={() => setPolicyDraft((current) => { const next = new Set(current[role] || []); if (next.has(permission)) next.delete(permission); else next.add(permission); return { ...current, [role]: next }; })} />{section.label === "화면 접근 권한" ? permissionLabel(permission).replace(/ 조회$/, "") : permissionLabel(permission)}</label>))}</div>) : null; })}</fieldset>))}</div></section>))}{canPolicyEdit && (<div className="role-policy-actions"><button type="button" className="primary" onClick={async () => { setBusy(true); setMessage(""); try { const changed = roles.filter((role) => { const before = policies.find((item) => item.role === role)?.permissions || []; const after = [...(policyDraft[role] || [])]; return before.length !== after.length || before.some((item) => !policyDraft[role]?.has(item)); }); if (!changed.length) { setMessage("변경된 역할 정책이 없습니다."); return; } const updated = await updateRolePolicies(changed.map((role) => ({ role, permissions: [...(policyDraft[role] || [])] }))); const next = policies.map((item) => updated.find((changedPolicy) => changedPolicy.role === item.role) || item); await onPolicyChanged(next); setMessage("역할 정책을 저장했습니다."); } catch (error) { setMessage(error instanceof Error ? error.message : "역할 정책 저장에 실패했습니다."); } finally { setBusy(false); } }}>권한 정책 저장</button></div>)}</div></div>)}
    {activeTab === "vulnerability" && isAdmin && canVulnerability && (<div id="settings-panel-vulnerability" role="tabpanel" aria-labelledby="settings-tab-vulnerability"><VulnerabilityPage embedded bundles={bundles} canManage={isAdmin && canVulnerabilityManage} onSync={onSync} onActivate={onActivate} /></div>)}
    {activeTab === "audit" && isAdmin && canAudit && (<div id="settings-panel-audit" role="tabpanel" aria-labelledby="settings-tab-audit"><AuditPage embedded events={auditEvents} /></div>)}
    {!settingsTabs.length && (<div className="empty-state"><Icon name="settings" /><h2>관리 가능한 설정이 없습니다.</h2><p>현재 계정에 허용된 설정 권한이 없습니다.</p></div>)}
    {mode && (<div className="modal-backdrop" role="presentation"><section className="modal" role="dialog" aria-modal="true" aria-labelledby="settings-modal-title"><header><h2 id="settings-modal-title">{mode === "user" ? "사용자 추가" : "API 토큰 발급"}</h2><button type="button" className="icon-button" aria-label="설정 창 닫기" onClick={() => setMode(null)}><Icon name="close" /></button></header><form onSubmit={submit}>{mode === "user" ? (<><label>사용자 이름<input name="username" required autoFocus /></label><label>임시 비밀번호<input name="password" type="password" minLength={12} required /></label><label>역할<select name="role" defaultValue="viewer">{canRoles && (<><option value="admin">관리자</option><option value="manager">매니저</option></>)}<option value="analyst">분석자</option><option value="uploader">업로더</option><option value="viewer">조회자</option></select></label></>) : (<><label>토큰 이름<input name="name" required autoFocus /></label><label>허용 서비스<select name="serviceId" required><option value="" disabled>서비스를 선택하세요</option>{services.map((item) => (<option key={item.id} value={item.id}>{item.name}</option>))}</select></label><small>서비스 범위 토큰입니다. 토큰 원문은 지금만 표시되며 서버에는 해시만 저장됩니다.</small></>)}{message && <p className="form-message">{message}</p>}<footer><button type="button" className="secondary" onClick={() => setMode(null)}>닫기</button><button className="primary" disabled={busy}>{busy ? "처리 중…" : "확인"}</button></footer></form></section></div>)}
  </section>);
}

function GenericPage({ rows }: { rows: string[][] }) {
  return (<section className="page generic-page"><h1>대시보드</h1><p>서비스와 최신 SBOM 회차의 운영 상태를 확인합니다.</p><div className="table-frame"><table><thead><tr><th>이름</th><th>구분</th><th>값</th><th>상태/시각</th></tr></thead><tbody>{rows.length ? (rows.map((row) => (<tr key={row.join()}>{row.map((cell) => (<td key={cell}>{cell}</td>))}</tr>) )
            ): (<tr><td colSpan={4}>표시할 데이터가 없습니다.</td></tr>)}</tbody></table></div></section>);}

function GuidePage() {
  return (<section className="page guide-page">
    <p className="preview-eyebrow">KODA SBOM TRACKER</p>
    <h1>사용 가이드</h1>
    <p className="guide-lead"><span>SBOM을 회차별로 관리하고 구성요소, CVE 취약점, 정책 결과의 변화를 추적하는 방법을 안내합니다.</span><span>표시되는 메뉴와 작업 버튼은 역할별 권한에 따라 달라질 수 있습니다.</span></p>
    <section className="guide-section" aria-labelledby="guide-flow-title">
      <h2 id="guide-flow-title">기본 사용 순서</h2>
      <ol className="guide-flow">
        <li><strong>서비스·환경 준비</strong><span>설정에서 SBOM을 구분할 서비스와 운영 환경을 확인합니다.</span></li>
        <li><strong>SBOM 업로드</strong><span>서비스, 환경, 릴리스를 선택하고 CycloneDX 파일을 등록합니다.</span></li>
        <li><strong>분석 결과 확인</strong><span>회차 상세에서 구성요소, CVE, CVSS, KEV, 제안 버전을 검토합니다.</span></li>
        <li><strong>변경 추적</strong><span>회차 비교에서 구성요소·취약점·정책 결과의 추가, 제거, 변경을 확인합니다.</span></li>
      </ol>
    </section>
    <section className="guide-section" aria-labelledby="guide-features-title">
      <h2 id="guide-features-title">주요 기능</h2>
      <div className="guide-card-grid">
        <article><h3>대시보드</h3><p>최신 SBOM의 구성요소 유형과 수, 취약 구성요소 추이, 심각도 및 KEV 현황을 한눈에 보여줍니다.</p></article>
        <article><h3>SBOM 회차</h3><p>서비스·환경·릴리스별 업로드 이력과 분석 상태를 관리하고 회차 상세 결과를 조회합니다.</p></article>
        <article><h3>취약점 분석</h3><p>CVE로 정규화된 결과를 기준으로 심각도, CVSS 점수, KEV 여부와 수정 가능한 제안 버전을 제공합니다.</p></article>
        <article><h3>회차 비교</h3><p>두 회차 사이의 구성요소, CVE 취약점과 정책 결과 차이를 비교합니다.</p></article>
        <article><h3>운영 설정</h3><p>서비스·환경, 사용자 승인, 역할별 권한, 취약점 데이터, 감사 로그와 외부 연동을 관리합니다.</p></article>
        <article><h3>감사와 이력</h3><p>업로드, 분석, 로그인, 관리 작업을 감사 로그로 확인하고 권한이 있는 관리자는 Excel 호환 CSV로 내려받을 수 있습니다.</p></article>
      </div>
    </section>
    <section className="guide-section" aria-labelledby="guide-terms-title">
      <h2 id="guide-terms-title">용어 설명</h2>
      <dl className="guide-glossary">
        <div><dt>SBOM (Software Bill of Materials)</dt><dd>소프트웨어를 구성하는 라이브러리, 패키지와 버전 등의 명세입니다.</dd></div>
        <div><dt>CycloneDX</dt><dd>Tracker가 업로드받는 표준 SBOM 형식으로 JSON(JavaScript Object Notation)과 XML(Extensible Markup Language)을 지원합니다.</dd></div>
        <div><dt>구성요소</dt><dd>SBOM에 포함된 라이브러리, 프레임워크, 애플리케이션 등의 개별 항목입니다.</dd></div>
        <div><dt>회차</dt><dd>서비스·환경·릴리스 조합에 업로드된 SBOM 한 건과 그 분석 이력입니다.</dd></div>
        <div><dt>CVE (Common Vulnerabilities and Exposures)</dt><dd>공개적으로 식별된 보안 취약점에 부여되는 표준 식별자입니다.</dd></div>
        <div><dt>CVSS (Common Vulnerability Scoring System)</dt><dd>취약점의 기술적 심각도를 점수로 표현하는 국제 표준입니다.</dd></div>
        <div><dt>NVD (National Vulnerability Database)</dt><dd>CVE 상세 정보와 CVSS 데이터를 제공하는 미국 국가 취약점 데이터베이스입니다.</dd></div>
        <div><dt>KEV (Known Exploited Vulnerabilities)</dt><dd>실제 악용이 확인되어 우선 대응이 필요한 CISA(Cybersecurity and Infrastructure Security Agency)의 취약점 목록입니다.</dd></div>
        <div><dt>제안 버전</dt><dd>현재 취약점이 수정된 것으로 확인된 업그레이드 후보 버전 전체입니다.</dd></div>
      </dl>
    </section>
  </section>);
}

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
    <img className="login-mark" src="/KODA.ico" alt="KODA" /><p className="eyebrow">KODA SECURITY OPERATIONS</p>
    <h1>KODA SBOM Tracker</h1><p>{mode === "login" ? "폐쇄망 SBOM 회차·분석 운영 포털" : "로컬 계정 가입 신청"}</p>
    <form onSubmit={submit}>
      <label>아이디
            <input name="username" autoComplete="username" required autoFocus /></label>
      <label>비밀번호
            <input name="password" type="password" minLength={mode === "register" ? 12 : undefined} autoComplete={mode === "register" ? "new-password" : "current-password"} required /></label>
      {mode === "register" && (<label>비밀번호 확인
            <input name="passwordConfirm" type="password" minLength={12} autoComplete="new-password" required /></label>)}
      {mode === "login" && (<label className="login-checkbox">
            <input name="useLdap" type="checkbox" defaultChecked /> LDAP 사용</label>)}
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
  const [rolePolicyCatalog, setRolePolicyCatalog] = useState<string[]>(previewMode ? [...demoRolePolicyCatalog.catalog] : []);
  const [rolePolicies, setRolePolicies] = useState<RolePolicy[]>(previewMode ? demoRolePolicyCatalog.roles.map((item) => ({ ...item, permissions: [...item.permissions] })) : []);
  const [genericRows, setGenericRows] = useState<Record<string, string[][]>>({});
  const [bundles, setBundles] = useState<VulnerabilityBundle[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [users, setUsers] = useState<UserSummary[]>([]);
  const [tokens, setTokens] = useState<ApiTokenSummary[]>([]);
  const [dtrackStatus, setDtrackStatus] = useState<DependencyTrackStatus | null>(null);
  const [ldapSettings, setLdapSettings] = useState<LdapSettings | null>(demoMode ? demoLdapSettings : null);
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
  const canRunAction = useCallback(
    (permission: string) => can(permission) && (permission !== "sbom.delete" || authUser?.role === "admin"),
    [authUser?.role, can]);
  const canUpload = hasPermissions(authUser, "sbom.upload", "services.view");
  const loadData = useCallback(async (loadedUser: AuthUser | null) => {
    setLoadError("");
    const loadedPermissions = permissionSet(loadedUser);
    const loadCan = (permission: string) => loadedPermissions.has("*") || loadedPermissions.has(permission);
    const access = dataAccess(loadedUser);
    let nextRuns: SbomRun[];
    let catalogs: { services: CatalogItem[]; environments: CatalogItem[] };
    try {
      const [runResult, nextCatalogs] = await Promise.all([
        access.runs ? fetchRuns({ size: 100 }) : Promise.resolve({ items: [] as SbomRun[], page: 1, size: 100, total: 0 }),
          access.catalogs ? fetchCatalogs({ includeInactive: loadedPermissions.has("catalog.manage") }) : Promise.resolve({ services: [], environments: [] }),
      ]);
      nextRuns = runResult.items;
      catalogs = nextCatalogs;
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "데이터를 불러오지 못했습니다.");
      return [];
    }
    setRuns(nextRuns);
    setServices(catalogs.services);
    setEnvironments(catalogs.environments);
    if (initialLink.runId) {
      let linkedRun = nextRuns.find((run) => run.id === initialLink.runId);
      if (!linkedRun && access.runs) {
        try {
          linkedRun = await fetchRun(initialLink.runId);
        } catch {
          setLoadError("링크의 SBOM 회차를 찾을 수 없습니다.");
        }
      }
      if (linkedRun) {
        setPage("runs");
        setSelectedRun(linkedRun);}
    }
    if (!demoMode && !standaloneMode) {
      const [auditResult, usersResult, bundlesResult, tokensResult, dtrackResult, ldapResult] = await Promise.allSettled([
        loadedUser?.role === "admin" && loadCan("audit.view")
          ? fetchAuditEvents()
          : Promise.resolve({ items: [] as AuditEvent[], page: 1, size: 10, total: 0 }),
        loadCan("users.manage") ?fetchUsers(): Promise.resolve([]),
        loadedUser?.role === "admin" && loadCan("vulnerability.view")
          ?fetchVulnerabilityBundles(): Promise.resolve([]),
        loadCan("tokens.manage") ?fetchApiTokens(): Promise.resolve([]),
        loadCan("dtrack.settings")
          ?fetchDependencyTrackStatus()
          : Promise.resolve(null),
        loadedUser?.role === "admin" ? fetchLdapSettings() : Promise.resolve(null)]);
      if (auditResult.status === "fulfilled") setAuditEvents(auditResult.value.items);
      if (usersResult.status === "fulfilled") setUsers(usersResult.value);
      if (bundlesResult.status === "fulfilled") setBundles(bundlesResult.value);
      if (tokensResult.status === "fulfilled") setTokens(tokensResult.value);
      if (dtrackResult.status === "fulfilled") setDtrackStatus(dtrackResult.value);
      if (ldapResult.status === "fulfilled") setLdapSettings(ldapResult.value);
      setGenericRows({
        dashboard: [
          ["등록 서비스", "서비스", String(catalogs.services.length), "활성"],
          ["SBOM 회차", "회차", String(nextRuns.length), nextRuns[0]?.createdAt || "-"],
          ["일부 실패", "처리 상태", String(nextRuns.filter((run) => run.state === "partial" || run.state === "failed").length), "검토 필요"]],
        services: catalogs.services.map((service) => [service.name, service.slug, service.id, "활성"]),
        audit: auditResult.status === "fulfilled" ? auditResult.value.items.map((item) => [item.actor, item.action, `${item.targetType}:${item.targetId}`, item.createdAt]) : [],
        settings: usersResult.status === "fulfilled" ? usersResult.value.map((item) => [item.username, item.role, item.active ? "활성" : "비활성", "-"]) : [],
        vuln: []});}
    if (standaloneMode) {
      setGenericRows({
        dashboard: [
          ["로컬 미리보기", "실행 모드", "standalone", "브라우저 분석"],
          ["업로드 회차", "SBOM", String(nextRuns.filter((run) => run.id.startsWith("standalone-")).length), "확인 가능"],
          ["서버 연동", "Docker·로그인·기존 외부 시스템", "사용 안 함", "미리보기"]]});}
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
  const content = useMemo(() => {
    if (page === "dashboard" ) return (<Dashboard runs={runs} onUpload={() => setUploadOpen(true)} canUpload={canUpload}
          standalone={standaloneMode}/>);
    if (page === "runs") return (<RunsPage runs={runs} services={services} environments={environments} search={globalSearch}
          canUpload={canUpload} onUpload={() => setUploadOpen(true)} onSelect={openRun} />);
    if (page === "compare") return <ComparePage runs={runs} can={can} />;
    if (page === "guide") return <GuidePage />;
    const settingsContent = (initialTab?: SettingsTab) => (<SettingsPage users={users} services={services} environments={environments} tokens={tokens} dtrackStatus={dtrackStatus} ldapSettings={ldapSettings} policies={rolePolicies}
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
          canSbomPolicies={can("policies.view")}
          canSbomPolicyManage={can("policies.manage")}
          canReanalysis={can("reanalysis.view")} canReanalysisManage={can("reanalysis.manage")}
          canNotifications={can("notifications.view")} canNotificationManage={can("notifications.manage")}
          canServices={can("services.view")}
          canCatalogManage={can("catalog.manage")}
          canMetadata={can("metadata.view")} canMetadataManage={can("metadata.manage")} canMigrations={can("migrations.manage")}
          initialTab={initialTab}
          onSync={async () => { const items = await syncVulnerabilityBundles(); setBundles(items);}}
          onActivate={async (version) => { await activateVulnerabilityBundle(version); const items = await fetchVulnerabilityBundles(); setBundles(items);}}
          onPolicyChanged={async (next) => {
            setRolePolicies(next);
            const session = await resumeSession();
            setAuthUser(session.user);
            await loadData(session.user);
            const nextPage = pageForPermissions(session.user, page);
            if (nextPage && nextPage !== page) navigate(nextPage);
          }}
          onLdapChanged={setLdapSettings}
          onChanged={() => void loadData(authUser)} />);
    if (page === "settings") return settingsContent(initialLink.settingsTab || undefined);
    return <GenericPage rows={genericRows.dashboard || []} />;}, [auditEvents, bundles, can,dtrackStatus, environments, genericRows, globalSearch, initialLink.settingsTab, ldapSettings, loadData, openRun, page, runs, services, tokens, users,
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
    <Sidebar page={page} collapsed={collapsed} onExpand={() => setCollapsed(false)} canNavigatePage={(next) => canPage(authUser, next)} onNavigate={(next) => canPage(authUser, next) && navigate(next)} />
    <Header collapsed={collapsed} search={globalSearch} onSearch={(value) => { setGlobalSearch(value); if (value.trim() && page !== "runs" && can("runs.view")) navigate("runs"); }} dataAsOf={runs.map((run) => preferredCveDate(run.cveDataAsOf, run.dataAsOf)).filter((value): value is string => Boolean(value) && value !== "unknown").sort().at(-1) || ""} onToggle={() => setCollapsed((value) => !value)} onLogout={() => {
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
    {selectedRun && (<RunDetail run={selectedRun} username={authUser?.username}
          can={canRunAction} onClose={closeRun} onChanged={() => void loadData(authUser)} />)}
  </div>);}

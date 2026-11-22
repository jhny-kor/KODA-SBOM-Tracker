import ComponentAddForm from "./ComponentAddForm";
import ComponentInspectorRow from "./ComponentInspectorRow";
import { DetailPagination } from "./DetailPagination";
import { RunDetailCard } from "./RunDetailCard";
import { ResizableTable } from "./ResizableTable";
import { Fragment, useCallback, useDeferredValue, useEffect, useId, useMemo, useRef, useState, type FormEvent } from "react";
import { demoMode, previewMode, standaloneMode, activateVulnerabilityBundle, approveUser, archiveRun, createApiToken, createAnalysis, createEnvironment, createService, createUser, deleteRun, deleteUser, fetchAuditEvents, fetchApiTokens, fetchCatalogs, fetchComparison, fetchJob, fetchLdapSettings, fetchRun, fetchRunComponents, fetchRunFindings, fetchRuns, fetchUsers, fetchVulnerabilityBundles, login, patchEnvironment, patchService, patchUser, logout, register, resumeSession, revokeApiToken, updateLdapSettings, uploadRun, syncVulnerabilityBundles, fetchRolePolicies, updateRolePolicies, setForbiddenHandler } from "./api";
import { demoChanges, demoLdapSettings, demoRolePolicyCatalog, demoRuns } from "./demo";
import { fetchActiveCveBaseline } from "./api";
import { formatSeoulDateTime } from "./format";
import { Icon } from "./icons";
import { FlowSelect, ScrollingSelect } from "./ScrollingSelect";
import { ScrollingText } from "./ScrollingText";
import { ReanalysisSchedulePanel } from "./ReanalysisSchedule";
import { PackageMetadataPanel } from "./OperationsData";
import { UnifiedVulnerabilityDataPanel } from "./UnifiedVulnerabilityData";
import { ProjectCatalogPanel } from "./ProjectCatalog";
import { PrivateVulnerabilitiesPanel } from "./PrivateVulnerabilities";
import { NotificationsPanel } from "./Notifications";
import { VexReviewsPanel } from "./VexReviews";
import { OfflineIntelligencePanel, OfflineRunEvidence } from "./OfflineIntelligence";
import { SsvcAssessmentsPanel } from "./SsvcAssessments";
import { EpssEvidence } from "./EpssEvidence";
import { CpeCoverage } from "./CpeCoverage";
import { OracleHomeEvidence } from "./OracleHomeEvidence";
import { latestAnalysisRevision } from "./analysisRevision";
import { SbomQualityPanel } from "./SbomQuality";
import { SbomPoliciesPanel } from "./SbomPolicies";
import { AnalysisPolicyHistory, NativePolicyResult } from "./NativePolicyResult";
import { policyCountLabel } from "./policy";
import LibrariesPage from "./Libraries";
import CveSearchPanel from "./CveSearch";
import EnvironmentAdministrators from "./EnvironmentAdministrators";
import RunMetadataEditor from "./RunMetadataEditor";
import ExternalReadTokens from "./ExternalReadTokens";
import JavaUpgradePanel from "./JavaUpgradePanel";
import OfflineUpgradePanel from "./OfflineUpgradePanel";
import OfficialCompatibilityData from "./OfficialCompatibilityData";
import { ComparisonAIBriefing, SharedAISettingsPanel, TrackerAISummary } from "./SharedAI";
import { analysisAvailable, analysisUnavailableReason } from "./analysisAvailability";
import { canPage, dataAccess, hasPermissions, pageForPermissions, permissionSet, type Page } from "./permissions";
import type { AnalysisRevisionSummary, AuditEvent, AuthUser, CatalogItem, Comparison, ComponentChange, ComponentSnapshot, LdapSettings, RecordChange, RolePolicy, SbomRun, SbomRunDetail, UserSummary, VulnerabilityBundle } from "./types";

const nav: { id: Page; label: string; icon: string }[] = [
  { id: "dashboard", label: "대시보드", icon: "dashboard" },
  { id: "runs", label: "SBOM 회차", icon: "runs" },
  { id: "libraries", label: "라이브러리", icon: "service" },
  { id: "compare", label: "회차 비교", icon: "compare" },
  { id: "settings", label: "설정", icon: "settings" }];
const guideNav = { id: "guide" as Page, label: "사용 가이드", icon: "guide" };

type SettingsTab = "private-vulnerabilities" | "metadata" | "cve-search" | "environment-admins" | "projects" | "reanalysis" | "notifications" | "sbom-policies" | "users" | "roles" | "vulnerability" | "audit" | "integration" | "shared-ai" | "compatibility-data" | "ldap" | "services";

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
  "sbom.archive": "회차 보관",
  "sbom.delete": "회차 영구 삭제",
  "catalog.manage": "서비스·환경 관리",
  "vulnerability.manage": "취약점 데이터 관리",
  "users.manage": "사용자 관리",
  "tokens.manage": "API 토큰 관리",
  "roles.manage": "권한 정책 관리",
  "policies.view": "SBOM 정책 조회",
  "policies.manage": "SBOM 정책 관리",
  "reanalysis.view": "재분석 일정 조회", "reanalysis.manage": "재분석 일정 관리",
  "vex.view": "VEX 검토 조회", "vex.manage": "VEX 검토 요청", "vex.approve": "VEX 검토 승인",
  "metadata.view": "패키지 메타데이터 조회", "metadata.manage": "패키지 메타데이터 수집",
  "notifications.view": "알림 조회", "notifications.manage": "알림 전송 관리",
};

const PERMISSION_GROUPS: { label: string; permissions: string[] }[] = [
  { label: "화면 조회", permissions: ["dashboard.view", "runs.view", "compare.view", "settings.view"] },
  { label: "SBOM·분석", permissions: ["sbom.upload", "artifact.download", "analysis.create", "sbom.archive", "sbom.delete"] },
  { label: "운영 관리", permissions: ["catalog.manage", "vulnerability.manage", "metadata.view", "metadata.manage", "policies.view", "policies.manage", "reanalysis.view", "reanalysis.manage", "vex.view", "vex.manage", "vex.approve", "notifications.view", "notifications.manage"] },
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
  if (updates.page && updates.page !== "compare") { url.searchParams.delete("baseRunId"); url.searchParams.delete("targetRunId"); }
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

function fixedInValues(record: Record<string, unknown>) {
  const value = record.fixedIn;
  const versions = Array.isArray(value) ? value.filter(Boolean).map(String) : value ? [String(value)] : [];
  return versions.length ? versions : ["-"];
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

function Header({ collapsed, onToggle, onLogout, dataAsOf, search, onSearch, preview, user }: { collapsed: boolean; onToggle: () => void; onLogout: () => void; dataAsOf: string | null; search: string; onSearch: (value: string) => void; preview: boolean; user: AuthUser | null;}) {
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
      <div className="freshness">{preview ? "CVE 기준일" : "활성 CVE 기준일"}: {dataBaselineLabel(dataAsOf, "확인 필요")}</div>
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
      <FlowSelect value={value} onChange={(event) => onChange(event.target.value)}>
        <option value="">전체</option>
        {values.map((item) => (<option key={item} value={item}>{formatValue ? formatValue(item) : item}</option>))}
      </FlowSelect>
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
  return (<article className="preview-metric-card preview-flow-values">
    <div><span className="preview-metric-label">{label}</span><strong>{value}</strong><small><ScrollingText>{description}</ScrollingText></small></div>
    <Sparkline values={values} color={color} label={label} pointLabels={pointLabels} />
  </article>);}

function PreviewBars({ items, emptyLabel }: { items: { label: string; value: number; tone?: string }[]; emptyLabel: string;}) {
  const maximum = Math.max(1, ...items.map((item) => item.value));
  if (!items.some((item) => item.value)) return <p className="preview-chart-empty">{emptyLabel}</p>;
  return (<div className="preview-bars">{items.map((item) => (<div className="preview-bar-row" key={item.label}>
    <span>{item.label}</span><div className="preview-bar-track"><i className={item.tone || ""} style={{ width: `${(item.value / maximum) * 100}%` }} /></div><strong>{item.value}</strong>
  </div>))}</div>);}

export function Dashboard({ runs, onUpload, loading = false, recent = false,
  standalone,
  canUpload}: { runs: SbomRun[]; onUpload: () => void;
  loading?: boolean;
  recent?: boolean;
  standalone: boolean;
  canUpload: boolean;}) {
  const uploadedRuns = useMemo(() => runs
    .filter((run) => run.state !== "archived" &&
            (!standalone ||
              run.service.id === "standalone-service" || run.id.startsWith("standalone-")))
    .sort((left, right) => left.createdAt.localeCompare(right.createdAt)), [runs, standalone]);
  // ponytail: chart the latest 12 uploads to keep the local preview readable; add pagination when history needs to scale.
  const chartRuns = useMemo(() => uploadedRuns.filter(analysisAvailable).slice(-12), [uploadedRuns]);
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
    {loading ? <p className="preview-empty" role="status">SBOM 현황을 불러오는 중입니다…</p> : <div className="preview-empty"><Icon name="upload" /><h2>아직 업로드한 SBOM이 없습니다.</h2><p>SBOM 회차에서 CycloneDX 1.4~1.7 JSON/XML 또는 SPDX 2.3 JSON을 업로드하면 이 화면에 분석
            그래프가 표시됩니다.
          </p>{canUpload && (<button className="primary" onClick={onUpload}>첫 SBOM 업로드
            </button>)}
        </div>}
  </section>);

  const series = [
    { label: "구성요소", color: "#32c6d1", values: chartRuns.map((run) => run.componentCount) },
    { label: "취약 구성요소", color: "#a970ff", values: chartRuns.map(vulnerableComponents) }];
  const trendMaximum = Math.max(1, ...series.flatMap((item) => item.values));
  return (<section className="page preview-dashboard-page">
    <div className="page-heading"><div><p className="preview-eyebrow">{standalone ? "LOCAL" : "OPERATIONS"} SBOM PORTFOLIO
          </p><h1>대시보드</h1><p className="preview-dashboard-subtitle">{recent ? "최근" : "등록된"} SBOM {uploadedRuns.length}건의 분석 결과입니다.{" "}
            {standalone ? "브라우저 내 미리보기 데이터" : "최신 분석 리비전"}을
            집계합니다.
          </p></div>{canUpload && (<button className="primary" onClick={onUpload}><Icon name="upload" />SBOM 업로드
          </button>)}
      </div>
    <div className="preview-metrics">
      <PreviewMetric label="구성요소 유형" value={componentTypeCount.toLocaleString()} description="최신 SBOM의 고유 유형" values={chartRuns.map((run) => Object.keys(run.componentTypeCounts || {}).length)} color="#32c6d1" pointLabels={chartRuns.map(pointLabel)} />
      <PreviewMetric label="구성요소" value={(latest?.componentCount || 0).toLocaleString()} description={`최신 · ${latest?.filename || "SBOM"}`} values={chartRuns.map((run) => run.componentCount)} color="#32c6d1" pointLabels={chartRuns.map(pointLabel)} />
      <PreviewMetric label="취약 구성요소" value={analysisAvailable(latest) ? vulnerableComponents(latest!).toLocaleString() : "미평가"} description="취약점이 있는 고유 구성요소" values={chartRuns.map(vulnerableComponents)} color="#a970ff" pointLabels={chartRuns.map(pointLabel)} />
      <PreviewMetric label="KEV" value={analysisAvailable(latest) ? kevCount.toLocaleString() : "미평가"} description={standalone ?"내장 KEV 플래그" : "분석 결과 KEV 플래그"} values={chartRuns.map((run) => run.kevCount || 0)} color="#ff8b8b" pointLabels={chartRuns.map(pointLabel)} />
    </div>
    <div className="preview-chart-grid">
      <article className="preview-chart-card preview-trend-card"><header><div><h2>업로드별 분석 추이</h2><p>분석 완료 회차의 구성요소·취약 구성요소 변화</p></div><span className="preview-chart-meta">{cveBaseline(latest)}</span></header>
        <div className="preview-legend">{series.map((item) => (<span key={item.label}><i style={{ background: item.color }} />{item.label}</span>))}</div>
        <div className="preview-chart-scroll"><div className="preview-chart-canvas"><svg className="preview-chart" viewBox="0 0 760 250" role="img" aria-label="업로드별 구성요소와 취약 구성요소 추이">
          <title>업로드별 구성요소와 취약 구성요소 추이</title>
          {[50, 105, 160, 215].map((y) => (<line key={y} x1="36" x2="744" y1={y} y2={y} className="preview-grid-line" />))}
          {series.map((item) => (<g key={item.label}><path d={pathFor(item.values, 708, 165, trendMaximum)} transform="translate(36 45)" fill="none" stroke={item.color} strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />{chartPoints(item.values, 708, 165, 4, trendMaximum).map((point, index) => { const run = chartRuns[index]; const x = point.x + 36; const y = point.y + 45; const text = `${item.label} · #${run.roundNumber} · ${run.service.name}/${run.environment.name} · ${item.values[index]} · CVE 기준일 ${cveBaseline(run)}`; const show = () => setTrendTooltip({ x: Math.max(14, Math.min(86, (x / 760) * 100)), y: (y / 250) * 100, text }); return (<circle className="preview-chart-point" key={`${item.label}-${index}`} cx={x} cy={y} r="4" fill={item.color} role="img" aria-label={text} tabIndex={0} onMouseEnter={show} onMouseLeave={() => setTrendTooltip(null)} onFocus={show} onBlur={() => setTrendTooltip(null)} />); })}</g>))}
          {chartRuns.map((run, index) => (<text key={run.id} x={chartRuns.length === 1 ? 390 : 36 + (index / (chartRuns.length - 1)) * 708} y="238" textAnchor="middle" className="preview-axis-label">#{uploadedRuns.length - chartRuns.length + index + 1}</text>))}
        </svg><ImmediateChartTooltip tooltip={trendTooltip} /></div></div>
      </article>
      <article className="preview-chart-card preview-flow-values"><header><div><h2>최신 SBOM 심각도</h2><p><ScrollingText>{latest?.filename || "업로드 파일"}</ScrollingText></p></div><span className="preview-chart-total">{analysisAvailable(latest) ? `${latest?.vulnerabilityCount || 0}건` : "미평가"}</span></header>
        {analysisAvailable(latest) ? <PreviewBars items={severityItems} emptyLabel="최신 분석에 취약점 레코드가 없습니다." /> : <p role="alert">{analysisUnavailableReason(latest)}</p>}
        <div className="preview-chart-footnote">CVE 기준일 {cveBaseline(latest)} · KEV {analysisAvailable(latest) ? `${kevCount}건` : "미평가"}
          </div>
      </article>
    </div>
    <div className="preview-lower-grid">
      <article className="preview-chart-card"><header><div><h2>구성요소 유형</h2><p>최신 업로드 기준</p></div><span className="preview-chart-total">{latest?.componentCount || 0}개
            </span></header><PreviewBars items={componentTypes} emptyLabel="구성요소 상세를 불러오는 중입니다." /></article>
      <article className="preview-upload-summary preview-flow-values"><span className="preview-eyebrow">LATEST UPLOAD</span><h2><ScrollingText>{latest?.filename || "SBOM 파일"}</ScrollingText></h2><dl><dt>릴리스</dt><dd><ScrollingText>{latest?.releaseVersion || ""}</ScrollingText></dd><dt>CVE 기준일</dt><dd>{cveBaseline(latest)}</dd><dt>업로드 시각</dt><dd>{latest ? formatSeoulDateTime(latest.createdAt) : "-"}</dd></dl></article>
    </div>
  </section>);}

function RunsPage({ revision, services, environments, search, onUpload, onSelect,
  canUpload}: { revision: number; services: CatalogItem[]; environments: CatalogItem[]; search: string; onUpload: () => void; onSelect: (run: SbomRun) => void;
  canUpload: boolean;}) {
  const [service, setService] = useState("");
  const [environment, setEnvironment] = useState("");
  const [state, setState] = useState("");
  const [source, setSource] = useState<"manual" | "scheduled">("manual");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [result, setResult] = useState({ items: [] as SbomRun[], page: 1, size: 10, total: 0 });
  const [searching, setSearching] = useState(true);
  const [error, setError] = useState("");
  const deferredSearch = useDeferredValue(search.trim());
  useEffect(() => { queueMicrotask(() => setPage(1)); }, [deferredSearch]);
  useEffect(() => {
    const request = new AbortController();
    queueMicrotask(() => {
      if (!request.signal.aborted) {
        setSearching(true);
        setError("");
      }
    });
    void fetchRuns({ page, size: pageSize, q: deferredSearch, serviceId: service, environmentId: environment, state, source }, request.signal)
      .then((next) => {
        if (request.signal.aborted) return;
        const finalPage = Math.max(1, Math.ceil(next.total / pageSize));
        if (page > finalPage) setPage(finalPage);
        setResult(next);
      })
      .catch((reason) => { if (!request.signal.aborted) setError(reason instanceof Error ? reason.message : "회차를 불러오지 못했습니다."); })
      .finally(() => { if (!request.signal.aborted) setSearching(false); });
    return () => request.abort();
  }, [deferredSearch, environment, page, pageSize, revision, service, source, state]);
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
          <ResizableTable className="runs-table">
            <thead><tr><th>서비스</th><th>환경</th><th>릴리스</th><th>회차</th><th>CVE 기준일</th><th>구성요소</th><th>취약 구성요소</th><th>정책 위반</th><th>처리 상태</th><th>업로드 시각</th></tr></thead>
            <tbody>
              {visible.map((run) => (
                <tr key={run.id} onClick={() => onSelect(run)} tabIndex={0}>
                  <td className="sticky-name"><ScrollingText>{run.service.name}</ScrollingText></td><td><ScrollingText>{run.environment.name}</ScrollingText></td><td><ScrollingText>{run.releaseVersion}</ScrollingText></td>
                  <td>{run.roundNumber}차</td><td>{cveBaseline(run)}</td><td>{run.componentCount.toLocaleString()}</td>
                  <td title={analysisAvailable(run) ? undefined : analysisUnavailableReason(run)}>{analysisAvailable(run) ? (run.vulnerableComponentCount?.toLocaleString() ?? "미평가") : <>미평가<small className="workflow-id">{analysisUnavailableReason(run)}</small></>}</td><td>{policyCountLabel(run)}</td>
                  <td><span className={`state ${run.state}`}>{stateLabel(run.state)}</span></td>
                  <td>{formatSeoulDateTime(run.createdAt)}</td>
                </tr>
              ))}
              {!visible.length && (<tr><td colSpan={10}>{searching ? "구성요소와 회차를 검색하고 있습니다…" : error || "조건에 맞는 회차가 없습니다."}</td></tr>)}
            </tbody>
          </ResizableTable>
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
  const [baseId, setBaseId] = useState(() => new URLSearchParams(window.location.search).get("baseRunId") || defaultBase?.id || "");
  const [targetId, setTargetId] = useState(() => new URLSearchParams(window.location.search).get("targetRunId") || defaultTarget?.id || "");
  const [linkedRuns, setLinkedRuns] = useState<SbomRun[]>([]);
  const [baseAnalyses, setBaseAnalyses] = useState<AnalysisRevisionSummary[]>([]);
  const [targetAnalyses, setTargetAnalyses] = useState<AnalysisRevisionSummary[]>([]);
  const [baseAnalysisId, setBaseAnalysisId] = useState("");
  const [targetAnalysisId, setTargetAnalysisId] = useState("");
  const [tab, setTab] = useState<"components" | "vulnerabilities" | "policies">("components");
  const [componentPage, setComponentPage] = useState(1);
  const [componentPageSize, setComponentPageSize] = useState(10);
  const [selected, setSelected] = useState<ComponentChange | null>(demoChanges[2]);
  const [comparison, setComparison] = useState<Comparison | null>(null);
  const [message, setMessage] = useState("");
  const options = [...new Map([...runs, ...linkedRuns].map(run => [run.id, run])).values()];
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
      setComponentPage(1);
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
        setLinkedRuns([baseDetail, targetDetail]);
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
  const baseRevision = baseAnalyses.find(item => item.id === baseAnalysisId);
  const targetRevision = targetAnalyses.find(item => item.id === targetAnalysisId);
  const securityAvailable = !!comparison && analysisAvailable(baseRevision || baseRun) && analysisAvailable(targetRevision || targetRun);
  const summary = comparison?.summary;
  const changes = comparison?.components || [];
  const visibleComponentPage = Math.min(componentPage, Math.max(1, Math.ceil(changes.length / componentPageSize)));
  const componentOffset = (visibleComponentPage - 1) * componentPageSize;
  const visibleChanges = changes.slice(componentOffset, componentOffset + componentPageSize);
  return (
    <section className="page compare-page">
      <h1>회차 비교</h1>
      <div className="compare-pickers">
        <label><span>기준 회차</span><ScrollingSelect value={baseId} text={baseRun ? label(baseRun) : ""} label="기준 회차" onChange={(value) => { setBaseId(value); setComparison(null);}}>{options.map((run) => (<option value={run.id} key={run.id}>{label(run)}</option>))}</ScrollingSelect></label>
        <span className="swap" aria-hidden="true"><Icon name="swap" /></span>
        <label><span>비교 회차</span><ScrollingSelect value={targetId} text={targetRun ? label(targetRun) : ""} label="비교 회차" onChange={(value) => { setTargetId(value); setComparison(null);}}>{options.map((run) => (<option value={run.id} key={run.id}>{label(run)}</option>))}</ScrollingSelect></label>
        <button className="primary compare-action" onClick={() => void compare()}>비교
        </button>
      </div>
      <div className="analysis-pickers"><label><span>기준 분석 리비전</span><ScrollingSelect value={baseAnalysisId} text={(() => { const item = baseAnalyses.find((item) => item.id === baseAnalysisId); return item ? `r${item.sequence} · ${dataBaselineLabel(preferredCveDate(item.cveDataAsOf, item.dataAsOf), "CVE 기준일 확인 필요")}` : "최신 리비전"; })()} label="기준 분석 리비전" onChange={(value) => { setBaseAnalysisId(value); setComparison(null);}}><option value="">최신 리비전</option>{baseAnalyses.map((item) => (<option key={item.id} value={item.id}>r{item.sequence} · {dataBaselineLabel(preferredCveDate(item.cveDataAsOf, item.dataAsOf), "CVE 기준일 확인 필요")}</option>))}</ScrollingSelect></label><label><span>비교 분석 리비전</span><ScrollingSelect value={targetAnalysisId} text={(() => { const item = targetAnalyses.find((item) => item.id === targetAnalysisId); return item ? `r${item.sequence} · ${dataBaselineLabel(preferredCveDate(item.cveDataAsOf, item.dataAsOf), "CVE 기준일 확인 필요")}` : "최신 리비전"; })()} label="비교 분석 리비전" onChange={(value) => { setTargetAnalysisId(value); setComparison(null);}}><option value="">최신 리비전</option>{targetAnalyses.map((item) => (<option key={item.id} value={item.id}>r{item.sequence} · {dataBaselineLabel(preferredCveDate(item.cveDataAsOf, item.dataAsOf), "CVE 기준일 확인 필요")}</option>))}</ScrollingSelect></label></div>
      {message && (<p className="form-message" role="status">{message}</p>)}
      {!securityAvailable && <p role="alert">취약점·정책 비교 미평가: {analysisUnavailableReason(!analysisAvailable(baseRevision || baseRun) ? baseRevision || baseRun : targetRevision || targetRun)}</p>}
      <div className="diff-summary">
        {[
          ["구성요소 추가", summary?.componentsAdded ?? 0, "teal"],
          ["구성요소 제거", summary?.componentsRemoved ?? 0, "red"],
          ["구성요소 변경", summary?.componentsChanged ?? 0, "amber"],
          ["신규 취약점", summary?.vulnerabilitiesAdded ?? 0, "red"],
          ["해소 취약점", summary?.vulnerabilitiesRemoved ?? 0, "teal"],
          ["정책 변화", summary?.policiesChanged ?? 0, "red"]].map((item) => (<div key={item[0]}><span>{item[0]}</span><strong className={String(item[2])}>{["신규 취약점", "해소 취약점", "정책 변화"].includes(String(item[0])) && !securityAvailable ? "미평가" : item[1]}</strong></div>))}
      </div>
      {!previewMode && comparison && securityAvailable && <ComparisonAIBriefing key={`${comparison.base.runId}:${comparison.target.runId}:${baseAnalysisId}:${targetAnalysisId}`} baseRunId={comparison.base.runId} targetRunId={comparison.target.runId} baseAnalysisId={baseAnalysisId || undefined} targetAnalysisId={targetAnalysisId || undefined} />}
      <div className="tabs" role="tablist">
        <button role="tab" aria-selected={tab === "components"} className={tab === "components" ? "active" : ""} onClick={() => setTab("components")}>구성요소
        </button>
        <button role="tab" aria-selected={tab === "vulnerabilities"} className={tab === "vulnerabilities" ? "active" : ""} onClick={() => setTab("vulnerabilities")}>취약점
        </button>
        <button role="tab" aria-selected={tab === "policies"} className={tab === "policies" ? "active" : ""} onClick={() => setTab("policies")}>정책 위반
        </button>
      </div>
      {tab === "policies" && comparison && securityAvailable && <p className="form-message">기준 정책: {comparison.base.policyVersion ? `v${comparison.base.policyVersion}` : "기존 결과"} · {comparison.base.policyState === "completed" ? "평가 완료" : comparison.base.policyState === "failed" ? "평가 실패" : "KODA 정책 미평가"} / 비교 정책: {comparison.target.policyVersion ? `v${comparison.target.policyVersion}` : "기존 결과"} · {comparison.target.policyState === "completed" ? "평가 완료" : comparison.target.policyState === "failed" ? "평가 실패" : "KODA 정책 미평가"}</p>}
      {tab === "components" ? (
        <>
          <div className="table-frame diff-table-frame">
            <DetailPagination label="구성요소 비교" total={changes.length} page={visibleComponentPage} pageSize={componentPageSize} onPage={setComponentPage} onPageSize={size => { setComponentPageSize(size); setComponentPage(1); }} />
            <div className="table-scroll"><ResizableTable className="diff-table">
            <thead><tr><th>변화</th><th>구성요소</th><th>기준 버전</th><th>비교 버전</th><th>PURL</th></tr></thead>
            <tbody>{visibleChanges.map((change) => (<tr key={change.identityKey} className={selected?.identityKey === change.identityKey ? "selected" : ""} onClick={() => setSelected(change)}>
              <td><span className={`change ${changeLabel(change).replace(" ", "-")}`}>{changeLabel(change)}</span></td><td>{change.name}</td><td>{change.baseVersion ?? "-"}</td><td>{change.targetVersion ?? "-"}</td><td className="mono">{change.purl}</td>
            </tr>))}</tbody>
          </ResizableTable></div></div>
          {selected ? (<ComponentInspector change={selected} comparison={securityAvailable ? comparison : null} can={can} /> ): (<p className="muted">구성요소 변화가 없습니다.</p>)}
        </>
      ) : !securityAvailable ? <p>완료된 분석 리비전을 선택해야 취약점·정책 변화를 확인할 수 있습니다.</p> : (
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
        <h3>연관 취약점</h3><ul className="vulnerabilities">{related.length ? (related.map((item, index) => { const record = item.record || item.target || item.base || {}; return (<li key={`${item.change}-${index}`}><b>{item.change === "added" ? "신규" : item.change === "removed" ? "해소" : "변경"}</b> {" "}{String(record.canonicalId || record.id || "식별자 없음")}{" "} <em>{String(record.severity || "UNKNOWN")}</em>{record.kev ? <span> · KEV</span> : null}</li>);}) ): (<li>{comparison ? "이 비교에서 직접 연관된 취약점이 없습니다." : "취약점 비교 미평가"}</li>)}</ul>
      </div>
      <div><h3>변경 정보</h3>{propertyEntries.map(([key, value]) => (<p key={key} className="muted">{key}: {value}</p>))}<h3>변경 내용</h3><p>{change.fields.length ? change.fields.filter((field) => field !== "sha256").join(", ") || "내용 변경" : "변경 필드 없음"}</p><div className="inspector-actions">{can("artifact.download") && comparison?.base.artifactUrl && (<a className="secondary" href={comparison.base.artifactUrl}>기준 원본 보기
            </a>)}{can("artifact.download") && comparison?.target.artifactUrl && (<a className="secondary" href={comparison.target.artifactUrl}>비교 원본 보기
            </a>)}</div></div>
    </div>
  );}

function ComparisonRecordsTable({ kind, rows }: { kind: string; rows: RecordChange[];}) {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const visiblePage = Math.min(page, Math.max(1, Math.ceil(rows.length / pageSize)));
  const offset = (visiblePage - 1) * pageSize;
  const visibleRows = rows.slice(offset, offset + pageSize);
  const isVulnerability = kind === "취약점";
  return (<><>{kind === "정책 위반" && <p className="form-message">정책 위반은 분석 리비전에 저장된 판정 결과의 추가·해소·변경 내역입니다. KODA 정책 버전과 예외 변경도 비교에 반영됩니다. 기존 기존 외부 시스템 결과는 과거 리비전에 보존됩니다.</p>}</><div className="table-frame diff-table-frame"><DetailPagination label={`${kind} 비교`} total={rows.length} page={visiblePage} pageSize={pageSize} onPage={setPage} onPageSize={size => { setPageSize(size); setPage(1); }} /><div className="table-scroll"><ResizableTable className="diff-table records-table"><thead><tr><th>변화</th><th>{isVulnerability ? "식별자" : "규칙"}</th><th>구성요소</th>{isVulnerability && <><th>CVSS</th><th>KEV</th></>}<th>상태</th></tr></thead><tbody>{rows.length ? (visibleRows.map((row, index) => {
    const record = row.record || row.target || row.base || {};
    const status = severityValue(record);
    return (<tr key={`${row.change}-${index}`}><td><span className={`change ${row.change === "added" ? "추가" : row.change === "removed" ? "제거" : "버전-변경"}`}>{row.change === "added" ? "신규" : row.change === "removed" ? "해소" : "변경"}</span></td><td className="mono">{String(record.canonicalId || record.id || record.policyName || record.policyId || record.rule || "-")}</td><td>{String(record.component || "-")}</td>{isVulnerability && <><td>{cvssScore(record)}</td><td>{record.kev ? "KEV" : "-"}</td></>}<td>{isVulnerability ? <span className={`severity-pill ${severityClass(status)}`}>{severityLabel(status)}</span> : record.suppressed ? "기한부 예외" : record.action === "fail" ? "위반" : record.action === "warn" ? "경고" : String(status)}</td></tr>);}) ): (<tr><td colSpan={isVulnerability ? 6 : 4}>변화가 없습니다.</td></tr>)}</tbody></ResizableTable></div></div></>);}


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
  return (<div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}><section className="modal sbom-upload-modal" role="dialog" aria-modal="true" aria-labelledby="upload-title">
    <header><h2 id="upload-title">SBOM 업로드</h2><button type="button" className="icon-button" aria-label="SBOM 업로드 창 닫기" onClick={onClose}><Icon name="close" /></button></header>
    <form onSubmit={submit}>
      {standaloneMode ? (<p className="preview-note">로그인·서버 없이 브라우저에서 CycloneDX 구조와 파일에 포함된
              취약점 레코드만 분석합니다.
            </p> ): (<label>서비스
              <FlowSelect name="serviceId" required>{services.filter((service) => service.active !== false).map((service) => (<option key={service.id} value={service.id}>{service.name}</option>))}</FlowSelect></label>)}
      <div className="form-row">{!standaloneMode && (<label>환경
                <FlowSelect name="environmentId" required>{environments.filter((environment) => environment.active !== false).map((environment) => (<option key={environment.id} value={environment.id}>{environment.name}</option>))}</FlowSelect></label>)}<label>{standaloneMode ? "릴리스 (선택)" : "릴리스"}<input name="releaseVersion" placeholder="예: 1.4.2" defaultValue={standaloneMode ? "preview" : undefined} required={!standaloneMode} /></label></div>
      <label>SBOM 파일
        <input name="sbom" type="file" aria-label="SBOM 파일"
          accept={standaloneMode ? ".json,.xml,application/json,application/xml" : ".json,.xml,.zip,.tar,.tar.gz,.tgz,.7z,.xlsx,.csv,text/csv,application/json,application/xml,application/spdx+json,application/vnd.cyclonedx+json,application/vnd.cyclonedx+xml"}
          aria-describedby={`sbom-supported-formats${standaloneMode ? "" : " sbom-archive-formats sbom-workbook-format"} sbom-upload-limit`} required />
        <small id="sbom-supported-formats">{standaloneMode ? "로컬 미리보기: CycloneDX JSON/XML" : "지원 형식: CycloneDX 1.4, 1.5, 1.6, 1.7 (JSON/XML) · SPDX 2.3 (JSON) · NIS-SBOM 1.0 (CSV)"}</small>
        {!standaloneMode && <>
          <small id="sbom-archive-formats">압축 업로드: ZIP · TAR.GZ/TGZ · TAR · 7Z. 압축파일에는 위 지원 형식의 JSON/XML/CSV 문서 파일만 정확히 1개 넣으세요. README 등 동반 파일은 허용하지 않습니다. 형식과 내용은 서버에서 확인합니다.</small>
          <small id="sbom-workbook-format">Excel (.xlsx, 최대 10 MiB) 첫 시트의 1~5행에는 A열 또는 B열에 항목명, C열에 값을 입력하세요. 항목 순서는 솔루션명, 기준 버전, 운영 OS Platform, 작성일자, 대상 서버입니다. 6행 A~F열은 번호, 구분, 컴포넌트명, 버전, 라이선스 유형, 비고 / 상세 설명입니다. 버전은 텍스트 셀에 입력하세요.</small>
        </>}
        <small id="sbom-upload-limit">{standaloneMode ? "최대 100 MiB" : "업로드 및 압축 해제 후 최대 5 GiB · 128 MiB 초과 문서는 CycloneDX 1.6/1.7 UTF-8 JSON으로 제출하세요."}</small>
      </label>
      <label>메모
            <textarea name="note" rows={3} placeholder="변경 사유 또는 배포 식별자" /></label>
      {message && (<p className="form-message" role="status">{message}{jobState && <small> · 작업 상태: {jobStateLabel(jobState)}</small>}</p>)}
      <footer><button type="button" className="secondary" onClick={onClose}>취소
            </button><button disabled={busy} className="primary">{busy ? "업로드 중…" : "업로드"}</button></footer>
    </form>
  </section></div>);}

function workbookComponentNotes(component: ComponentSnapshot) {
  if (!Array.isArray(component.properties)) return "-";
  const notes = [];
  for (const property of component.properties) {
    if (!property || typeof property !== "object" || !("name" in property) || !("value" in property)) continue;
    if (property.name === "koda:xlsx:category" || property.name === "koda:xlsx:description") {
      notes.push(String(property.value));
    }
  }
  return notes.join(" · ") || "-";
}

function RunDetail({ run, onClose, onChanged, username, onOpenLibrary,
  can}: { run: SbomRun; onClose: () => void; onChanged: () => void;
  onOpenLibrary?: (query: string) => void;
  can: (permission: string) => boolean; username?: string;}) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [archiveReason, setArchiveReason] = useState("");
  const [detail, setDetail] = useState<SbomRunDetail | null>(null);
  const [componentQuery, setComponentQuery] = useState("");
  const [editingComponentId, setEditingComponentId] = useState("");
  const [addingComponent, setAddingComponent] = useState(false);
  const addComponentFormId = useId();
  const [showRemovedComponents, setShowRemovedComponents] = useState(false);
  const [componentRefresh, setComponentRefresh] = useState(0);
  const [componentMessage, setComponentMessage] = useState("");
  const [componentLoadError, setComponentLoadError] = useState("");
  const [componentPage, setComponentPage] = useState(1);
  const [componentPageSize, setComponentPageSize] = useState(10);
  const [findingPage, setFindingPage] = useState(1);
  const [findingPageSize, setFindingPageSize] = useState(10);
  const [componentResult, setComponentResult] = useState({
    items: [] as ComponentSnapshot[], total: 0, removedTotal: 0, showingRemoved: false,
  });
  const [findingResult, setFindingResult] = useState<{ items: Record<string, unknown>[]; total: number }>({ items: [], total: 0 });
  const deferredComponentQuery = useDeferredValue(componentQuery.trim());
  const latestAnalysis = latestAnalysisRevision(detail?.analyses);
  const latestAnalysisId = latestAnalysis?.id || "";
  useEffect(() => {
    let cancelled = false;
    void fetchRun(run.id).then((result) => { if (!cancelled) setDetail(result);}).catch((error) => { if (!cancelled) setMessage(error instanceof Error ? error.message : "회차 상세를 불러오지 못했습니다.");});
    return () => { cancelled = true;};}, [run.id]);
  useEffect(() => {
    let cancelled = false;
    void fetchRunComponents(run.id, componentPage, componentPageSize, deferredComponentQuery, showRemovedComponents)
      .then((result) => {
        if (cancelled) return;
        setComponentLoadError("");
        const lastPage = Math.max(1, Math.ceil(result.total / componentPageSize));
        if (componentPage > lastPage) setComponentPage(lastPage);
        setComponentResult({
          items: result.items, total: result.total, removedTotal: result.removedTotal ?? 0, showingRemoved: showRemovedComponents,
        });
      })
      .catch((error) => {
        if (!cancelled) setComponentLoadError(error instanceof Error ? error.message : "구성요소를 불러오지 못했습니다.");
      });
    return () => { cancelled = true; };
  }, [componentPage, componentPageSize, deferredComponentQuery, componentRefresh, run.id, showRemovedComponents]);
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
    if (!window.confirm(`이 SBOM 회차와 Tracker 원본을 영구 삭제하시겠습니까?`)) return;
    setBusy(true); setMessage("");
    try { await deleteRun(current.id); onChanged(); onClose(); }
    catch (error) { setMessage(error instanceof Error ? error.message : "회차 삭제에 실패했습니다"); }
    finally { setBusy(false); }
  }
  const current = detail || run;
  const workbookMetadata = detail?.workbookMetadata;
  const scheduled = current.source === "scheduled";
  const sourceMetadata = current.sourceMetadata || {};
  const loadingComponentView = componentResult.showingRemoved !== showRemovedComponents;
  const components = loadingComponentView ? [] : componentResult.items;
  const canCorrectComponent = !previewMode && current.state !== "archived" && can("runs.view");
  const findings = analysisAvailable(current) ? findingResult.items : [];
  const showCompletedRunTools = !previewMode && current.state === "completed" && can("runs.view");
  const componentPageCount = Math.max(1, Math.ceil(componentResult.total / componentPageSize));
  const currentComponentPage = Math.min(componentPage, componentPageCount);
  const findingPageCount = Math.max(1, Math.ceil(findingResult.total / findingPageSize));
  const currentFindingPage = Math.min(findingPage, findingPageCount);
  return (<div className="drawer-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}><section className="detail-modal" role="dialog" aria-modal="true" aria-labelledby="run-detail-title"><header><div><ScrollingText>{current.service.name}</ScrollingText><h2 id="run-detail-title"><ScrollingText>{`${current.releaseVersion} · ${current.roundNumber}차`}</ScrollingText></h2></div><button type="button" className="icon-button" aria-label="회차 상세 닫기" onClick={onClose}><Icon name="close" /></button></header>
    <div className="detail-status"><span className={`state ${current.state}`}>{stateLabel(current.state)}</span><span>{scheduled ? "스케줄 점검" : "수동/API 점검"}</span><span className="detail-environment"><ScrollingText>{current.environment.name}</ScrollingText></span><span>CycloneDX {current.specVersion}</span></div>
    <section className="run-detail-group" aria-labelledby="run-detail-summary"><h3 id="run-detail-summary">회차 정보</h3>
    <dl><dt>원본 파일</dt><dd><ScrollingText>{current.filename || "-"}</ScrollingText></dd>{scheduled && (<><dt>대상 서버</dt><dd>{String(sourceMetadata.server || sourceMetadata.remoteServer || "-")}</dd><dt>대상 디렉토리</dt><dd className="mono wrap">{String(sourceMetadata.directory || sourceMetadata.remoteDirectory || "-")}</dd><dt>점검 방식</dt><dd>{String(sourceMetadata.mode || "-")}</dd><dt>예약 실행 ID</dt><dd className="mono wrap">{String(sourceMetadata.scheduleRunId || "-")}</dd><dt>규칙 버전</dt><dd>{String(sourceMetadata.rulePolicyVersion ?? "-")}</dd></>)}<dt>CVE 기준일</dt><dd>{cveBaseline(current)}</dd><dt>오프라인 분석</dt><dd>{jobStateLabel(current.analysisState)}</dd><dt>구성요소</dt><dd>{current.componentCount.toLocaleString()}개</dd><dt>취약 구성요소</dt><dd>{analysisAvailable(current) && current.vulnerableComponentCount != null ? `${current.vulnerableComponentCount.toLocaleString()}개` : "미평가"}</dd><dt>정책 위반·경고·정보</dt><dd>{policyCountLabel(current)}{current.policyState === "completed" ? "건" : ""}</dd></dl>
    {workbookMetadata && <>
      <h3>Excel 원본 정보</h3>
      <dl>{Object.entries(workbookMetadata).map(([label, value]) => (
        <Fragment key={label}><dt>{label}</dt><dd><ScrollingText>{value || "-"}</ScrollingText></dd></Fragment>
      ))}</dl>
      <p className="preview-note">이 양식에는 PURL과 CPE 입력란이 없어 취약점 자동 매칭 범위가 제한될 수 있습니다.</p>
    </>}
    {!analysisAvailable(current) && <p role="alert" className="drawer-error">{analysisUnavailableReason(current)}</p>}
    {current.note && <p className="preview-note">메모: {current.note}</p>}
    <RunMetadataEditor key={`metadata-${current.id}`} runId={current.id} onSaved={async () => { const refreshed = await fetchRun(current.id); setDetail(refreshed); onChanged(); }} />
    </section>
    <RunDetailCard title={`구성요소 검사기${loadingComponentView ? "" : ` (${componentResult.total.toLocaleString()})`}`} actions={
      <div className="component-inspector-actions">
        {(componentResult.removedTotal > 0 || showRemovedComponents) && <button type="button" className="secondary compact"
          aria-pressed={showRemovedComponents} onClick={() => {
            setShowRemovedComponents(value => !value);
            setComponentLoadError("");
            setEditingComponentId("");
            setComponentPage(1);
          }}>삭제된 항목 ({componentResult.removedTotal.toLocaleString()})</button>}
        {canCorrectComponent && <button type="button" className="secondary compact"
          aria-expanded={addingComponent} aria-controls={addingComponent ? addComponentFormId : undefined} onClick={() => {
            setAddingComponent(open => !open);
            setEditingComponentId("");
            setComponentMessage("");
          }}>+ 추가</button>}
        <label className="detail-search"><Icon name="search" /><input aria-label="구성요소 검색" value={componentQuery}
          onChange={(event) => { setComponentQuery(event.target.value); setComponentPage(1); }} placeholder="이름, 버전, PURL 검색" /></label>
      </div>
    }>
    {canCorrectComponent && addingComponent && <ComponentAddForm id={addComponentFormId} runId={current.id}
      onCancel={() => setAddingComponent(false)} onSaved={() => {
        setAddingComponent(false);
        setShowRemovedComponents(false);
        setComponentQuery("");
        setComponentPage(1);
        setComponentMessage("구성요소를 추가했습니다.");
        setComponentRefresh(value => value + 1);
      }} />}
    {componentMessage && <p role="status" className="form-message">{componentMessage}</p>}
    {components.length > 0 && componentLoadError && <p role="alert" className="form-message">{componentLoadError}</p>}
    <div className="table-scroll" role="region" aria-label="구성요소 표 가로 스크롤" tabIndex={0}>
      <ResizableTable className="component-inspector-table">
        <thead><tr><th>이름</th><th>버전</th><th>{workbookMetadata ? "구분 · 비고" : "PURL"}</th><th>라이선스</th><th>CPE 식별 후보</th></tr></thead>
        <tbody>
          {components.map(component => <ComponentInspectorRow
            key={component.id ?? component.identityKey}
            runId={current.id}
            component={component}
            identifier={workbookMetadata ? workbookComponentNotes(component) : component.purl || component.bomRef || "-"}
            canEdit={canCorrectComponent}
            editing={canCorrectComponent && Boolean(component.id && editingComponentId === component.id)}
            showCpeCandidates={!previewMode && current.state === "completed" && !component.purl}
            onOpenLibrary={onOpenLibrary}
            onEdit={id => { setComponentMessage(""); setAddingComponent(false); setEditingComponentId(id); }}
            onSaved={(id, saved) => {
              setEditingComponentId(previous => previous === id ? "" : previous);
              if (saved.removed === undefined) {
                setComponentResult(previous => ({
                  ...previous,
                  items: previous.items.map(item => item.id === id ? { ...item, ...saved } : item),
                }));
                setComponentMessage("구성요소 표시 정보를 저장했습니다.");
              } else {
                setComponentResult(previous => ({
                  ...previous, items: previous.items.filter(item => item.id !== id),
                }));
                setComponentMessage(saved.removed ? "구성요소를 검사기에서 삭제했습니다. 삭제된 항목에서 복원할 수 있습니다." : "구성요소를 복원했습니다.");
              }
              setComponentRefresh(value => value + 1);
            }}
          />)}
          {!components.length && <tr><td colSpan={5}>{
            componentLoadError ? <span role="alert">{componentLoadError}</span>
              : loadingComponentView ? "구성요소를 불러오는 중입니다." : deferredComponentQuery ? "검색 조건에 맞는 구성요소가 없습니다."
              : showRemovedComponents ? "삭제된 구성요소가 없습니다." : "구성요소 상세가 없습니다."
          }</td></tr>}
        </tbody>
      </ResizableTable>
    </div>
    {!loadingComponentView && <DetailPagination total={componentResult.total} page={currentComponentPage} pageSize={componentPageSize} onPage={setComponentPage} onPageSize={(size) => { setComponentPageSize(size); setComponentPage(1); }} />}
    </RunDetailCard>
    <RunDetailCard title={`취약점 검사기 (${analysisAvailable(current) ? findingResult.total.toLocaleString() : "미평가"})`}>
    <div className="table-scroll"><ResizableTable className="finding-inspector-table"><thead><tr><th>취약점 ID</th><th>심각도</th><th>구성요소</th><th>CVSS</th><th>KEV</th><th>CWE</th><th>EPSS</th><th>제안 버전</th><th>VEX 검토</th></tr></thead><tbody>{findings.map((finding, index) => { const severity = String(finding.severity || "unknown"); return (<tr key={`${String(finding.canonicalId || finding.id || "finding")}-${(currentFindingPage - 1) * findingPageSize + index}`}><td className="mono">{String(finding.canonicalId || finding.id || "식별자 없음")}{finding.sourceKind === "private_vulnerability" && <small className="workflow-id"><ScrollingText>{["사내 취약점", finding.title, finding.description].filter(Boolean).join(" · ")}</ScrollingText></small>}</td><td><span className={`severity-pill ${severityClass(severity)}`}>{severityLabel(severity)}</span></td><td className="mono"><ScrollingText>{String(finding.componentName || finding.component || "-")}</ScrollingText><OracleHomeEvidence value={finding.oracleHomeEvidence} /></td><td>{cvssScore(finding)}</td><td>{finding.kev ? "KEV" : "-"}</td><td>{Array.isArray(finding.cwes) && finding.cwes.length ? [...new Set(finding.cwes.map(String))].map(value => <ScrollingText key={value}>{`CWE-${value}`}</ScrollingText>) : "확인 안 됨"}</td><td><EpssEvidence finding={finding} stacked /></td><td>{fixedInValues(finding).map((version, versionIndex) => <ScrollingText key={versionIndex}>{version}</ScrollingText>)}</td><td>{finding.vex && typeof finding.vex === "object" ? <span title={String((finding.vex as Record<string, unknown>).detail || "")}>{(finding.vex as Record<string, unknown>).suppressed ? "승인된 영향 없음·오탐 (원시 발견 보존)" : `승인된 ${String((finding.vex as Record<string, unknown>).state || "검토")}`}</span> : "미검토"}</td></tr>);})}{!findings.length && (<tr><td colSpan={9}>{analysisAvailable(current) ? "취약점 결과가 없습니다." : analysisUnavailableReason(current)}</td></tr>)}</tbody></ResizableTable></div><DetailPagination total={findingResult.total} page={currentFindingPage} pageSize={findingPageSize} onPage={setFindingPage} onPageSize={(size) => { setFindingPageSize(size); setFindingPage(1); }} />
    </RunDetailCard>
    {showCompletedRunTools && analysisAvailable(current) && <RunDetailCard title="공통 AI 분석 요약"><TrackerAISummary key={`ai-${current.id}`} runId={current.id} /></RunDetailCard>}
    <NativePolicyResult result={current} runId={current.id} inRunDetail />
    <SbomQualityPanel runId={current.id} analysisId={latestAnalysisId} canRerun={can("analysis.create")} canViewProfiles={can("policies.view") || can("policies.manage")} canManage={can("policies.manage")} archived={current.state === "archived"} />
    {showCompletedRunTools && <>
      <JavaUpgradePanel key={`java-${current.id}`} runId={current.id} serviceId={current.service.id} canManage={can("catalog.manage")} />
      <OfflineUpgradePanel key={`upgrade-${current.id}`} runId={current.id} canManage={can("catalog.manage")} />
    </>}
    <CpeCoverage analysis={latestAnalysis} loading={!detail} collectionCoverage={detail?.collectionCoverage} collectionCoverageState={detail?.collectionCoverageState} />
    <RunDetailCard title="분석 리비전">
    <ul className="paths">{detail?.analyses?.length ? (detail.analyses.map((analysis) => (<li key={analysis.id}>r{analysis.sequence} · {jobStateLabel(analysis.state)} ·{" "}
                {dataBaselineLabel(preferredCveDate(analysis.cveDataAsOf, analysis.dataAsOf), "CVE 기준일 확인 필요")} · 취약 구성요소 {analysisAvailable(analysis) && analysis.vulnerableComponentCount != null ? `${analysis.vulnerableComponentCount.toLocaleString()}개` : "미평가"}{analysis.error ? ` · ${analysis.error}` : ""} · 정책 {analysis.policyVersion ? `v${analysis.policyVersion}` : "-"} · {analysis.policyState === "completed" ? "평가 완료" : analysis.policyState === "failed" ? "평가 실패" : "미평가"}{analysis.policyError ? ` · ${analysis.policyError}` : ""}<AnalysisPolicyHistory analysis={analysis} runId={current.id} /></li>) )
          ): (<li>상세를 불러오는 중이거나 분석 리비전이 없습니다.</li>)}</ul>
    </RunDetailCard>
    {(can("metadata.view") || can("metadata.manage")) && <PackageMetadataPanel runId={current.id} canManage={can("metadata.manage")} />}
    {can("metadata.view") && <OfflineRunEvidence key={`offline-${current.id}`} runId={current.id} canRespond={can("vex.manage")} canViewResponses={can("vex.view")} />}
    {(can("ssvc.view") || can("ssvc.manage")) && <SsvcAssessmentsPanel key={`ssvc-${current.id}`} runId={current.id} findings={findings} canManage={can("ssvc.manage")} />}
    {(can("vex.view") || can("vex.manage") || can("vex.approve")) && <VexReviewsPanel key={`vex-${current.id}`} runId={current.id} findings={findings} username={username} canManage={can("vex.manage")} canApprove={can("vex.approve")} />}
    <div className="drawer-actions">{message && (<p className="form-message" role="status">{message}</p>)}{standaloneMode ? (<p className="preview-note">미리보기 모드에서는 원본 파일을 저장하거나
              Grype 분석·KODA 정책 평가를 실행하지 않습니다.
            </p> ): (<><div className="drawer-action-row">
                {can("analysis.create") && (<button className="secondary" disabled={busy || current.state === "archived"} onClick={() => void runAction(() => createAnalysis(current.id), "새 분석 리비전을 접수했습니다.")}>새 분석 리비전
                  </button>)}
              </div><div className="drawer-action-row">{can("artifact.download") && (<a className="secondary" href={`/api/v1/sbom-runs/${current.id}/artifact`}>원본 SBOM 내려받기
                  </a>)}
                </div>{can("sbom.archive") && current.state !== "archived" && (<form className="archive-form" onSubmit={(event) => { event.preventDefault(); if (archiveReason.trim()) void runAction(() => archiveRun(current.id, archiveReason.trim()), "회차를 논리 보관했습니다.");}}><input aria-label="보관 사유" placeholder="보관 사유" value={archiveReason} onChange={(event) => setArchiveReason(event.target.value)} /><button className="secondary" disabled={busy || !archiveReason.trim()}>논리 보관
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
    <div className="settings-grid catalog-grid"><div className="table-frame"><h2 className="table-title">서비스 {activeServices.length}개</h2><div className="table-scroll" role="region" aria-label="서비스 목록 가로 스크롤" tabIndex={0}><ResizableTable className="service-catalog-flow-table"><thead><tr><th>서비스</th><th>식별자</th><th>작업</th></tr></thead><tbody>{activeServices.length ? (visibleServices.map((item) => (<tr key={item.id}><td><ScrollingText>{item.name}</ScrollingText></td><td className="mono"><ScrollingText>{item.slug}</ScrollingText></td><td><button type="button" className="secondary compact" title={item.id} onClick={() => void copyOrShow("서비스 연동 ID", item.id)}>연동 ID 복사</button>{canManage && (
                        <>
                          {" "}
                          <button className="secondary compact" disabled={busy} onClick={() => void editService(item)}>이름 변경
                          </button> {" "}<button className="danger compact" disabled={busy} onClick={() => void removeService(item)}>삭제</button></>
                      )}
    </td></tr>) )
              ): (<tr><td colSpan={3}>등록된 서비스가 없습니다.</td></tr>)}</tbody></ResizableTable></div><DetailPagination total={activeServices.length} page={currentServicePage} pageSize={catalogPageSize} label="서비스 페이지당 행 수" onPage={setServicePage} onPageSize={(size) => { setCatalogPageSize(size); setServicePage(1); setEnvironmentPage(1); }} /></div><div className="table-frame"><h2 className="table-title">환경 {activeEnvironments.length}개</h2><div className="table-scroll" role="region" aria-label="환경 목록 가로 스크롤" tabIndex={0}><ResizableTable className="environment-catalog-flow-table"><thead><tr><th>환경</th><th>식별자</th><th>정렬</th><th>작업</th></tr></thead><tbody>{activeEnvironments.length ? (visibleEnvironments.map((item) => (<tr key={item.id}><td><ScrollingText>{item.name}</ScrollingText></td><td className="mono"><ScrollingText>{item.slug}</ScrollingText></td><td>{item.sortOrder ?? "-"}</td><td><button type="button" className="secondary compact" title={item.id} onClick={() => void copyOrShow("환경 연동 ID", item.id)}>연동 ID 복사</button>{canManage && (<>{" "}<button className="secondary compact" disabled={busy} onClick={() => setEditingEnvironment(item)}>변경
                        </button> <button className="danger compact" disabled={busy} onClick={() => void removeEnvironment(item)}>삭제</button></>)}</td></tr>) )
              ): (<tr><td colSpan={4}>등록된 환경이 없습니다.</td></tr>)}</tbody></ResizableTable></div><DetailPagination total={activeEnvironments.length} page={currentEnvironmentPage} pageSize={catalogPageSize} label="환경 페이지당 행 수" onPage={setEnvironmentPage} onPageSize={(size) => { setCatalogPageSize(size); setServicePage(1); setEnvironmentPage(1); }} /></div></div>
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

function VulnerabilityPage({ bundles, onSync, onBaselineRefresh, canManage, embedded = false }: { bundles: VulnerabilityBundle[]; onSync: () => Promise<void>; onBaselineRefresh?: () => Promise<void>; onActivate: (version: string) => Promise<void>; canManage: boolean; embedded?: boolean; }) {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const currentPage = Math.min(page, Math.max(1, Math.ceil(bundles.length / pageSize)));
  const visibleBundles = bundles.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  return <section className={embedded ? "settings-panel generic-page" : "page generic-page"}>
    {!embedded && <div className="page-heading"><h1>취약점 데이터</h1></div>}
    <UnifiedVulnerabilityDataPanel canManage={canManage} onChanged={onSync} onBaselineRefresh={onBaselineRefresh} />
    <details><summary>과거 반입 기록 ({bundles.length}개)</summary><p>과거 기록은 현재 파일의 존재·활성 상태를 보증하지 않습니다. 위 통합 자료 상태를 기준으로 확인하세요.</p>
      <div className="table-scroll"><ResizableTable><thead><tr><th>기록된 번들</th><th>Grype 기준일</th><th>NVD 기준일</th><th>KEV 기준일</th><th>반입 시각</th></tr></thead><tbody>
        {visibleBundles.map(item => <tr key={item.id}><td>{item.version}</td><td>{item.dataAsOf || "미확인"}</td><td>{item.nvdDataAsOf || "미확인"}</td><td>{item.kevDataAsOf || "미확인"}</td><td>{formatSeoulDateTime(item.importedAt)}</td></tr>)}
        {!bundles.length && <tr><td colSpan={5}>과거 반입 기록이 없습니다.</td></tr>}
      </tbody></ResizableTable></div>
      <DetailPagination total={bundles.length} page={currentPage} pageSize={pageSize} label="취약점 번들 페이지당 행 수" onPage={setPage} onPageSize={size => {setPageSize(size); setPage(1);}} />
    </details>
  </section>;
}

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
  return (<section className={embedded ? "settings-panel generic-page" : "page generic-page"}><div className="page-heading"><div><h1>감사 로그</h1><p>가입·LDAP·업로드·분석·관리 작업을 불변 이력으로 조회합니다.</p></div><a className="secondary" href={previewMode ? "#" : exportHref} download={previewMode ? undefined : "koda-audit-events.csv"} onClick={(event) => previewMode && event.preventDefault()}>Excel 다운로드</a></div><div className="generic-toolbar"><label className="global-search"><Icon name="search" /><input aria-label="감사 로그 검색" value={query} onChange={(event) => { setQuery(event.target.value); setPage(1); }} placeholder="행위자, 작업, 대상, 상세 검색" /></label><span>{result.total}건</span></div><div className="table-frame"><div className="table-scroll"><ResizableTable><thead><tr><th>시각</th><th>행위자</th><th>작업</th><th>대상</th><th>상세</th></tr></thead><tbody>{result.items.length ? (result.items.map((item) => (<tr key={item.id}><td>{formatSeoulDateTime(item.createdAt)}</td><td>{item.actor}</td><td className="mono">{item.action}</td><td>{item.targetType}:{item.targetId}</td><td className="mono">{auditDetailLabel(item.detail)}</td></tr>) )
              ): (<tr><td colSpan={5}>감사 로그가 없습니다.</td></tr>)}</tbody></ResizableTable></div><DetailPagination total={result.total} page={Math.min(page, Math.max(1, Math.ceil(result.total / pageSize)))} pageSize={pageSize} onPage={setPage} onPageSize={(size) => { setPageSize(size); setPage(1); }} /></div></section>);}

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

export function SettingsPage({ users, services, environments = [], tokens, ldapSettings, policies, roleCatalog, bundles, auditEvents, isAdmin, canVulnerability, canVulnerabilityManage, canAudit, canUsers, canTokens, canPolicyEdit, canRoles, canSbomPolicies = false, canSbomPolicyManage = false, canReanalysis = false, canReanalysisManage = false, canNotifications = false, canNotificationManage = false, canMetadata = false, canMetadataManage = false, canProjects = false, canServices = false, canCatalogManage = false, canProjectRuns = false, onOpenRun, initialTab, onSync, onBaselineRefresh, onActivate, onPolicyChanged, onLdapChanged, onChanged }: {
  users: UserSummary[];
  services: CatalogItem[];
  environments?: CatalogItem[];
  tokens: ApiTokenSummary[];
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
  canPolicyEdit: boolean;
  canRoles: boolean;
  canSbomPolicies?: boolean;
  canSbomPolicyManage?: boolean;
  canReanalysis?: boolean; canReanalysisManage?: boolean; canNotifications?: boolean; canNotificationManage?: boolean;
  canMetadata?: boolean; canMetadataManage?: boolean; canProjects?: boolean;
  canServices?: boolean;
  canCatalogManage?: boolean;
  canProjectRuns?: boolean;
  onOpenRun?: (run: SbomRun) => void;
  initialTab?: SettingsTab;
  onSync: () => Promise<void>;
  onBaselineRefresh?: () => Promise<void>;
  onActivate: (version: string) => Promise<void>;
  onPolicyChanged: (policies: RolePolicy[]) => Promise<void>;
  onLdapChanged: (settings: LdapSettings) => void;
  onChanged: () => void;
}) {
  const [mode, setMode] = useState<"user" | "token" | null>(null);
  const [activeTab, setActiveTab] = useState<SettingsTab>(initialTab === "private-vulnerabilities" || initialTab === "metadata" || initialTab === "cve-search" ? "vulnerability" : initialTab || "users");
  const [vulnerabilityDataTab, setVulnerabilityDataTab] = useState<"external" | "private" | "metadata" | "cve">(initialTab === "private-vulnerabilities" ? "private" : initialTab === "metadata" ? "metadata" : initialTab === "cve-search" ? "cve" : "external");
  const canExternalData = isAdmin && canVulnerability;
  const canPrivateData = isAdmin && (canMetadata || canMetadataManage);
  const canMetadataData = canMetadata || canMetadataManage;
  const canCveData = canVulnerability || canMetadata;
  const canSelectedVulnerabilityData = vulnerabilityDataTab === "cve" ? canCveData : vulnerabilityDataTab === "external" ? canExternalData : vulnerabilityDataTab === "private" ? canPrivateData : canMetadataData;
  const activeVulnerabilityDataTab = canSelectedVulnerabilityData ? vulnerabilityDataTab : canExternalData ? "external" : canPrivateData ? "private" : canMetadataData ? "metadata" : "cve";
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
    if (canUsers || canTokens) tabs.push({ id: "users", label: "사용자 관리", icon: "user" });
    if (canRoles || canPolicyEdit) tabs.push({ id: "roles", label: "권한 관리", icon: "settings" });
    if (canProjects) tabs.push({ id: "projects", label: "프로젝트 관리", icon: "integration" });
    if (canServices) tabs.push({ id: "services", label: "서비스·환경", icon: "service" });
    if (isAdmin) tabs.push({ id: "environment-admins", label: "환경별 관리자", icon: "user" });
    if (canSbomPolicies || canSbomPolicyManage) tabs.push({ id: "sbom-policies", label: "SBOM 정책", icon: "settings" });
    if (canReanalysis || canReanalysisManage) tabs.push({ id: "reanalysis", label: "재분석 일정", icon: "settings" });
    if (canNotifications || canNotificationManage) tabs.push({ id: "notifications", label: "알림함", icon: "audit" });
    if (canExternalData || canPrivateData || canMetadataData || canCveData) tabs.push({ id: "vulnerability", label: "취약점 데이터", icon: "vulnerability" });
    if (!previewMode && (canMetadata || canMetadataManage)) tabs.push({ id: "compatibility-data", label: "공식 호환성 자료", icon: "integration" });
    if (canServices && canTokens) tabs.push({ id: "integration", label: "연동 설정", icon: "integration" });
    if (isAdmin && !previewMode) tabs.push({ id: "shared-ai", label: "공통 AI", icon: "integration" });
    if (isAdmin) tabs.push({ id: "ldap", label: "LDAP 로그인", icon: "lock" });
    if (isAdmin && canAudit) tabs.push({ id: "audit", label: "감사 로그", icon: "audit" });
    return tabs;
  }, [canExternalData, canPrivateData, canMetadata, canMetadataManage, canMetadataData, canCveData, canProjects, canReanalysis, canReanalysisManage, canNotifications, canNotificationManage, canSbomPolicies, canSbomPolicyManage, canAudit, canPolicyEdit, canRoles, canServices, canTokens, canUsers, isAdmin]);
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
    {activeTab === "projects" && canProjects && <><ProjectCatalogPanel canManage={isAdmin} canViewRuns={canProjectRuns} onOpenRun={onOpenRun} services={services} environments={environments}/></>}

    {issuedToken && activeTab === "users" && (<div className="token-reveal"><strong>{issuedToken.name}</strong><code>{issuedToken.token}</code><span>서비스 ID <code>{issuedToken.serviceId}</code></span><button type="button" className="secondary compact" onClick={() => void copyOrShow("KODA 서비스 토큰", issuedToken.token)}>토큰 복사</button><button type="button" className="secondary compact" onClick={() => void copyOrShow("서비스 연동 ID", issuedToken.serviceId)}>서비스 ID 복사</button></div>)}
    {activeTab === "users" && canUsers && (<p className="form-message">가입 신청 계정은 승인 대기로 구분됩니다. 역할을 확인한 뒤 승인하세요.</p>)}
    {activeTab === "compatibility-data" && !previewMode && (canMetadata || canMetadataManage) && <div id="settings-panel-compatibility-data" role="tabpanel" aria-labelledby="settings-tab-compatibility-data"><OfficialCompatibilityData canManage={canMetadataManage} /></div>}
    {activeTab === "integration" && (canServices && canTokens) && (<div className="settings-panel integration-settings-panel" id="settings-panel-integration" role="tabpanel" aria-labelledby="settings-tab-integration">
      {!previewMode && <ExternalReadTokens services={services} environments={environments} />}
      {canServices && canTokens && (<>
        <div className="table-frame integration-status"><div className="settings-panel-heading"><div><h2 className="table-title">KODA GitLab 자동 연동</h2><p>GitLab 연결과 저장소 선택은 KODA에서만 설정합니다. Tracker는 KODA 요청을 받아 저장소별 서비스·환경·전송 토큰을 자동 생성하거나 재사용합니다.</p></div><span className={`user-status ${gitlabServices.length ? "active" : "inactive"}`}>{gitlabServices.length ? "저장소 연결됨" : "연결 대기"}</span></div><div className="integration-status-body"><p>GitLab 저장소 → KODA 점검·CycloneDX 생성 → Tracker 회차 수신·분석 → KODA가 GitLab 결과 MR·취약점 이슈 저장</p><p>{gitlabEnvironment ? "gitlab-source 환경이 자동 준비되었습니다." : "첫 저장소 연결 시 gitlab-source 환경이 자동 준비됩니다."}</p><div className="button-row"><button type="button" className="secondary" onClick={() => setActiveTab("services")}>자동 생성 항목 보기</button></div></div></div>
        <div className="table-frame"><h2 className="table-title">자동 생성된 저장소 서비스</h2><div className="table-scroll" role="region" aria-label="저장소 서비스 목록 가로 스크롤" tabIndex={0}><ResizableTable className="gitlab-service-flow-table"><thead><tr><th>GitLab 저장소</th><th>Tracker 식별자</th><th>전송 토큰</th></tr></thead><tbody>{gitlabServices.length ? visibleGitlabServices.map((item) => { const tokenCount = tokens.filter((token) => token.active && token.serviceId === item.id).length; return (<tr key={item.id}><td><ScrollingText>{item.name}</ScrollingText></td><td className="mono"><ScrollingText>{item.slug}</ScrollingText></td><td>{tokenCount ? "활성" : "확인 필요"}</td></tr>);}) : (<tr><td colSpan={3}>KODA에서 연결한 GitLab 저장소가 없습니다.</td></tr>)}</tbody></ResizableTable></div><DetailPagination total={gitlabServices.length} page={currentGitlabServicePage} pageSize={gitlabPageSize} label="GitLab 서비스 페이지당 행 수" onPage={setGitlabServicePage} onPageSize={(size) => { setGitlabPageSize(size); setGitlabServicePage(1); }} /></div>
      </>)}
    </div>)}
    {activeTab === "shared-ai" && isAdmin && !previewMode && <div id="settings-panel-shared-ai" role="tabpanel" aria-labelledby="settings-tab-shared-ai"><SharedAISettingsPanel /></div>}
    {activeTab === "reanalysis" && (canReanalysis || canReanalysisManage) && <ReanalysisSchedulePanel canManage={canReanalysisManage} services={services} environments={environments} />}
    {activeTab === "notifications" && (canNotifications || canNotificationManage) && <NotificationsPanel canManage={canNotificationManage} />}
    {activeTab === "sbom-policies" && (canSbomPolicies || canSbomPolicyManage) && <SbomPoliciesPanel canManage={canSbomPolicyManage} services={services} environments={environments} />}
    {activeTab === "services" && canServices && (<div id="settings-panel-services" role="tabpanel" aria-labelledby="settings-tab-services"><ServicesPage services={services} environments={environments} canManage={canCatalogManage} onChanged={onChanged} /></div>)}
    {activeTab === "environment-admins" && isAdmin && <div id="settings-panel-environment-admins" role="tabpanel" aria-labelledby="settings-tab-environment-admins"><EnvironmentAdministrators /></div>}
    {activeTab === "ldap" && isAdmin && (<LdapSettingsPanel settings={ldapSettings} onChanged={onLdapChanged} />)}
    {activeTab === "users" && (canUsers || canTokens) && (<div className="settings-panel" id="settings-panel-users" role="tabpanel" aria-labelledby="settings-tab-users"><div className="settings-grid">{canUsers && (<div className="table-frame"><h2 className="table-title">사용자 {users.length}명</h2><div className="table-scroll" role="region" aria-label="사용자 목록 가로 스크롤" tabIndex={0}><ResizableTable className="settings-users-flow-table"><thead><tr><th>사용자</th><th>역할</th><th>상태</th><th>작업</th></tr></thead><tbody>{users.length ? visibleUsers.map((item) => (<tr key={item.id || item.username} className={item.status === "pending" ? "pending-user" : ""}><td><ScrollingText>{item.username}</ScrollingText></td><td><select aria-label={`${item.username} 역할`} value={item.role} disabled={busy || item.status === "deleted"} onChange={(event) => void updateUser(item, "role", event.target.value)}>{canRoles && (<><option value="admin">관리자</option><option value="manager">매니저</option></>)}<option value="analyst">분석자</option><option value="uploader">업로더</option><option value="viewer">조회자</option></select></td><td><span className={`user-status ${item.status || (item.active ? "active" : "inactive")}`}>{userStatusLabel(item)}</span></td><td>{item.id && (item.status === "pending" ? (<button type="button" className="primary compact" disabled={busy} onClick={() => void approve(item)}>승인</button>) : item.status === "deleted" ? (<span>삭제됨</span>) : (<><button type="button" className="secondary compact" disabled={busy} onClick={() => void updateUser(item, "active", !item.active)}>{item.active ? "비활성화" : "활성화"}</button>{<button type="button" className="danger compact" disabled={busy} onClick={() => void removeUser(item)}>삭제</button>}</>))}</td></tr>)) : (<tr><td colSpan={4}>등록된 사용자가 없습니다.</td></tr>)}</tbody></ResizableTable></div><DetailPagination total={users.length} page={currentUserPage} pageSize={accountPageSize} label="사용자 페이지당 행 수" onPage={setUserPage} onPageSize={(size) => { setAccountPageSize(size); setUserPage(1); setTokenPage(1); }} /></div>)}{canTokens && (<div className="table-frame"><h2 className="table-title">API 토큰 {tokens.length}개</h2><div className="table-scroll" role="region" aria-label="API 토큰 목록 가로 스크롤" tabIndex={0}><ResizableTable className="settings-tokens-flow-table"><thead><tr><th>이름</th><th>서비스</th><th>생성 시각</th><th>상태</th><th /></tr></thead><tbody>{tokens.length ? visibleTokens.map((item) => (<tr key={item.id}><td><ScrollingText>{item.name}</ScrollingText></td><td><ScrollingText>{services.find((service) => service.id === item.serviceId)?.name || item.serviceId || "-"}</ScrollingText></td><td>{formatSeoulDateTime(item.createdAt)}</td><td>{item.active ? "활성" : "폐기"}</td><td>{item.active && (<button type="button" className="secondary compact" onClick={() => void revoke(item.id)} disabled={busy}>폐기</button>)}</td></tr>)) : (<tr><td colSpan={5}>발급된 토큰이 없습니다.</td></tr>)}</tbody></ResizableTable></div><DetailPagination total={tokens.length} page={currentTokenPage} pageSize={accountPageSize} label="토큰 페이지당 행 수" onPage={setTokenPage} onPageSize={(size) => { setAccountPageSize(size); setUserPage(1); setTokenPage(1); }} /></div>)}</div></div>)}
    {activeTab === "roles" && canPolicyEdit && policies.length > 0 && (<div className="settings-panel" id="settings-panel-roles" role="tabpanel" aria-labelledby="settings-tab-roles"><div className="table-frame"><h2 className="table-title">권한 정책</h2>{POLICY_SECTIONS.map((section) => (<section className="role-policy-section" key={section.label}><div className="role-policy-section-heading"><h3>{section.label}</h3><p>{section.description}</p></div><div className="role-policy-grid">{roles.map((role) => (<fieldset key={role} aria-label={`${roleLabel(role)} ${section.label}`}><legend>{roleLabel(role)}</legend>{section.groups.map((group) => { const entries = group.permissions.filter((permission) => permissionNames.includes(permission)); return entries.length ? (<div className="permission-group" key={group.label}>{section.label === "기능 제어" && <h4>{group.label}</h4>}{entries.map((permission) => (<label key={permission}><input type="checkbox" checked={policyDraft[role]?.has(permission) || false} disabled={!canPolicyEdit || busy || (permission === "sbom.delete" && role !== "admin")} onChange={() => setPolicyDraft((current) => { const next = new Set(current[role] || []); if (next.has(permission)) next.delete(permission); else next.add(permission); return { ...current, [role]: next }; })} />{section.label === "화면 접근 권한" ? permissionLabel(permission).replace(/ 조회$/, "") : permissionLabel(permission)}</label>))}</div>) : null; })}</fieldset>))}</div></section>))}{canPolicyEdit && (<div className="role-policy-actions"><button type="button" className="primary" onClick={async () => { setBusy(true); setMessage(""); try { const changed = roles.filter((role) => { const before = policies.find((item) => item.role === role)?.permissions || []; const after = [...(policyDraft[role] || [])]; return before.length !== after.length || before.some((item) => !policyDraft[role]?.has(item)); }); if (!changed.length) { setMessage("변경된 역할 정책이 없습니다."); return; } const updated = await updateRolePolicies(changed.map((role) => ({ role, permissions: [...(policyDraft[role] || [])] }))); const next = policies.map((item) => updated.find((changedPolicy) => changedPolicy.role === item.role) || item); await onPolicyChanged(next); setMessage("역할 정책을 저장했습니다."); } catch (error) { setMessage(error instanceof Error ? error.message : "역할 정책 저장에 실패했습니다."); } finally { setBusy(false); } }}>권한 정책 저장</button></div>)}</div></div>)}
    {activeTab === "vulnerability" && (canExternalData || canPrivateData || canMetadataData || canCveData) && (<div id="settings-panel-vulnerability" role="tabpanel" aria-labelledby="settings-tab-vulnerability">
      <div className="page-heading vulnerability-data-heading"><h1>취약점 데이터</h1>
        <div className="settings-tabs vulnerability-data-tabs" role="tablist" aria-label="취약점 데이터 종류">
          {canCveData && <button type="button" role="tab" id="vulnerability-data-tab-cve" aria-controls="vulnerability-data-panel-cve" aria-selected={activeVulnerabilityDataTab === "cve"} className={activeVulnerabilityDataTab === "cve" ? "active" : ""} onClick={() => setVulnerabilityDataTab("cve")}>CVE 검색</button>}
          {canExternalData && <button type="button" role="tab" id="vulnerability-data-tab-external" aria-controls="vulnerability-data-panel-external" aria-selected={activeVulnerabilityDataTab === "external"} className={activeVulnerabilityDataTab === "external" ? "active" : ""} onClick={() => setVulnerabilityDataTab("external")}>공개 참조 자료</button>}
          {canPrivateData && <button type="button" role="tab" id="vulnerability-data-tab-private" aria-controls="vulnerability-data-panel-private" aria-selected={activeVulnerabilityDataTab === "private"} className={activeVulnerabilityDataTab === "private" ? "active" : ""} onClick={() => setVulnerabilityDataTab("private")}>자체 등록 취약점</button>}
          {canMetadataData && <button type="button" role="tab" id="vulnerability-data-tab-metadata" aria-controls="vulnerability-data-panel-metadata" aria-selected={activeVulnerabilityDataTab === "metadata"} className={activeVulnerabilityDataTab === "metadata" ? "active" : ""} onClick={() => setVulnerabilityDataTab("metadata")}>자료 현황·영향</button>}
        </div>
      </div>
      {activeVulnerabilityDataTab === "cve" && canCveData && <div id="vulnerability-data-panel-cve" role="tabpanel" aria-labelledby="vulnerability-data-tab-cve"><CveSearchPanel onOpenRun={canProjectRuns ? runId => { void fetchRun(runId).then(run => onOpenRun?.(run)).catch(cause => setMessage(cause instanceof Error ? cause.message : "연결된 회차를 열지 못했습니다.")); } : undefined} /></div>}
      {activeVulnerabilityDataTab === "external" && canExternalData && <div id="vulnerability-data-panel-external" role="tabpanel" aria-labelledby="vulnerability-data-tab-external"><VulnerabilityPage embedded bundles={bundles} canManage={canVulnerabilityManage} onSync={onSync} onBaselineRefresh={onBaselineRefresh} onActivate={onActivate} /></div>}
      {activeVulnerabilityDataTab === "private" && canPrivateData && <div id="vulnerability-data-panel-private" role="tabpanel" aria-labelledby="vulnerability-data-tab-private"><PrivateVulnerabilitiesPanel canManage={canMetadataManage}/></div>}
      {activeVulnerabilityDataTab === "metadata" && canMetadataData && <div id="vulnerability-data-panel-metadata" role="tabpanel" aria-labelledby="vulnerability-data-tab-metadata">
        <OfflineIntelligencePanel />
        <details className="package-metadata-advanced"><summary>패키지 버전·출시일 관측 현황 (고급)</summary><PackageMetadataPanel canManage={canMetadataManage} /></details>
      </div>}
    </div>)}
    {activeTab === "audit" && isAdmin && canAudit && (<div id="settings-panel-audit" role="tabpanel" aria-labelledby="settings-tab-audit"><AuditPage embedded events={auditEvents} /></div>)}
    {!settingsTabs.length && (<div className="empty-state"><Icon name="settings" /><h2>관리 가능한 설정이 없습니다.</h2><p>현재 계정에 허용된 설정 권한이 없습니다.</p></div>)}
    {mode && (<div className="modal-backdrop" role="presentation"><section className="modal" role="dialog" aria-modal="true" aria-labelledby="settings-modal-title"><header><h2 id="settings-modal-title">{mode === "user" ? "사용자 추가" : "API 토큰 발급"}</h2><button type="button" className="icon-button" aria-label="설정 창 닫기" onClick={() => setMode(null)}><Icon name="close" /></button></header><form onSubmit={submit}>{mode === "user" ? (<><label>사용자 이름<input name="username" required autoFocus /></label><label>임시 비밀번호<input name="password" type="password" minLength={12} required /></label><label>역할<select name="role" defaultValue="viewer">{canRoles && (<><option value="admin">관리자</option><option value="manager">매니저</option></>)}<option value="analyst">분석자</option><option value="uploader">업로더</option><option value="viewer">조회자</option></select></label></>) : (<><label>토큰 이름<input name="name" required autoFocus /></label><label>허용 서비스<FlowSelect name="serviceId" required><option value="" disabled>서비스를 선택하세요</option>{services.map((item) => (<option key={item.id} value={item.id}>{item.name}</option>))}</FlowSelect></label><small>서비스 범위 토큰입니다. 토큰 원문은 지금만 표시되며 서버에는 해시만 저장됩니다.</small></>)}{message && <p className="form-message">{message}</p>}<footer><button type="button" className="secondary" onClick={() => setMode(null)}>닫기</button><button className="primary" disabled={busy}>{busy ? "처리 중…" : "확인"}</button></footer></form></section></div>)}
  </section>);
}

function GuidePage() {
  return (<section className="page guide-page">
    <p className="preview-eyebrow">KODA SBOM TRACKER</p>
    <h1>사용 가이드</h1>
    <p className="guide-lead"><span>SBOM을 회차별로 관리하고 구성요소, CVE 취약점, 정책 결과의 변화를 추적하는 방법을 안내합니다.</span><span>표시되는 메뉴와 작업 버튼은 역할별 권한에 따라 달라질 수 있습니다.</span></p>
    <section className="guide-section" aria-labelledby="guide-flow-title">
      <h2 id="guide-flow-title">기본 사용 순서</h2>
      <ol className="guide-flow">
        <li><strong>서비스·환경 준비</strong><span>설정에서 SBOM을 구분할 서비스와 운영 환경을 확인합니다.</span></li>
        <li><strong>SBOM 업로드</strong><span>서비스, 환경, 릴리스를 선택하고 CycloneDX 1.4~1.7 JSON/XML, SPDX 2.3 JSON, NIS-SBOM 1.0 CSV 또는 구성요소 목록 Excel(.xlsx)을 등록합니다. ZIP, TAR.GZ/TGZ, TAR, 7Z 압축파일에는 지원 JSON/XML/CSV 문서가 정확히 1개 있어야 합니다.</span></li>
        <li><strong>분석 결과 확인</strong><span>회차 상세에서 분석 상태와 자료 기준일을 확인합니다. 취약점의 CVSS, KEV, EPSS와 제안 버전을 살펴보고, 필요하면 VEX 검토와 SSVC 평가를 진행합니다.</span></li>
        <li><strong>변경 추적</strong><span>회차 비교에서 구성요소·취약점·정책 결과의 변화를 확인합니다. 같은 SBOM이라도 분석에 사용한 취약점 자료 기준일이 다르면 결과가 달라질 수 있습니다.</span></li>
      </ol>
    </section>
    <section className="guide-section" aria-labelledby="guide-features-title">
      <h2 id="guide-features-title">주요 기능</h2>
      <div className="guide-card-grid">
        <article><h3>대시보드</h3><p>등록된 SBOM을 기준으로 구성요소 수, 취약 구성요소 추이, 심각도와 KEV 현황을 확인합니다. 실제 서버에 배포된 버전은 배포 기록과 함께 확인합니다.</p></article>
        <article><h3>SBOM 회차</h3><p>서비스·환경·릴리스별 원본과 분석 이력을 확인합니다. 분석 대기나 실패가 표시되면 회차 상세에서 상태와 원인을 확인합니다.</p></article>
        <article><h3>취약점 분석</h3><p>취약점에 해당하는 구성요소와 버전을 확인하고, 자료가 있으면 CVSS·KEV·EPSS·CWE와 수정 버전 후보를 검토합니다.</p></article>
        <article><h3>회차 비교</h3><p>두 회차 사이의 구성요소, CVE 취약점과 정책 결과 차이를 비교합니다.</p></article>
        <article><h3>운영 설정</h3><p>서비스·환경, 사용자 승인, 역할별 권한, 취약점 데이터, 감사 로그와 외부 연동을 관리합니다.</p></article>
        <article><h3>감사와 이력</h3><p>업로드, 분석, 로그인, 관리 작업을 감사 로그로 확인하고 권한이 있는 관리자는 Excel 호환 CSV로 내려받을 수 있습니다.</p></article>
      </div>
    </section>
    <section className="guide-section" aria-labelledby="guide-terms-title">
      <h2 id="guide-terms-title">용어 설명</h2>
      <dl className="guide-glossary">
        <div><dt>SBOM (Software Bill of Materials)</dt><dd>특정 산출물을 구성하는 라이브러리·패키지와 버전 등을 기록한 명세입니다. 의존성 관계가 기록되어 있으면 구성요소가 포함된 경로도 확인할 수 있습니다.</dd></div>
        <div><dt>CycloneDX</dt><dd>구성요소와 의존성 관계 등을 담을 수 있는 SBOM 표준입니다. Tracker는 1.4·1.5·1.6·1.7의 JSON과 XML 업로드를 지원합니다.</dd></div>
        <div><dt>SPDX</dt><dd>소프트웨어 구성요소와 라이선스 정보 등을 교환하는 표준입니다. Tracker는 2.3 JSON 원본을 보존하고 분석용 공통 형식으로 변환합니다.</dd></div>
        <div><dt>구성요소</dt><dd>SBOM에 기록된 라이브러리, 프레임워크, 애플리케이션 등의 개별 항목입니다. 이름이 같은 항목은 생태계, PURL, 버전도 함께 비교합니다.</dd></div>
        <div><dt>PURL (Package URL)</dt><dd>생태계, 패키지 이름, 버전 등으로 소프트웨어 패키지를 식별하는 표준입니다. 예를 들어 <code>pkg:maven/com.example/library@1.2.3</code>은 Maven 패키지와 버전을 가리킵니다.</dd></div>
        <div><dt>CPE (Common Platform Enumeration)</dt><dd>공급사·제품·버전 등의 속성으로 애플리케이션, 운영체제, 하드웨어를 식별하는 표준입니다. NVD의 제품 및 버전 조건을 대조할 때 사용하며, 실제 영향은 해당 조건과 구성요소 정보를 함께 확인합니다.</dd></div>
        <div><dt>직접·전이 의존성</dt><dd>프로젝트가 직접 추가한 패키지를 직접 의존성, 다른 패키지를 통해 함께 포함된 패키지를 전이 의존성이라고 합니다. 프로젝트 → A → B에서 A는 직접, B는 전이 의존성입니다. SBOM에 의존성 관계가 없으면 경로를 확인하기 어렵습니다.</dd></div>
        <div><dt>회차</dt><dd>서비스·환경·릴리스에 등록한 SBOM 한 건입니다. 같은 원본을 재분석하면 회차에 분석 이력이 추가되므로 결과를 비교할 때 분석 시점과 자료 기준일도 확인합니다.</dd></div>
        <div><dt>CVE (Common Vulnerabilities and Exposures)</dt><dd>개별 보안 취약점을 참조하는 공개 식별자입니다. 내 환경의 영향 여부는 CVE에 해당하는 패키지·버전과 적용 조건을 확인해 판단합니다.</dd></div>
        <div><dt>CWE (Common Weakness Enumeration)</dt><dd>취약점의 원인이 될 수 있는 설계·구현상 약점 유형을 분류합니다. 여러 CVE가 같은 CWE에 연결될 수 있어 반복되는 원인을 파악하는 데 도움이 됩니다.</dd></div>
        <div><dt>NVD (National Vulnerability Database)</dt><dd>CVE에 대한 설명, CVSS, 영향 제품과 버전 조건 등을 제공하는 미국 국가 취약점 데이터베이스입니다. 폐쇄망에서는 반입한 자료의 기준일과 제공 범위를 함께 확인합니다.</dd></div>
        <div><dt>CVSS (Common Vulnerability Scoring System)</dt><dd>취약점의 기술적 심각도를 0~10점으로 표현하는 표준입니다. 대응 순서는 KEV·EPSS와 실제 서비스 노출 및 업무 영향도 함께 보고 정합니다.</dd></div>
        <div><dt>EPSS (Exploit Prediction Scoring System)</dt><dd>공개 CVE의 실제 악용 활동이 점수 기준일로부터 30일 안에 관측될 확률을 추정합니다. 백분위는 다른 CVE와 비교한 순위입니다. 폐쇄망에서는 점수 기준일을 확인하세요. 미수집이면 활용할 점수가 없습니다.</dd></div>
        <div><dt>KEV (Known Exploited Vulnerabilities)</dt><dd>미국 사이버보안·인프라보안국(CISA)이 실제 악용을 확인한 취약점 목록입니다. 등재된 항목은 우선 검토하고, 미등재 항목은 다른 악용 근거와 환경 정보를 함께 확인합니다.</dd></div>
        <div><dt>VEX (Vulnerability Exploitability eXchange)</dt><dd>특정 제품·버전에 취약점이 영향을 주는지와 그 근거를 기록하는 방식입니다. Tracker에서 영향 없음·오탐을 적용하려면 근거와 별도 승인자가 필요합니다. 승인 결과는 다음 재분석부터 반영되며 원시 발견은 보존됩니다.</dd></div>
        <div><dt>SSVC (Stakeholder-Specific Vulnerability Categorization)</dt><dd>악용 상태, 서비스 노출, 악용 자동화 가능성, 업무·안전 영향을 바탕으로 조치 우선순위를 정하는 방법입니다. Tracker는 보류·정기 조치·일정 외 우선 조치·즉시 대응을 제시하며, 확인되지 않은 필수 입력이 있으면 미평가로 표시합니다.</dd></div>
        <div><dt>OVAL (Open Vulnerability and Assessment Language)</dt><dd>취약점과 패치 조건을 도구가 읽을 수 있게 표현하는 언어입니다. Tracker는 지원하는 Ubuntu OVAL 조건을 정확한 Ubuntu 릴리스와 패키지 버전에 대조합니다. 결과는 검토 참고이며, 정보가 부족하거나 조건을 지원하지 않으면 판정 불가로 표시합니다.</dd></div>
        <div><dt>제안 버전</dt><dd>취약점 자료에 기록된 수정 버전 후보입니다. 적용 전에 의존성 호환성을 확인하고, 적용 후 새 SBOM을 등록해 실제 버전과 재분석 결과를 확인합니다.</dd></div>
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
  const [runsLoaded, setRunsLoaded] = useState(demoMode);
  const [recentRunsOnly, setRecentRunsOnly] = useState(false);
  const [revision, setRevision] = useState(0);
  const [activeCveDate, setActiveCveDate] = useState<string | null>(null);
  const baselineRequest = useRef<AbortController | null>(null);
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
  const [bundles, setBundles] = useState<VulnerabilityBundle[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [users, setUsers] = useState<UserSummary[]>([]);
  const [tokens, setTokens] = useState<ApiTokenSummary[]>([]);
  const [ldapSettings, setLdapSettings] = useState<LdapSettings | null>(demoMode ? demoLdapSettings : null);
  const [loadError, setLoadError] = useState("");
  const [libraryQuery, setLibraryQuery] = useState("");
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
  const openRunById = useCallback((runId: string) => {
    void fetchRun(runId).then(openRun).catch(cause => setLoadError(cause instanceof Error ? cause.message : "연결된 회차를 열지 못했습니다."));
  }, [openRun]);
  const permissions = useMemo(() => permissionSet(authUser), [authUser]);
  const can = useCallback(
    (permission: string) => permissions.has("*") || permissions.has(permission),
    [permissions]);
  const canLoadRuns = dataAccess(authUser).runs;
  const canReadCveBaseline = ["dashboard.view", "runs.view", "vulnerability.view", "metadata.view"].some(can);
  const refreshCveBaseline = useCallback(() => {
    baselineRequest.current?.abort();
    const request = new AbortController();
    baselineRequest.current = request;
    return fetchActiveCveBaseline(request.signal).then(
      ({ cveDataAsOf }) => { if (!request.signal.aborted) setActiveCveDate(cveDataAsOf); },
      () => { if (!request.signal.aborted) setActiveCveDate(null); },
    );
  }, []);
  useEffect(() => {
    if (previewMode || !authenticated || !canReadCveBaseline) return;
    void refreshCveBaseline();
    return () => baselineRequest.current?.abort();
  }, [authenticated, canReadCveBaseline, refreshCveBaseline]);
  const canRunAction = useCallback(
    (permission: string) => can(permission) && (permission !== "sbom.delete" || authUser?.role === "admin"),
    [authUser?.role, can]);
  const canUpload = hasPermissions(authUser, "sbom.upload", "services.view");
  const loadData = useCallback(async (loadedUser: AuthUser | null) => {
    setLoadError("");
    setRevision((value) => value + 1);
    if (!dataAccess(loadedUser).catalogs) {
      setServices([]);
      setEnvironments([]);
      return;
    }
    try {
      const catalogs = await fetchCatalogs({ includeInactive: permissionSet(loadedUser).has("catalog.manage") });
      setServices(catalogs.services);
      setEnvironments(catalogs.environments);
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "카탈로그를 불러오지 못했습니다.");
    }
  }, []);
  useEffect(() => {
    if (demoMode || !authenticated || !canLoadRuns || (page !== "dashboard" && page !== "compare")) return;
    const request = new AbortController();
    const firstPageSize = page === "dashboard" ? 24 : 100;
    async function loadRuns() {
      try {
        const first = await fetchRuns({ size: firstPageSize }, request.signal);
        if (request.signal.aborted) return;
        const hasMore = first.total > firstPageSize;
        setRuns(first.items);
        setRecentRunsOnly(hasMore);
        setRunsLoaded(true);
        if (page === "dashboard" && hasMore) {
          const history = await fetchRuns({ size: 100 }, request.signal);
          if (request.signal.aborted) return;
          setRuns(history.items);
          setRecentRunsOnly(history.total > history.items.length);
        }
      } catch (error) {
        if (request.signal.aborted) return;
        setLoadError(error instanceof Error ? error.message : "회차를 불러오지 못했습니다.");
        setRunsLoaded(true);
      }
    }
    void loadRuns();
    return () => request.abort();
  }, [authenticated, canLoadRuns, page, revision]);
  useEffect(() => {
    if (demoMode || !authenticated || page !== "runs" || !initialLink.runId ||
        readPortalLink().runId !== initialLink.runId || !dataAccess(authUser).runs) return;
    let cancelled = false;
    void fetchRun(initialLink.runId).then(
      (run) => { if (!cancelled) setSelectedRun(run); },
      () => { if (!cancelled) setLoadError("링크의 SBOM 회차를 찾을 수 없습니다."); },
    );
    return () => { cancelled = true; };
  }, [authenticated, authUser, initialLink.runId, page]);
  useEffect(() => {
    if (demoMode || standaloneMode || !authenticated || page !== "settings" || !canPage(authUser, "settings")) return;
    let cancelled = false;
    const isAdmin = authUser?.role === "admin";
    void Promise.allSettled([
      isAdmin && can("audit.view") ? fetchAuditEvents() : Promise.resolve({ items: [] as AuditEvent[], page: 1, size: 10, total: 0 }),
      can("users.manage") ? fetchUsers() : Promise.resolve([]),
      isAdmin && can("vulnerability.view") ? fetchVulnerabilityBundles() : Promise.resolve([]),
      can("tokens.manage") ? fetchApiTokens() : Promise.resolve([]),
      isAdmin ? fetchLdapSettings() : Promise.resolve(null),
      can("roles.manage") ? fetchRolePolicies() : Promise.resolve(null),
    ]).then(([audit, currentUsers, currentBundles, currentTokens, ldap, roles]) => {
      if (cancelled) return;
      if (audit.status === "fulfilled") setAuditEvents(audit.value.items);
      if (currentUsers.status === "fulfilled") setUsers(currentUsers.value);
      if (currentBundles.status === "fulfilled") setBundles(currentBundles.value);
      if (currentTokens.status === "fulfilled") setTokens(currentTokens.value);
      if (ldap.status === "fulfilled") setLdapSettings(ldap.value);
      if (roles.status === "fulfilled" && roles.value) {
        setRolePolicyCatalog(roles.value.catalog);
        setRolePolicies(roles.value.roles);
      } else if (roles.status === "rejected") {
        setLoadError(roles.reason instanceof Error ? roles.reason.message : "역할 정책을 불러오지 못했습니다.");
      }
    });
    return () => { cancelled = true; };
  }, [authenticated, authUser, can, page, revision]);
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
    if (page === "dashboard" ) return (<Dashboard runs={canLoadRuns ? runs : []} onUpload={() => setUploadOpen(true)} canUpload={canUpload}
          standalone={standaloneMode} loading={!runsLoaded && canLoadRuns} recent={recentRunsOnly}/>);
    if (page === "runs") return (<RunsPage revision={revision} services={services} environments={environments} search={globalSearch}
          canUpload={canUpload} onUpload={() => setUploadOpen(true)} onSelect={openRun} />);
    if (page === "libraries") return <LibrariesPage initialQuery={libraryQuery} onOpenRun={openRunById} />;
    if (page === "compare") return <ComparePage runs={canLoadRuns ? runs : []} can={can} />;
    if (page === "guide") return <GuidePage />;
    const settingsContent = (initialTab?: SettingsTab) => (<SettingsPage users={users} services={services} environments={environments} tokens={tokens} ldapSettings={ldapSettings} policies={rolePolicies}
          roleCatalog={rolePolicyCatalog}
          bundles={bundles}
          auditEvents={auditEvents}
          isAdmin={authUser?.role === "admin"}
          canVulnerability={can("vulnerability.view")}
          canVulnerabilityManage={can("vulnerability.manage")}
          canAudit={can("audit.view")}
          canUsers={can("users.manage")}
          canTokens={hasPermissions(authUser, "tokens.manage", "services.view")}
          canRoles={can("roles.manage")}
          canPolicyEdit={can("roles.manage")}
          canProjectRuns={can("runs.view")}
          onOpenRun={openRun}
          canSbomPolicies={can("policies.view")}
          canSbomPolicyManage={can("policies.manage")}
          canReanalysis={can("reanalysis.view")} canReanalysisManage={can("reanalysis.manage")}
          canNotifications={can("notifications.view")} canNotificationManage={can("notifications.manage")}
          canServices={can("services.view")}
          canCatalogManage={can("catalog.manage")}
          canMetadata={can("metadata.view")} canMetadataManage={can("metadata.manage")} canProjects={can("catalog.manage")}
          initialTab={initialTab}
          onSync={async () => { const items = await syncVulnerabilityBundles(); setBundles(items);}}
          onBaselineRefresh={canReadCveBaseline ? refreshCveBaseline : undefined}
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
    return null;}, [auditEvents, bundles, can, environments, globalSearch, revision, runsLoaded, recentRunsOnly, initialLink.settingsTab, ldapSettings, loadData, openRun, openRunById, libraryQuery, page, runs, services, tokens, users,
    rolePolicyCatalog,
    rolePolicies, authUser, navigate, canUpload, canLoadRuns, canReadCveBaseline, refreshCveBaseline]);
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
    <Header collapsed={collapsed} search={globalSearch} onSearch={(value) => { setGlobalSearch(value); if (value.trim() && page !== "runs" && can("runs.view")) navigate("runs"); }} dataAsOf={previewMode ? runs.map((run) => preferredCveDate(run.cveDataAsOf, run.dataAsOf)).filter((value): value is string => Boolean(value) && value !== "unknown").sort().at(-1) || null : canReadCveBaseline ? activeCveDate : null} onToggle={() => setCollapsed((value) => !value)} onLogout={() => {
      void logout()
        .then(() => {
          setAuthUser(null);
          setActiveCveDate(null);
          setRuns([]);
          setRunsLoaded(false);
          setSelectedRun(null);
          replacePortalLink({ runId: null });
          setAuthenticated(false);
        })
        .catch((error) => setLoadError(error instanceof Error ? error.message : "로그아웃에 실패했습니다."));
    }} preview={previewMode} user={authUser} />
    <main>{loadError && <p className="form-message" role="alert">{loadError}</p>}{standaloneMode && (<div className="standalone-banner" role="status"><strong>로컬 미리보기 모드</strong><span>로그인·Docker 없이 CycloneDX 구조와 파일 내장 취약점 레코드만
              표시합니다.
            </span></div>)}{content}</main>
    {uploadOpen && canUpload && (<UploadModal services={services} environments={environments} onClose={() => setUploadOpen(false)} onUploaded={(runId) => { setUploadOpen(false); void loadData(authUser); openRunById(runId);}} />)}
    {selectedRun && (<RunDetail key={selectedRun.id} run={selectedRun} username={authUser?.username}
          onOpenLibrary={query => { setLibraryQuery(query); closeRun(); navigate("libraries"); }}
          can={canRunAction} onClose={closeRun} onChanged={() => void loadData(authUser)} />)}
  </div>);}

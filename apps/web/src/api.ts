import type { ReanalysisSchedule, ReanalysisCycle, VexReview, VexReviewInput, ReviewEvent, InboxNotification, NotificationDelivery } from "./types";
import { demoChanges, demoRolePolicyCatalog, demoRuns } from "./demo";
import { compareStandaloneRuns, getStandaloneCatalogs, getStandaloneRun, getStandaloneRuns, importStandaloneSbom } from "./standalone";
import type { AuditEvent, AuthUser, CatalogItem, Comparison, ComponentSnapshot, JobState, LdapSettings, PageResult, RolePolicy, RolePolicyCatalog, SbomRun, SbomRunDetail, SbomPolicyDocument, UserSummary, VulnerabilityBundle, VulnerabilityDataJob } from "./types";

export const standaloneMode = import.meta.env.VITE_STANDALONE_MODE === "true";
export const demoMode = !standaloneMode && import.meta.env.VITE_DEMO_MODE !== "false";
export const previewMode = demoMode || standaloneMode;
let csrfToken = "";
let onForbidden: (() => Promise<void> | void) | undefined;
let previewRolePolicies = demoRolePolicyCatalog.roles.map((item) => ({ ...item, permissions: [...item.permissions] }));

export function setForbiddenHandler(handler: (() => Promise<void> | void) | undefined) { onForbidden = handler; }

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

export async function request<T>(path: string, init?: RequestInit): Promise<T> {
  if (standaloneMode) throw new ApiError("로컬 미리보기에서는 서버 API를 사용할 수 없습니다.", 0);
  const response = await fetch(path, {
    credentials: "include",
    ...init,
    headers: {
      ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
      ...init?.headers,
    },
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: response.statusText }));
    const apiError = new ApiError(error.detail || "요청을 처리하지 못했습니다", response.status);
    if (response.status === 403) await onForbidden?.();
    throw apiError;
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export async function login(username: string, password: string, useLdap = false) {
  const result = await request<{ csrfToken: string; user: AuthUser }>("/api/v1/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password, useLdap }),
  });
  csrfToken = result.csrfToken;
  return result;
}

export function register(username: string, password: string, passwordConfirm: string) {
  return request<{ status: "pending"; detail: string }>("/api/v1/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password, passwordConfirm }),
  });
}

export async function resumeSession(): Promise<{ user: AuthUser; csrfToken: string }> {
  if (previewMode) return { user: { id: "preview", username: "preview", displayName: "미리보기 사용자", department: "보안운영팀", role: "admin", active: true, status: "active", permissions: ["*"] }, csrfToken: "preview" };
  const result = await request<{ csrfToken: string; user: AuthUser }>("/api/v1/auth/me");
  csrfToken = result.csrfToken;
  return result;
}

export async function fetchRolePolicies(): Promise<RolePolicyCatalog> {
  if (previewMode) return { catalog: [...demoRolePolicyCatalog.catalog], roles: previewRolePolicies.map((item) => ({ ...item, permissions: [...item.permissions] })) };
  return request<RolePolicyCatalog>("/api/v1/role-policies");
}

export async function updateRolePolicies(policies: RolePolicy[]): Promise<RolePolicy[]> {
  if (previewMode) {
    previewRolePolicies = policies.map((item) => ({ ...item, permissions: [...item.permissions] }));
    return previewRolePolicies;
  }
  const result = await request<{ roles: RolePolicy[] }>("/api/v1/role-policies", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ roles: Object.fromEntries(policies.map((item) => [item.role, item.permissions])) }),
  });
  return result.roles;
}

export async function logout() {
  if (!previewMode) await request<void>("/api/v1/auth/logout-current", {
    method: "POST",
    headers: {
      "X-KODA-Logout": "current-browser",
    },
  });
  csrfToken = "";
}

export type RunQuery = {
  page?: number;
  size?: number;
  q?: string;
  serviceId?: string;
  environmentId?: string;
  state?: string;
  source?: string;
};

export async function fetchRuns(options: RunQuery = {}): Promise<PageResult<SbomRun>> {
  const page = options.page || 1;
  const size = options.size || 10;
  if (previewMode) {
    const runs = standaloneMode ? [...demoRuns, ...getStandaloneRuns()] : demoRuns;
    const term = options.q?.trim().toLowerCase() || "";
    const filtered = runs.filter((run) => {
      if (options.serviceId && run.service.id !== options.serviceId) return false;
      if (options.environmentId && run.environment.id !== options.environmentId) return false;
      if (options.state && run.state !== options.state) return false;
      if (options.source) {
        const runSource = run.source || "manual";
        if (options.source === "manual" ? !["", "manual", "api"].includes(runSource) : runSource !== options.source) return false;
      }
      if (!term) return true;
      const summary = `${run.service.name} ${run.environment.name} ${run.releaseVersion} ${run.filename || ""} ${run.id}`.toLowerCase();
      const standaloneComponents = getStandaloneRun(run.id)?.components || [];
      const componentText = [
        ...standaloneComponents.flatMap((component) => [component.group, component.name, component.version, component.purl, component.bomRef]),
        ...(run.id === "run-1" ? demoChanges.flatMap((component) => [component.name, component.purl, component.baseVersion, component.targetVersion]) : []),
      ].filter(Boolean).join(" ").toLowerCase();
      return summary.includes(term) || componentText.includes(term);
    });
    const start = (page - 1) * size;
    return { items: filtered.slice(start, start + size), page, size, total: filtered.length };
  }
  const params = new URLSearchParams({ page: String(page), size: String(size) });
  if (options.q?.trim()) params.set("q", options.q.trim());
  if (options.serviceId) params.set("service_id", options.serviceId);
  if (options.environmentId) params.set("environment_id", options.environmentId);
  if (options.state) params.set("state", options.state);
  if (options.source) params.set("source", options.source);
  return request<PageResult<SbomRun>>(`/api/v1/sbom-runs?${params}`);
}

export async function fetchRun(runId: string): Promise<SbomRunDetail> {
  const standaloneRun = standaloneMode ? getStandaloneRun(runId) : undefined;
  if (standaloneRun) return standaloneRun;
  if (previewMode) {
    const run = demoRuns.find((item) => item.id === runId) || demoRuns[0];
    return { ...run, cveDataAsOf: run.cveDataAsOf || run.dataAsOf, components: [{ identityKey: "pkg:maven/org.apache.httpcomponents/httpclient@4.5.13", identityStatus: "stable", componentType: "library", group: "org.apache.httpcomponents", name: "httpclient", version: "4.5.13", purl: "pkg:maven/org.apache.httpcomponents/httpclient@4.5.13", bomRef: "pkg:maven/org.apache.httpcomponents/httpclient@4.5.13", sha256: "demo-sha256", licenses: [{ license: { id: "Apache-2.0" } }], properties: {} }], analyses: [{ id: `demo-analysis-${run.id}`, sequence: 1, state: "completed", dataAsOf: "2025-05-21", cveDataAsOf: "2025-05-21", toolVersion: "grype-demo", dataSources: {}, policyState: run.policyState, policyStatus: run.policyStatus, policyVersion: run.policyVersion, policyCount: run.policyViolationCount, policyViolations: run.policyViolations, analysisMetrics: run.analysisMetrics, findings: [{ canonicalId: "CVE-2025-DEMO", severity: "high", component: "httpclient@4.5.13", cvssScore: 9.8, kev: true, fixedIn: ["4.5.14", "5.0.0"] }] }] };
  }
  return request<SbomRunDetail>(`/api/v1/sbom-runs/${encodeURIComponent(runId)}`);
}

export async function fetchRunComponents(runId: string, page = 1, size = 10, q = ""): Promise<PageResult<ComponentSnapshot>> {
  if (previewMode) {
    const detail = await fetchRun(runId);
    const term = q.trim().toLowerCase();
    const filtered = detail.components.filter((component) =>
      !term || [component.group, component.name, component.version, component.purl, component.bomRef]
        .filter(Boolean).join(" ").toLowerCase().includes(term));
    const start = (page - 1) * size;
    return { items: filtered.slice(start, start + size), page, size, total: filtered.length };
  }
  const params = new URLSearchParams({ page: String(page), size: String(size) });
  if (q.trim()) params.set("q", q.trim());
  return request<PageResult<ComponentSnapshot>>(`/api/v1/sbom-runs/${encodeURIComponent(runId)}/components?${params}`);
}

export async function fetchRunFindings(runId: string, page = 1, size = 10, analysisId = ""): Promise<PageResult<Record<string, unknown>>> {
  if (previewMode) {
    const detail = await fetchRun(runId);
    const analysis = analysisId
      ? detail.analyses.find((item) => item.id === analysisId)
      : detail.analyses[0];
    const findings = analysis?.findings || [];
    const start = (page - 1) * size;
    return { items: findings.slice(start, start + size), page, size, total: findings.length };
  }
  const params = new URLSearchParams({ page: String(page), size: String(size) });
  if (analysisId) params.set("analysisId", analysisId);
  return request<PageResult<Record<string, unknown>>>(`/api/v1/sbom-runs/${encodeURIComponent(runId)}/findings?${params}`);
}

export interface JobSummary {
  id: string;
  kind: string;
  runId: string;
  state: JobState;
  attempts: number;
  error?: string | null;
}

export async function fetchJob(jobId: string): Promise<JobSummary> {
  if (previewMode) return { id: jobId, kind: "process_run", runId: jobId.endsWith("-job") ? jobId.slice(0, -4) : "demo-new", state: "completed", attempts: 1 };
  return request<JobSummary>(`/api/v1/jobs/${encodeURIComponent(jobId)}`);
}

export async function fetchCatalogs(options: { includeInactive?: boolean } = {}): Promise<{ services: CatalogItem[]; environments: CatalogItem[] }> {
  if (standaloneMode) {
    const catalogs = getStandaloneCatalogs();
    return {
      services: [...new Map([...demoRuns.map((run) => run.service), ...catalogs.services].map((item) => [item.id, item])).values()],
      environments: [...new Map([...demoRuns.map((run) => run.environment), ...catalogs.environments].map((item) => [item.id, item])).values()],
    };
  }
  if (previewMode) {
    return {
      services: [...new Map(demoRuns.map((run) => [run.service.id, run.service])).values()],
      environments: [...new Map(demoRuns.map((run) => [run.environment.id, run.environment])).values()],
    };
  }
  const suffix = options.includeInactive ? "?includeInactive=true" : "";
  const [services, environments] = await Promise.all([
    request<CatalogItem[]>(`/api/v1/services${suffix}`),
    request<CatalogItem[]>(`/api/v1/environments${suffix}`),
  ]);
  return { services, environments };
}

export async function fetchAuditEvents(page = 1, size = 10, q = ""): Promise<PageResult<AuditEvent>> {
  if (previewMode) return { items: [], page, size, total: 0 };
  const params = new URLSearchParams({ page: String(page), size: String(size) });
  if (q.trim()) params.set("q", q.trim());
  return request<PageResult<AuditEvent>>(`/api/v1/audit-events?${params}`);
}

export async function fetchUsers() {
  if (previewMode) return [];
  return request<UserSummary[]>("/api/v1/users");
}

export async function fetchVulnerabilityBundles() {
  if (previewMode) return [];
  const result = await request<{ items: VulnerabilityBundle[] }>("/api/v1/vulnerability-data-bundles");
  return result.items;
}

export async function syncVulnerabilityBundles() {
  if (previewMode) return [] as VulnerabilityBundle[];
  const result = await request<{ items: VulnerabilityBundle[] }>("/api/v1/vulnerability-data-bundles/sync", { method: "POST" });
  return result.items;
}

export async function activateVulnerabilityBundle(version: string) {
  if (previewMode) return undefined;
  return request<VulnerabilityBundle>(`/api/v1/vulnerability-data-bundles/${encodeURIComponent(version)}/activate`, { method: "POST" });
}

export function uploadVulnerabilityData(kind: "grype-db" | "vuln-data" | "unified", file: File) {
  if (previewMode) return Promise.resolve({ id: `preview-${Date.now()}`, kind, action: "validate", state: "completed", attempts: 1, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() } as VulnerabilityDataJob);
  return request<VulnerabilityDataJob>(`/api/v1/vulnerability-data-bundles/upload?kind=${encodeURIComponent(kind)}`, { method: "POST", body: file });
}

export function fetchVulnerabilityDataJob(jobId: string) {
  return request<VulnerabilityDataJob>(`/api/v1/vulnerability-data-bundles/jobs/${encodeURIComponent(jobId)}`);
}

export function applyVulnerabilityDataJob(jobId: string) {
  return request<VulnerabilityDataJob>(`/api/v1/vulnerability-data-bundles/jobs/${encodeURIComponent(jobId)}/apply`, { method: "POST" });
}

export function rollbackVulnerabilityData(kind: "grype-db" | "vuln-data", version?: string) {
  const query = version ? `?version=${encodeURIComponent(version)}` : "";
  return request<VulnerabilityDataJob>(`/api/v1/vulnerability-data-bundles/${kind}/rollback${query}`, { method: "POST" });
}

export async function createService(body: { slug: string; name: string }) {
  return request<CatalogItem>("/api/v1/services", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

export async function createEnvironment(body: { slug: string; name: string; sortOrder: number }) {
  return request<CatalogItem>("/api/v1/environments", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

export async function createUser(body: { username: string; password: string; role: string }) {
  return request<UserSummary>("/api/v1/users", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

export async function createApiToken(body: { name: string; serviceId: string }) {
  return request<{ id: string; name: string; token: string; serviceId: string }>("/api/v1/api-tokens", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

export async function fetchApiTokens() {
  if (previewMode) return [] as Array<{ id: string; name: string; serviceId?: string; active: boolean; createdAt: string }>;
  return request<Array<{ id: string; name: string; serviceId?: string; active: boolean; createdAt: string }>>("/api/v1/api-tokens");
}


export async function fetchLdapSettings(): Promise<LdapSettings> {
  return request<LdapSettings>("/api/v1/settings/ldap");
}

export async function updateLdapSettings(body: Record<string, unknown>): Promise<LdapSettings> {
  return request<LdapSettings>("/api/v1/settings/ldap", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function revokeApiToken(id: string) {
  return request<{ id: string; active: boolean }>(`/api/v1/api-tokens/${encodeURIComponent(id)}/revoke`, { method: "POST" });
}

export async function patchUser(id: string, body: { role?: string; active?: boolean }) {
  return request<UserSummary>(`/api/v1/users/${encodeURIComponent(id)}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

export async function deleteUser(id: string) {
  return request<{ id: string; username: string; role: string; status: "deleted" }>(`/api/v1/users/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export async function approveUser(id: string) {
  return request<UserSummary>(`/api/v1/users/${encodeURIComponent(id)}/approve`, { method: "POST" });
}

export async function patchService(id: string, body: { name?: string; active?: boolean }) {
  return request<CatalogItem>(`/api/v1/services/${encodeURIComponent(id)}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

export async function patchEnvironment(id: string, body: { name?: string; slug?: string; sortOrder?: number; active?: boolean }) {
  return request<CatalogItem>(`/api/v1/environments/${encodeURIComponent(id)}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

export async function uploadRun(form: FormData): Promise<{ runId: string; jobId: string }> {
  if (standaloneMode) {
    const file = form.get("sbom");
    if (!(file instanceof File)) throw new ApiError("SBOM 파일을 선택하세요.", 400);
    return importStandaloneSbom(file, String(form.get("releaseVersion") || "preview"));
  }
  if (previewMode) {
    await new Promise((resolve) => setTimeout(resolve, 500));
    return { runId: "demo-new", jobId: "demo-job" };
  }
  return request("/api/v1/sbom-runs", { method: "POST", body: form });
}


export async function createAnalysis(runId: string) {
  return request<{ runId: string; jobId: string }>(`/api/v1/sbom-runs/${encodeURIComponent(runId)}/analyses`, { method: "POST" });
}

export async function archiveRun(runId: string, reason: string) {
  return request<{ runId: string; state: string; archivedAt: string }>(`/api/v1/sbom-runs/${encodeURIComponent(runId)}/archive`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reason }),
  });
}

export async function deleteRun(runId: string) {
  return request<{ runId: string; deleted: boolean; artifactCleanupPending: boolean }>(`/api/v1/sbom-runs/${encodeURIComponent(runId)}`, { method: "DELETE" });
}

export async function fetchComparison(baseRunId: string, targetRunId: string, baseAnalysisId?: string, targetAnalysisId?: string): Promise<Comparison> {
  if (standaloneMode && (getStandaloneRun(baseRunId) || getStandaloneRun(targetRunId))) return compareStandaloneRuns(baseRunId, targetRunId);
  if (previewMode) {
    return {
      base: { runId: baseRunId, sha256: demoRuns.find((run) => run.id === baseRunId)?.sha256 || "", dataAsOf: "2025-05-21", cveDataAsOf: "2025-05-21", artifactUrl: `/api/v1/sbom-runs/${baseRunId}/artifact` },
      target: { runId: targetRunId, sha256: demoRuns.find((run) => run.id === targetRunId)?.sha256 || "", dataAsOf: "2025-05-21", cveDataAsOf: "2025-05-21", artifactUrl: `/api/v1/sbom-runs/${targetRunId}/artifact` },
      summary: {
        componentsAdded: demoChanges.filter((item) => item.change === "added").length,
        componentsRemoved: demoChanges.filter((item) => item.change === "removed").length,
        componentsChanged: demoChanges.filter((item) => item.change === "changed").length,
        vulnerabilitiesAdded: 2,
        vulnerabilitiesRemoved: 1,
        policiesChanged: 1,
      },
      components: demoChanges,
      vulnerabilities: [
        { change: "added", record: { id: "CVE-2024-30260", component: "httpclient", severity: "High", cvssScore: 9.8, kev: true } },
        { change: "removed", record: { id: "CVE-2020-13956", component: "httpclient", severity: "Medium" } },
      ],
      policies: [{ change: "added", record: { rule: "금지 라이선스", component: "commons-logging", status: "violation" } }],
    };
  }
  const params = new URLSearchParams({ baseRunId, targetRunId });
  if (baseAnalysisId) params.set("baseAnalysisId", baseAnalysisId);
  if (targetAnalysisId) params.set("targetAnalysisId", targetAnalysisId);
  return request<Comparison>(`/api/v1/comparisons?${params}`);
}

export async function fetchSbomPolicies(): Promise<SbomPolicyDocument> {
  if (previewMode) return {
    version: 1,
    rules: [
      { id: "critical-high", name: "Critical·High 취약점", kind: "severity", enabled: true, action: "fail", values: ["critical", "high"] },
      { id: "kev", name: "KEV 취약점", kind: "kev", enabled: true, action: "fail", values: [] },
      { id: "license-review", name: "라이선스 확인 필요", kind: "license_unknown", enabled: true, action: "warn", values: [] },
    ],
    exceptions: [], createdBy: "샘플 정책",
  };
  return request<SbomPolicyDocument>("/api/v1/sbom-policies");
}

export function updateSbomPolicies(document: SbomPolicyDocument): Promise<SbomPolicyDocument> {
  if (previewMode) return Promise.reject(new ApiError("미리보기에서는 정책을 저장하지 않습니다.", 0));
  return request<SbomPolicyDocument>("/api/v1/sbom-policies", {
    method: "PUT", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ expectedVersion: document.version, rules: document.rules, exceptions: document.exceptions }),
  });
}

export async function fetchRunPolicyViolations(runId: string, page = 1, size = 25, analysisId = ""): Promise<PageResult<Record<string, unknown>> & { analysisId?: string | null }> {
  if (previewMode) {
    const detail = await fetchRun(runId);
    const analysis = analysisId ? detail.analyses.find((item) => item.id === analysisId) : detail.analyses[0];
    const records = analysis?.policyViolations || analysis?.policies || detail.policyViolations || [];
    return { analysisId: analysis?.id, items: records.slice((page - 1) * size, page * size), total: records.length, page, size };
  }
  const params = new URLSearchParams({ page: String(page), size: String(size) });
  if (analysisId) params.set("analysisId", analysisId);
  return request<PageResult<Record<string, unknown>> & { analysisId?: string | null }>(`/api/v1/sbom-runs/${encodeURIComponent(runId)}/policy-violations?${params}`);
}

function workflowMutation<T>(path: string, body: unknown, method = "POST"): Promise<T> {
  if (previewMode) return Promise.reject(new ApiError("샘플 모드에서는 워크플로를 변경하지 않습니다.", 0));
  return request<T>(path, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}
export function validateSbomPolicyExpression(expression: string, target: string) {
  return workflowMutation<{ valid: boolean; runtime?: string; contextVariables?: string[] }>("/api/v1/sbom-policies/validate", { expression, target });
}
export function fetchReanalysisSchedule() { return request<ReanalysisSchedule>("/api/v1/reanalysis-schedule"); }
export function updateReanalysisSchedule(schedule: ReanalysisSchedule) {
  const { enabled, intervalMinutes, onDataUpdate, latestOnly, serviceIds, environmentIds } = schedule;
  return workflowMutation<ReanalysisSchedule>("/api/v1/reanalysis-schedule", { expectedVersion: schedule.version, enabled, intervalMinutes, onDataUpdate, latestOnly, serviceIds, environmentIds }, "PUT");
}
export function queueReanalysisCycle() { return workflowMutation<ReanalysisCycle>("/api/v1/reanalysis-schedule/run-now", {}); }
export function fetchReanalysisCycles(page = 1) { return request<PageResult<ReanalysisCycle>>(`/api/v1/reanalysis-cycles?page=${page}&size=10`); }
export function fetchVexReviews(runId: string, page = 1) { return request<PageResult<VexReview>>(`/api/v1/sbom-runs/${encodeURIComponent(runId)}/reviews?page=${page}&size=10`); }
export function submitVexReview(runId: string, body: VexReviewInput) { return workflowMutation<VexReview>(`/api/v1/sbom-runs/${encodeURIComponent(runId)}/reviews`, body); }
export function decideVexReview(id: string, decision: "approved" | "rejected", reason: string) { return workflowMutation<VexReview>(`/api/v1/reviews/${encodeURIComponent(id)}/decision`, { decision, reason }); }
export function fetchReviewEvents(id: string) { return request<{ items: ReviewEvent[] }>(`/api/v1/reviews/${encodeURIComponent(id)}/events`); }
export function commentVexReview(id: string, comment: string) { return workflowMutation<ReviewEvent>(`/api/v1/reviews/${encodeURIComponent(id)}/events`, { comment }); }
export function importVex(runId: string, document: unknown) { return workflowMutation<unknown>(`/api/v1/sbom-runs/${encodeURIComponent(runId)}/vex-import`, document); }
export function fetchNotifications(page = 1) { return request<PageResult<InboxNotification> & { unreadCount: number }>(`/api/v1/notifications?page=${page}&size=10`); }
export function markNotificationRead(id: string) { return workflowMutation<unknown>(`/api/v1/notifications/${encodeURIComponent(id)}/read`, {}); }
export function fetchNotificationDeliveries(page = 1) { return request<PageResult<NotificationDelivery>>(`/api/v1/notification-deliveries?page=${page}&size=10`); }
export function retryNotificationDelivery(id: string) { return workflowMutation<unknown>(`/api/v1/notification-deliveries/${encodeURIComponent(id)}/retry`, {}); }

export function fetchNotificationSettings() { return request<{webhookEnabled:boolean;webhookConfigured:boolean;webhookHost?:string;secretConfigured:boolean}>("/api/v1/notification-settings"); }

export interface PackageMetadataRow {
  purl: string; ecosystem: string; currentVersion: string; status: string;
  latestVersion?: string | null; currentVersionPublishedAt?: string | null; latestPublishedAt?: string | null;
  ageDays?: number | null; versionDistance?: number | null; fetchedAt?: string | null; expiresAt?: string | null;
  sourceUrls?: string[]; sourceKind?: string; error?: string | null; fieldStatus?: Record<string, string>;
  versionDistanceBasis?: string; publicationBasis?: string; latestSelection?: string; latestIsPrerelease?: boolean;
  currentVersionPublishedAtBasis?: string; latestPublishedAtBasis?: string;
  registryLatestVersion?: string | null; registryLatestIsPrerelease?: boolean; warnings?: string[];
  versionDistanceParts?: {epoch:number;major:number;minor:number;patch:number} | null;
  versionDistancePartsBasis?: string;
}
export interface RunMetadataItem { component: {identityKey?: string; name: string; version?: string | null; purl?: string | null}; metadata: PackageMetadataRow }
export interface MetadataStatus { enabled: boolean; supportedEcosystems: string[]; counts: Record<string, number>; ttlSeconds: number }
export const fetchMetadataStatus = () => request<MetadataStatus>("/api/v1/package-metadata/status");
export const fetchRunMetadata = (id: string, page = 1) => request<PageResult<RunMetadataItem>>(`/api/v1/sbom-runs/${encodeURIComponent(id)}/package-metadata?page=${page}&size=10`);
export const refreshRunMetadata = (id: string) => workflowMutation<{queued:number;cached:number;unsupported:number;invalid?:number;deferred?:number}>(`/api/v1/sbom-runs/${encodeURIComponent(id)}/package-metadata/refresh`, {});
export const importMetadata = (bundle: unknown) => workflowMutation<{imported:number;skipped:number}>("/api/v1/package-metadata/import", bundle);
export const importVulnerabilityIntelligence = (bundle: unknown) => workflowMutation<{imported:number;skipped:number}>("/api/v1/vulnerability-intelligence/import", bundle);
export function importEpssSnapshot(file: File) {
  if (previewMode) return Promise.reject(new ApiError("샘플 모드에서는 EPSS를 반입하지 않습니다.", 0));
  const form = new FormData();
  form.append("file", file);
  return request<{imported:number;skipped:number;date:string;modelVersion:string;sha256:string;policyEligible:boolean}>("/api/v1/vulnerability-intelligence/import-csv", {method:"POST",body:form});
}

export interface NativeProject {
  id:string;sourceId:string;sourceProjectId:string;serviceId:string;environmentId:string;releaseId?:string;currentRunId?:string;
  name:string;version:string;parentProjectId:string|null;tags:string[];isLatest:boolean;active:boolean;revision:number;collectionLogic?:CollectionLogic;collectionTag?:string|null;
}
export const fetchProjectCatalog = (page=1) => request<PageResult<NativeProject>>(`/api/v1/project-catalog?page=${page}&size=20`);
export const fetchProjectRuns = (id:string,page=1) => request<PageResult<SbomRun>>(`/api/v1/project-catalog/${encodeURIComponent(id)}/runs?page=${page}&size=10`);
export const createNativeProject = (body:Record<string,unknown>) => workflowMutation<NativeProject>("/api/v1/project-catalog",body);
export const updateNativeProject = (project:NativeProject, update:Record<string,unknown>) => workflowMutation<NativeProject>(`/api/v1/project-catalog/${encodeURIComponent(project.id)}`,{expectedRevision:project.revision,...update},"PATCH");

export type CollectionLogic = "NONE" | "AGGREGATE_DIRECT_CHILDREN" | "AGGREGATE_DIRECT_CHILDREN_WITH_TAG" | "AGGREGATE_LATEST_VERSION_CHILDREN" | "AGGREGATE_ALL_DESCENDANTS";
export interface CollectionTotals {rawVulnerabilityCount?:number;policyFailCount?:number;policyWarnCount?:number;policyInfoCount?:number;policySuppressedCount?:number;componentCount:number;vulnerabilityCount:number;vulnerableComponentCount:number;kevCount:number;policyViolationCount:number;suppressedVulnerabilityCount:number;severityCounts:Record<string,number>;uniqueVulnerabilityCount:number}
export interface CollectionMetrics {projectId:string;collectionLogic:CollectionLogic;collectionTag:string|null;generatedAt:string;coverage:{selectedProjectCount:number;analyzedProjectCount:number;missingProjectCount:number;staleProjectCount:number;policyIncompleteProjectCount?:number;ambiguousProjectCount?:number;complete:boolean};totals:CollectionTotals;projects:{projectId:string;name:string;version:string;runId?:string|null;analysisId?:string|null;analysisSequence?:number|null;state:string;policyState?:string|null;metrics?:CollectionTotals|null}[]}
export const fetchCollectionMetrics = (id:string) => request<CollectionMetrics>(`/api/v1/project-catalog/${encodeURIComponent(id)}/metrics`);

export interface PrivateAffected {purl:string;versions:string[];ranges:{scheme:"maven"|"semver";introduced:string|null;fixed:string|null;lastAffected:string|null}[];fixedVersions:string[]}
export interface PrivateAdvisoryInput {advisoryId:string;title:string;description:string;severity:"Critical"|"High"|"Medium"|"Low"|"Unknown";cvssScore:number|null;cwes:number[];aliases:string[];references:string[];state:"draft"|"published"|"withdrawn";affected:PrivateAffected[]}
export interface PrivateAdvisory extends PrivateAdvisoryInput {id:string;revision:number;createdAt:string;updatedAt:string;affectedRunsQueued?:number}
export const fetchPrivateAdvisories = (page=1) => request<PageResult<PrivateAdvisory>>(`/api/v1/private-vulnerabilities?page=${page}&size=20`);
export const createPrivateAdvisory = (body:PrivateAdvisoryInput) => workflowMutation<PrivateAdvisory>("/api/v1/private-vulnerabilities",body);
export const updatePrivateAdvisory = (advisory:PrivateAdvisory,body:PrivateAdvisoryInput) => workflowMutation<PrivateAdvisory>(`/api/v1/private-vulnerabilities/${encodeURIComponent(advisory.id)}`,{...body,expectedRevision:advisory.revision},"PUT");
export const fetchPrivateAdvisoryHistory = (id:string) => request<unknown>(`/api/v1/private-vulnerabilities/${encodeURIComponent(id)}/history`);

export interface UnifiedVulnerabilityStatus {
  state: "active" | "empty" | "purged" | "purging" | "unavailable";
  available: boolean;
  currentVersion: string | null;
  expectedBaseVersion: string | null;
  managed: boolean;
  signatureRequired: boolean;
  referenceSources: {kind: string; id: string; dataDate?: string | null; status?: string; maxAgeDays?: number}[];
  datasets?: {kind: string; dataDate?: string | null; status?: string; records?: number | null}[];
  pendingJobs: VulnerabilityDataJob[];
  canPurge: boolean;
  blockedReason?: string | null;
}
export function fetchUnifiedVulnerabilityStatus() {
  return request<UnifiedVulnerabilityStatus>("/api/v1/vulnerability-data-bundles/unified/status");
}
export function purgeUnifiedVulnerabilityData(expectedBaseVersion: string | null) {
  return request<VulnerabilityDataJob>("/api/v1/vulnerability-data-bundles/unified/purge", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({confirm: "DELETE VULNERABILITY DATA", expectedBaseVersion}),
  });
}

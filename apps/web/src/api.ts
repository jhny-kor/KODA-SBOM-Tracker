import { demoChanges, demoRolePolicyCatalog, demoRuns } from "./demo";
import { compareStandaloneRuns, getStandaloneCatalogs, getStandaloneRun, getStandaloneRuns, importStandaloneSbom } from "./standalone";
import type { AuditEvent, AuthUser, CatalogItem, Comparison, ComponentSnapshot, DependencyTrackStatus, JobState, LdapSettings, PageResult, RolePolicy, RolePolicyCatalog, SbomRun, SbomRunDetail, UserSummary, VulnerabilityBundle } from "./types";

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

async function request<T>(path: string, init?: RequestInit): Promise<T> {
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
  return request<PageResult<SbomRun>>(`/api/v1/sbom-runs?${params}`);
}

export async function fetchRun(runId: string): Promise<SbomRunDetail> {
  const standaloneRun = standaloneMode ? getStandaloneRun(runId) : undefined;
  if (standaloneRun) return standaloneRun;
  if (previewMode) {
    const run = demoRuns.find((item) => item.id === runId) || demoRuns[0];
    return { ...run, cveDataAsOf: run.cveDataAsOf || run.dataAsOf, components: [{ identityKey: "pkg:maven/org.apache.httpcomponents/httpclient@4.5.13", identityStatus: "stable", componentType: "library", group: "org.apache.httpcomponents", name: "httpclient", version: "4.5.13", purl: "pkg:maven/org.apache.httpcomponents/httpclient@4.5.13", bomRef: "pkg:maven/org.apache.httpcomponents/httpclient@4.5.13", sha256: "demo-sha256", licenses: [{ license: { id: "Apache-2.0" } }], properties: {} }], analyses: [{ id: `demo-analysis-${run.id}`, sequence: 1, state: "completed", dataAsOf: "2025-05-21", cveDataAsOf: "2025-05-21", toolVersion: "grype-demo", dataSources: {}, findings: [{ canonicalId: "CVE-2025-DEMO", severity: "high", component: "httpclient@4.5.13", cvssScore: 9.8, kev: true, fixedIn: ["4.5.14", "5.0.0"] }] }] };
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

export async function fetchDependencyTrackStatus(): Promise<DependencyTrackStatus> {
  if (standaloneMode) return { configured: false, reachable: false, authenticated: false, version: "standalone-preview", team: "local", permissions: [], missingPermissions: [] };
  if (demoMode) return { configured: true, reachable: true, authenticated: true, version: "5.0.3", team: "demo", permissions: [], missingPermissions: [] };
  return request<DependencyTrackStatus>("/api/v1/dependency-track/status");
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

export async function retryDependencyTrack(runId: string) {
  return request<{ runId: string; jobId: string }>(`/api/v1/sbom-runs/${encodeURIComponent(runId)}/retry-dependency-track`, { method: "POST" });
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
  return request<{ runId: string; deleted: boolean; dependencyTrackProjectUuid?: string | null; artifactCleanupPending: boolean }>(`/api/v1/sbom-runs/${encodeURIComponent(runId)}`, { method: "DELETE" });
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

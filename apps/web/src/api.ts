import { demoChanges, demoRuns } from "./demo";
import type { AuditEvent, CatalogItem, Comparison, DependencyTrackStatus, JobState, SbomRun, SbomRunDetail, UserSummary, VulnerabilityBundle } from "./types";

export const demoMode = import.meta.env.VITE_DEMO_MODE !== "false";
let csrfToken = "";

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
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
    throw new ApiError(error.detail || "요청을 처리하지 못했습니다", response.status);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export async function login(username: string, password: string) {
  const result = await request<{ csrfToken: string; user: unknown }>("/api/v1/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  csrfToken = result.csrfToken;
  return result;
}

export async function resumeSession() {
  if (demoMode) return { user: { username: "보안운영팀", role: "admin" }, csrfToken: "demo" };
  const result = await request<{ csrfToken: string; user: unknown }>("/api/v1/auth/me");
  csrfToken = result.csrfToken;
  return result;
}

export async function logout() {
  if (!demoMode) await request<void>("/api/v1/auth/logout", { method: "POST" });
  csrfToken = "";
}

export async function fetchRuns(search = ""): Promise<SbomRun[]> {
  if (demoMode) return demoRuns;
  const items: SbomRun[] = [];
  let page = 1;
  let total = 0;
  do {
    const params = new URLSearchParams({ page: String(page), size: "100" });
    if (search.trim()) params.set("q", search.trim());
    const result = await request<{ items: SbomRun[]; total: number }>(`/api/v1/sbom-runs?${params}`);
    items.push(...result.items);
    total = result.total;
    page += 1;
    if (!result.items.length) break;
  } while (items.length < total);
  return items;
}

export async function fetchRun(runId: string): Promise<SbomRunDetail> {
  if (demoMode) {
    const run = demoRuns.find((item) => item.id === runId) || demoRuns[0];
    return { ...run, components: [{ identityKey: "pkg:maven/org.apache.httpcomponents/httpclient@4.5.13", identityStatus: "stable", componentType: "library", group: "org.apache.httpcomponents", name: "httpclient", version: "4.5.13", purl: "pkg:maven/org.apache.httpcomponents/httpclient@4.5.13", bomRef: "pkg:maven/org.apache.httpcomponents/httpclient@4.5.13", sha256: "demo-sha256", licenses: [{ license: { id: "Apache-2.0" } }], properties: {} }], analyses: [{ id: `demo-analysis-${run.id}`, sequence: 1, state: "completed", dataAsOf: "2025-05-21", toolVersion: "grype-demo", dataSources: {} }] };
  }
  return request<SbomRunDetail>(`/api/v1/sbom-runs/${encodeURIComponent(runId)}`);
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
  if (demoMode) return { id: jobId, kind: "process_run", runId: "demo-new", state: "completed", attempts: 1 };
  return request<JobSummary>(`/api/v1/jobs/${encodeURIComponent(jobId)}`);
}

export async function fetchCatalogs(): Promise<{ services: CatalogItem[]; environments: CatalogItem[] }> {
  if (demoMode) {
    return {
      services: [...new Map(demoRuns.map((run) => [run.service.id, run.service])).values()],
      environments: [...new Map(demoRuns.map((run) => [run.environment.id, run.environment])).values()],
    };
  }
  const [services, environments] = await Promise.all([
    request<CatalogItem[]>("/api/v1/services"),
    request<CatalogItem[]>("/api/v1/environments"),
  ]);
  return { services, environments };
}

export async function fetchAuditEvents() {
  if (demoMode) return [];
  const result = await request<{ items: AuditEvent[] }>("/api/v1/audit-events?size=100");
  return result.items;
}

export async function fetchUsers() {
  if (demoMode) return [];
  return request<UserSummary[]>("/api/v1/users");
}

export async function fetchVulnerabilityBundles() {
  if (demoMode) return [];
  const result = await request<{ items: VulnerabilityBundle[] }>("/api/v1/vulnerability-data-bundles");
  return result.items;
}

export async function syncVulnerabilityBundles() {
  if (demoMode) return [] as VulnerabilityBundle[];
  const result = await request<{ items: VulnerabilityBundle[] }>("/api/v1/vulnerability-data-bundles/sync", { method: "POST" });
  return result.items;
}

export async function activateVulnerabilityBundle(version: string) {
  if (demoMode) return undefined;
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
  if (demoMode) return [] as Array<{ id: string; name: string; serviceId?: string; active: boolean; createdAt: string }>;
  return request<Array<{ id: string; name: string; serviceId?: string; active: boolean; createdAt: string }>>("/api/v1/api-tokens");
}

export async function fetchDependencyTrackStatus(): Promise<DependencyTrackStatus> {
  if (demoMode) return { configured: true, reachable: true, authenticated: true, version: "5.0.3", team: "demo", permissions: [], missingPermissions: [] };
  return request<DependencyTrackStatus>("/api/v1/dependency-track/status");
}

export async function revokeApiToken(id: string) {
  return request<{ id: string; active: boolean }>(`/api/v1/api-tokens/${encodeURIComponent(id)}/revoke`, { method: "POST" });
}

export async function patchUser(id: string, body: { role?: string; active?: boolean }) {
  return request<UserSummary>(`/api/v1/users/${encodeURIComponent(id)}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

export async function patchService(id: string, body: { name?: string; active?: boolean }) {
  return request<CatalogItem>(`/api/v1/services/${encodeURIComponent(id)}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

export async function patchEnvironment(id: string, body: { name?: string; sortOrder?: number }) {
  return request<CatalogItem>(`/api/v1/environments/${encodeURIComponent(id)}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

export async function uploadRun(form: FormData): Promise<{ runId: string; jobId: string }> {
  if (demoMode) {
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

export async function fetchComparison(baseRunId: string, targetRunId: string, baseAnalysisId?: string, targetAnalysisId?: string): Promise<Comparison> {
  if (demoMode) {
    return {
      base: { runId: baseRunId, sha256: demoRuns.find((run) => run.id === baseRunId)?.sha256 || "", dataAsOf: "2025-05-21", artifactUrl: `/api/v1/sbom-runs/${baseRunId}/artifact` },
      target: { runId: targetRunId, sha256: demoRuns.find((run) => run.id === targetRunId)?.sha256 || "", dataAsOf: "2025-05-21", artifactUrl: `/api/v1/sbom-runs/${targetRunId}/artifact` },
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
        { change: "added", record: { id: "CVE-2024-30260", component: "httpclient", severity: "High" } },
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

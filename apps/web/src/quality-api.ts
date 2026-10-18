import { request } from "./api";

export type QualityProfile = {
  projectId: string | null;
  name: string;
  version: number;
  mode: "warn" | "enforce";
  maxErrors: number;
  maxWarnings: number | null;
  maxMissingIdentityRatio: number;
  maxUnresolvedRefs: number;
  maxAgeDays: number;
  reanalysisRequested?: number;
};
export type QualitySummary = {
  componentCount: number;
  errorCount: number;
  warningCount: number;
  missingIdentityCount: number;
  missingIdentityRatio: number | null;
  unresolvedRefCount: number;
  score: number | null;
  qualityStatus: "pass" | "warn" | "fail" | "failed";
  fieldStatus: Record<string, unknown>;
  sourceBasis?: "verified_original_artifact" | "stored_normalized_json";
};
export type QualityRevision = {
  id: string;
  runId: string;
  sequence: number;
  state: "completed" | "failed";
  profileSnapshot: QualityProfile;
  summary: QualitySummary;
  createdAt: string;
  engineVersion: string;
  originalSha256: string;
  error: string | null;
  comparison: { previousRevisionId: string; errorDelta: number; warningDelta: number } | null;
};
export type QualityIssue = {
  id: string;
  ruleId: string;
  severity: "error" | "warning" | "info";
  path: string;
  bomRef: string;
  componentName: string;
  message: string;
  observed: unknown;
  expected: unknown;
  remediation: string;
};
export type QualityPage<T> = { items: T[]; total: number; page: number; size: number };

export function fetchQualityRevisions(runId: string, page = 1) {
  return request<QualityPage<QualityRevision>>(`/api/v1/sbom-runs/${encodeURIComponent(runId)}/quality-revisions?page=${page}&size=20`);
}
export function createQualityRevision(runId: string) {
  return request<QualityRevision>(`/api/v1/sbom-runs/${encodeURIComponent(runId)}/quality-revisions`, { method: "POST" });
}
export function fetchQualityIssues(runId: string, revisionId: string, page: number, severity: string, ruleId: string) {
  const params = new URLSearchParams({ revisionId, page: String(page), size: "20" });
  if (severity) params.set("severity", severity);
  if (ruleId) params.set("ruleId", ruleId);
  return request<QualityPage<QualityIssue>>(`/api/v1/sbom-runs/${encodeURIComponent(runId)}/quality-issues?${params}`);
}
export function qualityExportUrl(runId: string, revisionId: string, format: "json" | "csv") {
  const params = new URLSearchParams({ revisionId, format });
  return `/api/v1/sbom-runs/${encodeURIComponent(runId)}/quality-export?${params}`;
}
export function fetchQualityProfile(projectId: string) {
  const params = new URLSearchParams();
  if (projectId.trim()) params.set("projectId", projectId.trim());
  return request<QualityProfile>(`/api/v1/quality-profiles?${params}`);
}
export function saveQualityProfile(projectId: string, profile: QualityProfile) {
  const params = new URLSearchParams();
  if (projectId.trim()) params.set("projectId", projectId.trim());
  const { name, mode, maxErrors, maxWarnings, maxMissingIdentityRatio, maxUnresolvedRefs, maxAgeDays } = profile;
  return request<QualityProfile>(`/api/v1/quality-profiles?${params}`, {
    method: "PUT", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ expectedVersion: profile.version, name, mode, maxErrors, maxWarnings, maxMissingIdentityRatio, maxUnresolvedRefs, maxAgeDays }),
  });
}

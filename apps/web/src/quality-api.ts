import { request } from "./api";

export const QUALITY_DOMAINS = ["identity", "graph", "license", "provenance", "integrity"] as const;
export type QualityDomain = typeof QUALITY_DOMAINS[number];
export type QualityWeights = Record<QualityDomain, number>;
export const DEFAULT_QUALITY_WEIGHTS: QualityWeights = { identity: 30, graph: 20, license: 20, provenance: 20, integrity: 10 };
export type QualityResolution = {
  kind: "project" | "tag" | "parent" | "parent_tag" | "global";
  projectId?: string | null;
  sourceId?: string | null;
  depth?: number | null;
  inheritedFrom?: string | null;
  owningProjectId?: string | null;
  chain?: { projectId: string; sourceProjectId: string; parentProjectId?: string | null; tags: string[]; active: boolean; profileVersion: number; profileInherited: boolean }[];
  matchedTags?: unknown[];
  selectedScopeKey?: string;
};
export type QualityTagScope = { sourceId: string; tag: string };
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
  sourceId?: string | null;
  tag?: string | null;
  priority?: number;
  inherit?: boolean;
  scopeKey?: string;
  scoreWeights?: QualityWeights;
  minScore?: number | null;
  resolution?: QualityResolution;
};
export type QualitySummary = {
  componentCount: number;
  errorCount: number;
  warningCount: number;
  missingIdentityCount: number;
  missingIdentityRatio: number | null;
  unresolvedRefCount: number;
  score: number | null;
  scoreDetails?: { version?: string; state?: "completed" | "failed" | "empty" | "no_applicable_weight"; domains?: Partial<Record<QualityDomain, QualityDomainScore>>; [key: string]: unknown };
  blockingIssueCount?: number | null;
  minScore?: number | null;
  scoreThresholdViolated?: boolean;
  scoreVersion?: string;
  qualityStatus: "pass" | "warn" | "fail" | "failed";
  fieldStatus: Record<string, unknown>;
  sourceBasis?: "verified_original_artifact" | "stored_normalized_json";
};
export type QualityDomainScore = {
  score: number | null;
  applicable?: boolean;
  passed?: number;
  total?: number;
  numerator?: number;
  denominator?: number;
  weight?: number;
  effectiveWeight?: number;
  weightedContribution?: number | null;
};
export type EffectiveQualityProfile = {
  profile: QualityProfile;
  project: { id: string; sourceId: string; sourceProjectId: string; parentProjectId?: string | null; tags: string[] } | null;
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
  comparison: { previousRevisionId: string; errorDelta: number; warningDelta: number; scoreDelta?: number | null } | null;
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
export function fetchQualityProfile(projectId: string, tagScope?: QualityTagScope) {
  const params = new URLSearchParams();
  if (tagScope) { params.set("sourceId", tagScope.sourceId.trim()); params.set("tag", tagScope.tag.trim()); }
  else if (projectId.trim()) params.set("projectId", projectId.trim());
  return request<QualityProfile>(`/api/v1/quality-profiles?${params}`);
}
export function saveQualityProfile(projectId: string, profile: QualityProfile, tagScope?: QualityTagScope) {
  const params = new URLSearchParams();
  if (tagScope) { params.set("sourceId", tagScope.sourceId.trim()); params.set("tag", tagScope.tag.trim()); }
  else if (projectId.trim()) params.set("projectId", projectId.trim());
  const { name, mode, maxErrors, maxWarnings, maxMissingIdentityRatio, maxUnresolvedRefs, maxAgeDays, minScore, priority, inherit } = profile;
  return request<QualityProfile>(`/api/v1/quality-profiles?${params}`, {
    method: "PUT", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ expectedVersion: profile.version, name, mode, maxErrors, maxWarnings, maxMissingIdentityRatio, maxUnresolvedRefs, maxAgeDays, scoreWeights: profile.scoreWeights || DEFAULT_QUALITY_WEIGHTS, minScore: minScore ?? null, priority: priority ?? 0, inherit: inherit ?? false }),
  });
}

export function fetchEffectiveQualityProfile(runId: string) {
  return request<EffectiveQualityProfile>(`/api/v1/sbom-runs/${encodeURIComponent(runId)}/quality-profile`);
}
export function fetchQualityTagProfiles(sourceId: string, page = 1) {
  const params = new URLSearchParams({ sourceId, page: String(page), size: "20" });
  return request<QualityPage<QualityProfile>>(`/api/v1/quality-tag-profiles?${params}`);
}

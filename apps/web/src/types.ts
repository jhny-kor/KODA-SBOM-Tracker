export type RunState = "completed" | "processing" | "partial" | "failed" | "queued" | "archived";
export type JobState = "completed" | "running" | "failed" | "queued";

export interface SbomRun {
  id: string;
  service: { id: string; name: string; slug: string };
  environment: { id: string; name: string; slug: string };
  releaseVersion: string;
  roundNumber: number;
  state: RunState;
  sha256: string;
  componentCount: number;
  vulnerabilityCount: number;
  policyViolationCount: number;
  dataAsOf: string | null;
  createdAt: string;
  filename?: string;
  specVersion?: string;
  analysisState?: JobState;
  dependencyTrackState?: JobState;
  dependencyTrackError?: string | null;
  analysisDataSources?: Record<string, unknown>;
  dependencyTrackMetrics?: Record<string, unknown> | null;
  dependencyTrackPolicies?: Record<string, unknown>[];
}

export interface AnalysisRevisionSummary {
  id: string;
  sequence: number;
  state: JobState;
  dataAsOf: string | null;
  toolVersion?: string | null;
  dataSources?: Record<string, unknown>;
  error?: string | null;
}

export interface SbomRunDetail extends SbomRun {
  analyses: AnalysisRevisionSummary[];
}

export interface ComponentChange {
  change: "added" | "removed" | "changed";
  fields: string[];
  identityKey: string;
  name: string;
  purl: string;
  baseVersion?: string;
  targetVersion?: string;
  baseSha256?: string;
  targetSha256?: string;
  identityStatus?: string;
}

export interface RecordChange {
  change: "added" | "removed" | "changed";
  record?: Record<string, unknown>;
  base?: Record<string, unknown>;
  target?: Record<string, unknown>;
}

export interface Comparison {
  base: { runId: string; sha256: string; dataAsOf: string | null };
  target: { runId: string; sha256: string; dataAsOf: string | null };
  summary: {
    componentsAdded: number;
    componentsRemoved: number;
    componentsChanged: number;
    vulnerabilitiesAdded: number;
    vulnerabilitiesRemoved: number;
    policiesChanged: number;
  };
  components: ComponentChange[];
  vulnerabilities: RecordChange[];
  policies: RecordChange[];
}

export interface CatalogItem {
  id: string;
  name: string;
  slug: string;
}

export interface VulnerabilityBundle {
  id: string;
  version: string;
  dataAsOf: string;
  nvdDataAsOf: string;
  kevDataAsOf: string;
  grypeDbSchema: string;
  aliasCount: number;
  kevCount: number;
  manifestSha256: string;
  active: boolean;
  importedAt: string;
}

export interface AuditEvent {
  id: string;
  actor: string;
  action: string;
  targetType: string;
  targetId: string;
  detail?: Record<string, unknown>;
  createdAt: string;
}

export interface UserSummary {
  id?: string;
  username: string;
  role: string;
  active: boolean;
}

export interface DependencyTrackStatus {
  configured: boolean;
  reachable: boolean;
  authenticated: boolean;
  version?: string | null;
  team?: string | null;
  permissions: string[];
  missingPermissions: string[];
  error?: string;
}

export type RunState = "completed" | "processing" | "partial" | "failed" | "queued" | "archived";
export type JobState = "completed" | "running" | "failed" | "queued";

export type PolicyState = "not_evaluated" | "completed" | "failed";
export type PolicyStatus = "info" | "pass" | "warn" | "fail" | "not_evaluated" | "failed";
export interface SbomPolicyRule {
  id: string;
  name: string;
  kind: "severity" | "kev" | "license_denied" | "license_unknown" | "component_denied" | "cel";
  enabled: boolean;
  action: "fail" | "warn" | "info";
  values: string[];
  expression?: string;
  target?: "component" | "vulnerability" | "project";
  serviceIds?: string[];
  environmentIds?: string[];
  releaseVersions?: string[];
  runIds?: string[];
}
export interface SbomPolicyException {
  id: string;
  ruleId: string;
  runId?: string;
  component: string;
  vulnerabilityId?: string;
  reason: string;
  expiresAt: string | null;
}
export interface SbomPolicyDocument {
  version: number;
  rules: SbomPolicyRule[];
  exceptions: SbomPolicyException[];
  createdAt?: string;
  createdBy?: string;
}
export interface NativePolicyFields {
  analysisId?: string | null;
  policyState?: PolicyState;
  policyStatus?: PolicyStatus;
  policyVersion?: number | null;
  policyError?: string | null;
  policyViolations?: Record<string, unknown>[];
  analysisMetrics?: Record<string, unknown>;
  policySnapshot?: Record<string, unknown>;
}

export interface SbomRun extends NativePolicyFields {
  id: string;
  service: { id: string; name: string; slug: string };
  environment: { id: string; name: string; slug: string };
  releaseVersion: string;
  roundNumber: number;
  state: RunState;
  sha256: string;
  componentCount: number;
  componentTypeCounts?: Record<string, number>;
  vulnerabilityCount: number;
  vulnerableComponentCount?: number;
  severityCounts?: Record<string, number>;
  kevCount?: number;
  policyViolationCount: number;
  dataAsOf: string | null;
  cveDataAsOf?: string | null;
  createdAt: string;
  filename?: string;
  specVersion?: string;
  analysisState?: JobState;
  dependencyTrackEnabled?: boolean;
  dependencyTrackUrl?: string | null;
  dependencyTrackState?: JobState;
  dependencyTrackError?: string | null;
  analysisDataSources?: Record<string, unknown>;
  dependencyTrackMetrics?: Record<string, unknown> | null;
  dependencyTrackPolicies?: Record<string, unknown>[];
  source?: "manual" | "api" | "scheduled" | string;
  sourceMetadata?: Record<string, unknown>;
}

export interface AnalysisRevisionSummary extends NativePolicyFields {
  id: string;
  sequence: number;
  state: JobState;
  dataAsOf: string | null;
  cveDataAsOf?: string | null;
  toolVersion?: string | null;
  dataSources?: Record<string, unknown>;
  error?: string | null;
  findingCount?: number;
  policyCount?: number;
  findings?: Record<string, unknown>[];
  policies?: Record<string, unknown>[];
}

export interface SbomRunDetail extends SbomRun {
  analyses: AnalysisRevisionSummary[];
  components: ComponentSnapshot[];
}

export interface ComponentSnapshot {
  identityKey: string;
  identityStatus?: string;
  componentType?: string | null;
  group?: string | null;
  name: string;
  version?: string | null;
  purl?: string | null;
  bomRef?: string | null;
  sha256?: string | null;
  licenses?: unknown[];
  properties?: unknown[] | Record<string, unknown>;
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
  componentType?: string | null;
  group?: string | null;
  bomRef?: string | null;
  baseLicenses?: unknown[];
  targetLicenses?: unknown[];
}

export interface RecordChange {
  change: "added" | "removed" | "changed";
  record?: Record<string, unknown>;
  base?: Record<string, unknown>;
  target?: Record<string, unknown>;
}

export interface Comparison {
  base: { runId: string; sha256: string; dataAsOf: string | null; cveDataAsOf?: string | null; artifactUrl?: string; dependencyTrackEnabled?: boolean; policyState?: PolicyState; policyVersion?: number | null };
  target: { runId: string; sha256: string; dataAsOf: string | null; cveDataAsOf?: string | null; artifactUrl?: string; dependencyTrackEnabled?: boolean; policyState?: PolicyState; policyVersion?: number | null };
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
  active?: boolean;
  sortOrder?: number;
}

export interface VulnerabilityBundle {
  id: string;
  version: string;
  dataAsOf: string;
  nvdDataAsOf: string;
  kevDataAsOf: string;
  grypeDbSchema: string;
  grypeDbVersion?: string | null;
  vulnDataVersion?: string | null;
  aliasCount: number;
  kevCount: number;
  manifestSha256: string;
  active: boolean;
  importedAt: string;
}

export interface VulnerabilityDataJob {
  id: string;
  kind: "grype-db" | "vuln-data";
  action?: "validate" | "apply" | "rollback";
  state: JobState;
  attempts: number;
  error?: string | null;
  version?: string | null;
  dataAsOf?: string | null;
  manifestSha256?: string | null;
  fileSha256?: string | null;
  bytes?: number | null;
  expectedBaseVersion?: string | null;
  createdAt: string;
  updatedAt: string;
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

export interface PageResult<T> {
  items: T[];
  page: number;
  size: number;
  total: number;
}

export interface UserSummary {
  id?: string;
  username: string;
  displayName?: string;
  department?: string;
  role: string;
  active: boolean;
  status?: "pending" | "active" | "inactive" | "deleted";
  authSource?: "local" | "ldap";
  permissions?: string[];
}

export interface AuthUser extends UserSummary { id: string; }

export interface RolePolicy {
  role: string;
  permissions: string[];
}

export interface RolePolicyCatalog {
  catalog: string[];
  roles: RolePolicy[];
}

export interface DependencyTrackStatus {
  enabled?: boolean;
  configured: boolean;
  reachable: boolean;
  authenticated: boolean;
  version?: string | null;
  team?: string | null;
  permissions: string[];
  missingPermissions: string[];
  error?: string;
}

export interface LdapSettings {
  enabled: boolean;
  host: string;
  port: number;
  tlsMode: "ldaps" | "starttls" | "plain";
  verifyCertificate: boolean;
  caCertPath: string;
  bindDn: string;
  baseDn: string;
  loginAttribute: string;
  usernameAttribute: string;
  subjectAttribute: string;
  userFilter: string;
  groupAttribute: string;
  groupMappings: Record<string, string>;
  autoProvision: boolean;
  defaultRole: string;
  hasBindPassword: boolean;
  encryptionReady: boolean;
}

export interface ReanalysisCycle {
  id: string; reason: string; state: "queued" | "running" | "completed" | "partial";
  createdAt: string; finishedAt?: string | null; totalCount: number; pendingCount: number;
  enqueuedCount: number; completedCount: number; failedCount: number; skippedCount: number;
}
export interface ReanalysisSchedule {
  version: number; enabled: boolean; intervalMinutes: number; nextRunAt?: string | null;
  lastRunAt?: string | null; onDataUpdate: boolean; latestOnly: boolean;
  serviceIds: string[]; environmentIds: string[]; activeCycle?: ReanalysisCycle | null;
}
export type VexState = "in_triage" | "exploitable" | "not_affected" | "false_positive" | "resolved" | "resolved_with_pedigree";
export interface VexReviewInput {
  component: string; vulnerabilityId: string; state: VexState; justification?: string;
  detail: string; response: string[]; expiresAt?: string;
}
export interface VexReview extends VexReviewInput {
  id: string; status: "submitted" | "approved" | "rejected"; author: string; reviewer?: string;
  decisionReason?: string; createdAt: string; applied?: boolean; expired?: boolean;
}
export interface ReviewEvent { id: string; author?: string; actor?: string; type?: string; kind?: string; comment?: string; detail?: string; createdAt: string }
export interface InboxNotification { id: string; title?: string; message?: string; eventType?: string; kind?: string; read?: boolean; createdAt: string; readAt?: string | null }
export interface NotificationDelivery { id: string; status: string; attempts: number; error?: string | null; lastError?: string | null; createdAt: string; channel?: string; notificationId?: string }

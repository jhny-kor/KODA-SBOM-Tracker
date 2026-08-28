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
  base: { runId: string; sha256: string; dataAsOf: string | null; cveDataAsOf?: string | null; artifactUrl?: string };
  target: { runId: string; sha256: string; dataAsOf: string | null; cveDataAsOf?: string | null; artifactUrl?: string };
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

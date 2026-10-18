import type { ComponentChange, LdapSettings, RolePolicyCatalog, SbomRun } from "./types";

export const demoLdapSettings: LdapSettings = {
  enabled: true, host: "ldap.example.com", port: 636, tlsMode: "ldaps",
  verifyCertificate: true, caCertPath: "/run/secrets/ldap-ca.crt",
  bindDn: "CN=tracker-reader,OU=ServiceAccounts,DC=example,DC=com",
  baseDn: "OU=People,DC=example,DC=com",
  loginAttribute: "sAMAccountName", usernameAttribute: "sAMAccountName",
  subjectAttribute: "objectGUID", userFilter: "(sAMAccountName={username})",
  groupAttribute: "memberOf",
  groupMappings: { "CN=Security-Analysts,OU=Groups,DC=example,DC=com": "analyst", "CN=SBOM-Viewers,OU=Groups,DC=example,DC=com": "viewer" },
  autoProvision: true, defaultRole: "viewer", hasBindPassword: true, encryptionReady: true,
};

const permissions = [
  "dashboard.view", "services.view", "runs.view", "compare.view", "vulnerability.view", "audit.view", "settings.view",
  "sbom.upload", "artifact.download", "analysis.create", "dtrack.retry", "sbom.archive", "sbom.delete",
  "catalog.manage", "vulnerability.manage", "dtrack.settings", "users.manage", "tokens.manage", "roles.manage", "policies.view", "policies.manage",
];

export const demoRolePolicyCatalog: RolePolicyCatalog = {
  catalog: permissions,
  roles: [
    { role: "admin", permissions },
    { role: "manager", permissions: ["dashboard.view", "services.view", "runs.view", "compare.view", "settings.view", "sbom.upload", "artifact.download", "analysis.create", "dtrack.retry", "sbom.archive", "catalog.manage", "users.manage"] },
    { role: "analyst", permissions: ["dashboard.view", "services.view", "runs.view", "compare.view", "sbom.upload", "artifact.download", "analysis.create", "dtrack.retry"] },
    { role: "uploader", permissions: ["dashboard.view", "services.view", "runs.view", "compare.view", "sbom.upload", "artifact.download"] },
    { role: "viewer", permissions: ["dashboard.view", "services.view", "runs.view", "compare.view", "artifact.download"] },
  ],
};

const names = [
  ["결제 API", "운영", "1.4.2", 3, 1248, 7, 2, "completed"],
  ["회원 서비스", "검증", "2.1.0", 1, 842, 3, 0, "completed"],
  ["주문 서비스", "운영", "3.0.1", 5, 2105, 12, 1, "processing"],
  ["정산 배치", "운영", "1.2.3", 2, 612, 1, 0, "completed"],
  ["알림 서비스", "검증", "1.7.0", 4, 1130, 5, 1, "partial"],
  ["프론트엔드 웹", "운영", "2.5.3", 6, 1568, 0, 0, "completed"],
  ["검색 서비스", "검증", "1.0.0", 1, 487, 2, 0, "completed"],
  ["보고서 API", "운영", "1.1.4", 2, 734, 4, 1, "completed"],
  ["데이터 수집기", "검증", "0.9.8", 3, 399, 0, 0, "processing"],
  ["모바일 앱", "운영", "3.2.0", 7, 2023, 9, 3, "partial"],
  ["권한 서비스", "운영", "1.3.0", 2, 556, 1, 0, "completed"],
  ["로그 수집기", "운영", "2.0.1", 4, 613, 2, 0, "completed"],
  ["파일 변환 서비스", "검증", "1.0.5", 2, 294, 1, 0, "completed"],
  ["메일 발송 서비스", "운영", "1.6.2", 3, 721, 3, 1, "completed"],
  ["배치 스케줄러", "운영", "1.0.2", 1, 312, 0, 0, "completed"],
  ["캐시 서비스", "검증", "2.2.1", 2, 441, 1, 0, "completed"],
  ["인증 서비스", "운영", "1.8.0", 5, 982, 6, 2, "partial"],
  ["지표 수집기", "검증", "0.7.5", 3, 258, 0, 0, "completed"],
] as const;

export const demoRuns: SbomRun[] = names.map((value, index) => ({
  id: `run-${index + 1}`,
  service: { id: `svc-${index + 1}`, name: value[0], slug: `service-${index + 1}` },
  environment: { id: value[1] === "운영" ? "prod" : "qa", name: value[1], slug: value[1] === "운영" ? "prod" : "qa" },
  releaseVersion: value[2],
  roundNumber: value[3],
  componentCount: value[4],
  vulnerabilityCount: value[5],
  vulnerableComponentCount: Math.ceil(value[5] / 2),
  componentTypeCounts: { library: value[4] },
  policyViolationCount: value[6],
  policyState: value[7] === "processing" ? "not_evaluated" : "completed",
  policyStatus: value[7] === "processing" ? "not_evaluated" : value[6] ? "fail" : "pass",
  policyVersion: value[7] === "processing" ? null : 1,
  dependencyTrackEnabled: false,
  policyViolations: Array.from({ length: value[6] }, (_, i) => ({ policyId: "critical-high", policyName: "Critical·High 취약점", component: `샘플 구성요소 ${i + 1}`, vulnerabilityId: `CVE-2025-DEMO-${i + 1}`, type: "SECURITY", action: "fail", reason: "샘플 정책 평가 결과", suppressed: false })),
  state: value[7],
  dataAsOf: index < 3 ? "2025-05-21" : `2025-05-${String(Math.max(13, 20 - Math.floor(index / 2))).padStart(2, "0")}`,
  createdAt: `2025-05-${String(Math.max(13, 21 - Math.floor(index / 2))).padStart(2, "0")}T${String(9 + (index % 8)).padStart(2, "0")}:${String((15 + index * 3) % 60).padStart(2, "0")}:00Z`,
  sha256: `${String(index + 1).padStart(2, "0")}b6f0d8c3e2a9f4c1c3b1a7d5e6f8a9b0d1c2e3f4a5b6c7d8e9f0011223344`,
  specVersion: "1.6",
  filename: `${value[0]}-${value[2]}.cdx.json`,
}));

export const demoChanges: ComponentChange[] = [
  ["added", [], "purl:jackson", "com.fasterxml.jackson.core:jackson-databind", "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.1", undefined, "2.17.1"],
  ["removed", [], "purl:slf4j", "org.slf4j:slf4j-log4j12", "pkg:maven/org.slf4j/slf4j-log4j12@1.7.30", "1.7.30", undefined],
  ["changed", ["version"], "purl:httpclient", "org.apache.httpcomponents:httpclient", "pkg:maven/org.apache.httpcomponents/httpclient@4.5.14", "4.5.14", "4.5.14.1"],
  ["changed", ["version"], "purl:netty", "io.netty:netty-handler", "pkg:maven/io.netty/netty-handler@4.1.109.Final", "4.1.100.Final", "4.1.109.Final"],
  ["changed", ["sha256"], "purl:dtrack", "org.owasp:dependency-check-core", "pkg:maven/org.owasp/dependency-check-core@9.0.9", "9.0.9", "9.0.9"],
  ["added", [], "purl:text", "org.apache.commons:commons-text", "pkg:maven/org.apache.commons/commons-text@1.11.0", undefined, "1.11.0"],
  ["changed", ["version"], "purl:logback", "ch.qos.logback:logback-classic", "pkg:maven/ch.qos.logback/logback-classic@1.4.14", "1.2.11", "1.4.14"],
  ["removed", [], "purl:logging", "commons-logging:commons-logging", "pkg:maven/commons-logging/commons-logging@1.2", "1.2", undefined],
  ["added", [], "purl:yaml", "org.yaml:snakeyaml", "pkg:maven/org.yaml/snakeyaml@2.2", undefined, "2.2"],
  ["changed", ["version"], "purl:annotations", "com.fasterxml.jackson.core:jackson-annotations", "pkg:maven/com.fasterxml.jackson.core/jackson-annotations@2.17.1", "2.15.2", "2.17.1"],
].map((item, index) => ({
  change: item[0] as ComponentChange["change"],
  fields: item[1] as string[],
  identityKey: item[2] as string,
  name: item[3] as string,
  purl: item[4] as string,
  baseVersion: item[5] as string | undefined,
  targetVersion: item[6] as string | undefined,
  baseSha256: `${index}c3b1a7d5e6f8a9b0d1c2e3f4a5b6c7d8e9f0`,
  targetSha256: `${index}d4c2b1a9f8e7d6c5b4a3928171625344556677889`,
}));

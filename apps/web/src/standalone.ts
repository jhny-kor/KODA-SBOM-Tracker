import type { AnalysisRevisionSummary, CatalogItem, Comparison, ComponentChange, ComponentSnapshot, SbomRun, SbomRunDetail } from "./types";

type JsonObject = Record<string, unknown>;

export const standaloneService: CatalogItem = { id: "standalone-service", name: "로컬 미리보기", slug: "local-preview", active: true };
export const standaloneEnvironment: CatalogItem = { id: "standalone-environment", name: "미리보기", slug: "preview", sortOrder: 0 };

const storedRuns = new Map<string, SbomRunDetail>();
let sequence = 0;

function object(value: unknown): JsonObject {
  return value && typeof value === "object" && !Array.isArray(value) ? value as JsonObject : {};
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function text(value: unknown): string {
  return typeof value === "string" || typeof value === "number" ? String(value) : "";
}

function child(element: Element, name: string): Element | undefined {
  return Array.from(element.children).find((item) => item.localName === name);
}

function childText(element: Element, name: string): string {
  return child(element, name)?.textContent?.trim() || "";
}

function descendants(root: Document | Element, name: string): Element[] {
  return Array.from(root.getElementsByTagName("*")).filter((item) => item.localName === name);
}

function componentFromJson(value: unknown, index: number): ComponentSnapshot {
  const item = object(value);
  const group = text(item.group);
  const name = text(item.name) || text(item["bom-ref"]) || `component-${index + 1}`;
  const version = text(item.version);
  const purl = text(item.purl);
  const bomRef = text(item["bom-ref"]);
  const hashes = list(item.hashes).map(object);
  const sha256 = text(hashes.find((hash) => text(hash.alg).toLowerCase().replace(/[-_]/g, "") === "sha256")?.content);
  const identityKey = purl || bomRef || [group, name, version].filter(Boolean).join(":");
  return {
    identityKey: identityKey || `component-${index + 1}`,
    identityStatus: "stable",
    componentType: text(item.type) || "library",
    group,
    name,
    version,
    purl,
    bomRef,
    sha256,
    licenses: list(item.licenses),
    properties: Array.isArray(item.properties) ? item.properties : {},
  };
}

function vulnerabilityFromJson(value: unknown): Record<string, unknown> {
  const item = object(value);
  const source = object(item.source);
  const ratings = list(item.ratings).map(object);
  const affects = list(item.affects).map(object);
  const id = text(item.id) || text(source.id) || text(item["bom-ref"]);
  const severity = text(ratings[0]?.severity) || text(item.severity) || "UNKNOWN";
  const component = text(affects[0]?.ref) || text(item.component);
  return { ...item, id, canonicalId: id, severity, component, kev: item.kev === true || item.knownExploited === true };
}

function componentFromXml(element: Element, index: number): ComponentSnapshot {
  const group = childText(element, "group");
  const name = childText(element, "name") || `component-${index + 1}`;
  const version = childText(element, "version");
  const purl = childText(element, "purl");
  const bomRef = element.getAttribute("bom-ref") || "";
  const licensesNode = child(element, "licenses");
  const licenses = licensesNode
    ? Array.from(licensesNode.children).filter((item) => item.localName === "license").map((license) => ({ license: { id: childText(license, "id"), name: childText(license, "name") } }))
    : [];
  const propertiesNode = child(element, "properties");
  const properties = propertiesNode
    ? Array.from(propertiesNode.children).filter((item) => item.localName === "property").map((property) => ({ name: property.getAttribute("name") || "", value: property.textContent?.trim() || "" }))
    : [];
  const identityKey = purl || bomRef || [group, name, version].filter(Boolean).join(":");
  return {
    identityKey: identityKey || `component-${index + 1}`,
    identityStatus: "stable",
    componentType: element.getAttribute("type") || "library",
    group,
    name,
    version,
    purl,
    bomRef,
    sha256: "",
    licenses,
    properties,
  };
}

function vulnerabilityFromXml(element: Element): Record<string, unknown> {
  const id = element.getAttribute("id") || childText(element, "id");
  const rating = child(child(element, "ratings") || element, "rating");
  const severity = rating ? childText(rating, "severity") : "UNKNOWN";
  const target = descendants(element, "target")[0];
  return { id, canonicalId: id, severity: severity || "UNKNOWN", component: target?.getAttribute("ref") || "", kev: false };
}

function parseBom(raw: string): { specVersion: string; dataAsOf: string; components: ComponentSnapshot[]; vulnerabilities: Record<string, unknown>[] } {
  if (raw.trimStart().startsWith("<")) {
    const document = new DOMParser().parseFromString(raw, "application/xml");
    if (document.getElementsByTagName("parsererror").length || document.documentElement.localName !== "bom") {
      throw new Error("유효한 CycloneDX XML이 아닙니다.");
    }
    const namespaceVersion = document.documentElement.namespaceURI?.match(/bom\/(\d+\.\d+)/)?.[1];
    const timestamp = descendants(document, "timestamp")[0]?.textContent?.trim() || "";
    return {
      specVersion: document.documentElement.getAttribute("version") || namespaceVersion || "unknown",
      dataAsOf: timestamp.slice(0, 10),
      components: descendants(document, "component").map(componentFromXml),
      vulnerabilities: descendants(document, "vulnerability").map(vulnerabilityFromXml),
    };
  }

  let payload: JsonObject;
  try {
    payload = object(JSON.parse(raw));
  } catch {
    throw new Error("유효한 CycloneDX JSON이 아닙니다.");
  }
  if (payload.bomFormat !== "CycloneDX") {
    throw new Error("CycloneDX SBOM만 업로드할 수 있습니다.");
  }
  const metadata = object(payload.metadata);
  return {
    specVersion: text(payload.specVersion) || "unknown",
    dataAsOf: text(metadata.timestamp).slice(0, 10),
    components: list(payload.components).map(componentFromJson),
    vulnerabilities: list(payload.vulnerabilities).map(vulnerabilityFromJson),
  };
}

function fallbackFingerprint(raw: string): string {
  let hash = 2166136261;
  for (let index = 0; index < raw.length; index += 1) hash = Math.imul(hash ^ raw.charCodeAt(index), 16777619);
  return `preview-${(hash >>> 0).toString(16).padStart(8, "0")}`;
}

async function fingerprint(raw: string): Promise<string> {
  if (globalThis.crypto?.subtle && globalThis.TextEncoder) {
    const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw));
    return Array.from(new Uint8Array(digest), (value) => value.toString(16).padStart(2, "0")).join("");
  }
  return fallbackFingerprint(raw);
}

export async function parseStandaloneSbom(raw: string, filename: string, releaseVersion = "preview"): Promise<SbomRunDetail> {
  if (!raw.trim()) throw new Error("SBOM 파일이 비어 있습니다.");
  const parsed = parseBom(raw);
  const createdAt = new Date().toISOString();
  const id = `standalone-${Date.now()}-${sequence += 1}`;
  const dataAsOf = parsed.dataAsOf || createdAt.slice(0, 10);
  const run: SbomRun = {
    id,
    service: standaloneService,
    environment: standaloneEnvironment,
    releaseVersion: releaseVersion.trim() || "preview",
    roundNumber: 1,
    state: "completed",
    sha256: await fingerprint(raw),
    componentCount: parsed.components.length,
    vulnerabilityCount: parsed.vulnerabilities.length,
    policyViolationCount: 0,
    dataAsOf,
    createdAt,
    filename,
    specVersion: parsed.specVersion,
    analysisState: "completed",
    analysisDataSources: { mode: "standalone-preview", source: "CycloneDX embedded records" },
  };
  const analysis: AnalysisRevisionSummary = {
    id: `${id}-analysis-1`,
    sequence: 1,
    state: "completed",
    dataAsOf,
    toolVersion: "standalone-preview",
    dataSources: { mode: "standalone-preview", source: "CycloneDX embedded records" },
    findings: parsed.vulnerabilities,
  };
  return { ...run, components: parsed.components, analyses: [analysis] };
}

export async function importStandaloneSbom(file: File, releaseVersion?: string): Promise<{ runId: string; jobId: string }> {
  if (file.size > 25 * 1024 * 1024) throw new Error("SBOM 파일은 25 MiB 이하만 업로드할 수 있습니다.");
  const detail = await parseStandaloneSbom(await file.text(), file.name, releaseVersion);
  storedRuns.set(detail.id, detail);
  return { runId: detail.id, jobId: `${detail.id}-job` };
}

export function getStandaloneRuns(): SbomRun[] {
  return [...storedRuns.values()].map((detail) => {
    const run = { ...detail } as Partial<SbomRunDetail>;
    delete run.components;
    delete run.analyses;
    return run as SbomRun;
  }).reverse();
}

export function getStandaloneRun(id: string): SbomRunDetail | undefined {
  return storedRuns.get(id);
}

export function getStandaloneCatalogs(): { services: CatalogItem[]; environments: CatalogItem[] } {
  return { services: [standaloneService], environments: [standaloneEnvironment] };
}

export function compareStandaloneRuns(baseId: string, targetId: string): Comparison {
  const base = storedRuns.get(baseId);
  const target = storedRuns.get(targetId);
  if (!base || !target) throw new Error("standalone 미리보기 회차를 찾을 수 없습니다.");
  const baseComponents = new Map(base.components.map((component) => [component.identityKey, component]));
  const targetComponents = new Map(target.components.map((component) => [component.identityKey, component]));
  const components: ComponentChange[] = [];
  for (const [identityKey, component] of targetComponents) {
    const previous = baseComponents.get(identityKey);
    if (!previous) {
      components.push({ change: "added", fields: [], identityKey, name: component.name, purl: component.purl || "", targetVersion: component.version || undefined, targetSha256: component.sha256 || undefined, componentType: component.componentType, group: component.group, bomRef: component.bomRef });
      continue;
    }
    const fields = [
      previous.version !== component.version ? "version" : "",
      previous.sha256 !== component.sha256 ? "sha256" : "",
      JSON.stringify(previous.licenses) !== JSON.stringify(component.licenses) ? "licenses" : "",
    ].filter(Boolean);
    if (fields.length) components.push({ change: "changed", fields, identityKey, name: component.name, purl: component.purl || "", baseVersion: previous.version || undefined, targetVersion: component.version || undefined, baseSha256: previous.sha256 || undefined, targetSha256: component.sha256 || undefined, componentType: component.componentType, group: component.group, bomRef: component.bomRef });
  }
  for (const [identityKey, component] of baseComponents) {
    if (!targetComponents.has(identityKey)) components.push({ change: "removed", fields: [], identityKey, name: component.name, purl: component.purl || "", baseVersion: component.version || undefined, baseSha256: component.sha256 || undefined, componentType: component.componentType, group: component.group, bomRef: component.bomRef });
  }
  const baseFindings = new Map((base.analyses[0]?.findings || []).map((finding) => [String(finding.id || finding.canonicalId), finding]));
  const targetFindings = new Map((target.analyses[0]?.findings || []).map((finding) => [String(finding.id || finding.canonicalId), finding]));
  const vulnerabilities: Comparison["vulnerabilities"] = [];
  for (const [id, finding] of targetFindings) if (!baseFindings.has(id)) vulnerabilities.push({ change: "added", record: finding });
  for (const [id, finding] of baseFindings) if (!targetFindings.has(id)) vulnerabilities.push({ change: "removed", record: finding });
  return {
    base: { runId: base.id, sha256: base.sha256, dataAsOf: base.dataAsOf },
    target: { runId: target.id, sha256: target.sha256, dataAsOf: target.dataAsOf },
    summary: {
      componentsAdded: components.filter((item) => item.change === "added").length,
      componentsRemoved: components.filter((item) => item.change === "removed").length,
      componentsChanged: components.filter((item) => item.change === "changed").length,
      vulnerabilitiesAdded: vulnerabilities.filter((item) => item.change === "added").length,
      vulnerabilitiesRemoved: vulnerabilities.filter((item) => item.change === "removed").length,
      policiesChanged: 0,
    },
    components,
    vulnerabilities,
    policies: [],
  };
}

export function resetStandaloneStore() {
  storedRuns.clear();
  sequence = 0;
}

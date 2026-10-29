import { demoMode, request, standaloneMode } from "./api";
export interface LibrarySummary {
    key: string;
    coordinate: string;
    name: string;
    ecosystem: string;
    versions: string[];
    currentVersions: string[];
    serviceCount: number;
    currentServiceCount: number;
    currentEnvironmentCount: number;
    environments: {
        id: string;
        name: string;
    }[];
    lastObservedAt: string;
    observationCount: number;
}
export interface LibraryObservation {
    name?: string;
    runId: string;
    at: string;
    roundNumber: number;
    service: {
        id: string;
        name: string;
    };
    environment: {
        id: string;
        name: string;
    };
    releaseVersion: string;
    libraryVersion: string;
    purl: string;
    bomRef: string;
    state: string;
    current: boolean;
    archived: boolean;
    identityStatus: string;
}
export interface LibraryEvent {
    kind: string;
    runId: string;
    at: string;
    roundNumber: number;
    service: {
        id: string;
        name: string;
    };
    environment: {
        id: string;
        name: string;
    };
    releaseVersion: string;
    versions: string[];
    previousVersions: string[];
    previousRunId: string | null;
    reliable: boolean;
}
export interface LibraryDetail {
    key: string;
    coordinate: string;
    name: string;
    ecosystem: string;
    observations: LibraryObservation[];
    historicalObservations: LibraryObservation[];
    observationsTotal: number;
    history: {
        items: LibraryEvent[];
        total: number;
        page: number;
        size: number;
    };
    vulnerabilities: {
        id: string;
        severity: string;
        runId: string;
        analysisId: string;
        dataAsOf: string;
        matchBasis: string;
        current: boolean;
        analysisCurrent?: boolean;
        evaluationState?: "completed" | "reanalysis_required";
    }[];
    vulnerabilitiesTruncated?: boolean;
    vulnerabilityCoverage?: { runLimit: number; recordLimit: number; matchingRuns: number; runsInScope: number };
    basis: string;
    notice: string;
}
export interface LibraryQuery {
    q?: string;
    environmentId?: string;
    ecosystem?: string;
    version?: string;
    page?: number;
    size?: number;
}
export interface LibraryPage {
    items: LibrarySummary[];
    total: number;
    page: number;
    size: number;
    basis: string;
    filters: {
        environments: {
            id: string;
            name: string;
        }[];
        ecosystems: string[];
    };
}
const sampleEnvironments = [{ id: "prod", name: "운영" }, { id: "qa", name: "검증" }];
const sampleNames = ["sample-json", "sample-http", "sample-utils"];
const samples: LibrarySummary[] = sampleNames.map((name, index) => ({
    key: `sample-${index}`, coordinate: `pkg:npm/${name}`, name, ecosystem: "npm", versions: index === 0 ? ["1.4.0", "1.4.2"] : ["2.0.1"],
    currentVersions: index === 0 ? ["1.4.0", "1.4.2"] : ["2.0.1"], serviceCount: 3, currentServiceCount: 3, currentEnvironmentCount: 2,
    environments: sampleEnvironments, lastObservedAt: "2026-10-29T00:20:00Z", observationCount: 6,
}));
function sampleDetail(key: string): LibraryDetail {
    const summary = samples.find(item => item.key === key);
    if (!summary)
        throw new Error("라이브러리를 찾을 수 없습니다.");
    const oldVersion = summary.versions[0], latestVersion = summary.versions[summary.versions.length - 1];
    const observations: LibraryObservation[] = [
        { service: { id: "svc-1", name: "결제 API" }, environment: sampleEnvironments[0], releaseVersion: "2026.10.2", libraryVersion: latestVersion, runId: "run-1" },
        { service: { id: "svc-2", name: "회원 API" }, environment: sampleEnvironments[1], releaseVersion: "2026.10.2", libraryVersion: latestVersion, runId: "run-2" },
        { service: { id: "svc-4", name: "정산 배치" }, environment: sampleEnvironments[0], releaseVersion: "2026.10.1", libraryVersion: oldVersion, runId: "run-4" },
    ].map((item, index) => ({ ...item, name: summary.name, purl: `${summary.coordinate}@${item.libraryVersion}`, at: `2026-10-${29 - index}T00:20:00Z`, roundNumber: index === 0 ? 4 : 3, bomRef: "", state: "completed", current: true, archived: false, identityStatus: "identified" }));
    const history: LibraryEvent[] = [
        { kind: oldVersion === latestVersion ? "observed" : "version_changed", versions: [latestVersion], previousVersions: [oldVersion], at: "2026-10-29T00:20:00Z", releaseVersion: "2026.10.2", roundNumber: 4 },
        { kind: "observed", versions: [oldVersion], previousVersions: [oldVersion], at: "2026-10-22T06:10:00Z", releaseVersion: "2026.10.1", roundNumber: 3 },
        { kind: "first_seen", versions: [oldVersion], previousVersions: [], at: "2026-10-15T02:00:00Z", releaseVersion: "2026.10.1", roundNumber: 1 },
    ].map(item => ({ ...item, runId: "run-1", previousRunId: null, service: observations[0].service, environment: observations[0].environment, reliable: true }));
    return { ...summary, observations, historicalObservations: observations, observationsTotal: 6, history: { items: history, total: 3, page: 1, size: 20 },
        vulnerabilities: [{ id: "CVE-2026-00001 (가상)", severity: "High", runId: "run-4", analysisId: "sample-analysis", dataAsOf: "2026-10-29", matchBasis: "purl", current: true }],
        basis: "latest_completed_sbom_per_service_environment", notice: "최신 완료 SBOM 관측 기준입니다. 미수집·불완전 SBOM의 부재를 제거로 판단하지 않습니다." };
}
export async function fetchLibraries(query: LibraryQuery = {}): Promise<LibraryPage> {
    if (demoMode) {
        const items = samples.filter(item => (!query.q || `${item.name} ${item.coordinate}`.includes(query.q.toLowerCase())) && (!query.ecosystem || item.ecosystem === query.ecosystem) && (!query.version || item.versions.includes(query.version))).map(item => {
            if (!query.environmentId)
                return item;
            const observations = sampleDetail(item.key).observations.filter(value => value.environment.id === query.environmentId);
            return { ...item, currentVersions: [...new Set(observations.map(value => value.libraryVersion))], currentServiceCount: observations.length, currentEnvironmentCount: observations.length ? 1 : 0, environments: item.environments.filter(value => value.id === query.environmentId) };
        });
        const page = query.page || 1, size = query.size || 20;
        return { items: items.slice((page - 1) * size, page * size), total: items.length, page, size, basis: "sample", filters: { environments: sampleEnvironments, ecosystems: ["npm"] } };
    }
    if (standaloneMode)
        return { items: [], total: 0, page: 1, size: 20, basis: "standalone_unavailable", filters: { environments: [], ecosystems: [] } };
    const parameters = new URLSearchParams();
    Object.entries(query).forEach(([key, value]) => { if (value !== undefined && value !== "")
        parameters.set(key, String(value)); });
    return request<LibraryPage>(`/api/v1/libraries?${parameters}`);
}
export async function fetchLibrary(key: string, environmentId = "", page = 1, size = 20): Promise<LibraryDetail> {
    if (demoMode) {
        const result = sampleDetail(key);
        if (environmentId) {
            result.observations = result.observations.filter(item => item.environment.id === environmentId);
            result.historicalObservations = result.historicalObservations.filter(item => item.environment.id === environmentId);
            result.history.items = result.history.items.filter(item => item.environment.id === environmentId);
            result.history.total = result.history.items.length;
        }
        result.history = { ...result.history, items: result.history.items.slice((page - 1) * size, page * size), page, size };
        return result;
    }
    return request<LibraryDetail>(`/api/v1/libraries/detail?${new URLSearchParams({ key, environmentId, page: String(page), size: String(size) })}`);
}

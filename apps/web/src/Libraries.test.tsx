import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import LibrariesPage from "./Libraries";
import * as api from "./library-api";
import type { LibraryDetail, LibraryPage } from "./library-api";
vi.mock("./api", () => ({ demoMode: false, standaloneMode: false }));
vi.mock("./library-api", () => ({ fetchLibraries: vi.fn(), fetchLibrary: vi.fn() }));
const row = { key: "json", coordinate: "pkg:npm/sample-json", name: "sample-json", ecosystem: "npm", versions: ["1.4.0", "1.4.2"], currentVersions: ["1.4.2"], serviceCount: 1, currentServiceCount: 1, currentEnvironmentCount: 1, environments: [{ id: "prod", name: "운영" }], lastObservedAt: "2026-10-29T00:20:00Z", observationCount: 2 };
const page: LibraryPage = { items: [row], total: 1, page: 1, size: 20, basis: "latest_completed_sbom_per_service_environment", filters: { environments: [{ id: "prod", name: "운영" }], ecosystems: ["npm"] } };
const observation = { runId: "run-new", at: "2026-10-29T00:20:00Z", roundNumber: 4, service: { id: "service", name: "결제 API" }, environment: { id: "prod", name: "운영" }, releaseVersion: "2026.10.2", libraryVersion: "1.4.2", purl: "pkg:npm/sample-json@1.4.2", bomRef: "", state: "completed", current: true, archived: false, identityStatus: "identified" };
const detail: LibraryDetail = { key: "json", coordinate: row.coordinate, name: row.name, ecosystem: "npm", observations: [observation], historicalObservations: [observation], observationsTotal: 2, history: { items: [{ kind: "version_changed", runId: "run-new", at: observation.at, roundNumber: 4, service: observation.service, environment: observation.environment, releaseVersion: "2026.10.2", versions: ["1.4.2"], previousVersions: ["1.4.0"], previousRunId: "run-old", reliable: true }], total: 1, page: 1, size: 20 }, vulnerabilities: [{ id: "CVE-2026-12345", severity: "High", runId: "run-new", analysisId: "a", dataAsOf: "2026-10-29", matchBasis: "purl", current: true }], basis: "latest", notice: "SBOM 기준" };
afterEach(cleanup);
beforeEach(() => { vi.resetAllMocks(); vi.mocked(api.fetchLibraries).mockResolvedValue(page); vi.mocked(api.fetchLibrary).mockResolvedValue(detail); });
describe("library inventory", () => {
    it("discloses the related-evidence coverage cap without hiding full history", async () => {
        vi.mocked(api.fetchLibrary).mockResolvedValue({ ...detail, vulnerabilitiesTruncated: true, vulnerabilityCoverage: { runLimit: 1000, recordLimit: 200, matchingRuns: 1200, runsInScope: 1000 } });
        render(<LibrariesPage />);
        await screen.findByRole("table", { name: "라이브러리 보유 환경" });
        fireEvent.click(screen.getByRole("tab", { name: "연관 취약점" }));
        expect(screen.getByRole("note")).toHaveTextContent("최근 관측 회차 최대 1000개, 발견 근거 최대 200건");
        expect(screen.getByRole("note")).toHaveTextContent("전체 이력이 아니며");
        fireEvent.click(screen.getByRole("tab", { name: "변경 이력" }));
        expect(screen.getByText("1.4.0 → 1.4.2")).toBeInTheDocument();
    });
    it("labels preserved old findings as reanalysis required after scope changes", async () => {
        vi.mocked(api.fetchLibrary).mockResolvedValue({ ...detail, vulnerabilities: [{ ...detail.vulnerabilities[0], current: false, analysisCurrent: false, evaluationState: "reanalysis_required" }] });
        render(<LibrariesPage />);
        await screen.findByRole("table", { name: "라이브러리 보유 환경" });
        fireEvent.click(screen.getByRole("tab", { name: "연관 취약점" }));
        expect(screen.getByText("과거 분석 · 재분석 필요")).toBeInTheDocument();
        expect(screen.queryByText("최신 관측", { exact: true })).not.toBeInTheDocument();
    });
    it("does not label a present component with an unspecified version as absent", async () => {
        vi.mocked(api.fetchLibrary).mockResolvedValue({ ...detail, history: { ...detail.history, items: [{ ...detail.history.items[0], kind: "first_seen", versions: [""], previousVersions: [] }] } });
        render(<LibrariesPage />);
        await screen.findByRole("table", { name: "라이브러리 보유 환경" });
        fireEvent.click(screen.getByRole("tab", { name: "변경 이력" }));
        expect(screen.getByText("버전 미기재")).toBeInTheDocument();
        expect(screen.queryByText("구성요소 부재 확인")).not.toBeInTheDocument();
    });
    it("separates release and package version and navigates to the evidence run", async () => {
        const onOpenRun = vi.fn();
        render(<LibrariesPage onOpenRun={onOpenRun}/>);
        const table = await screen.findByRole("table", { name: "라이브러리 보유 환경" });
        expect(within(table).getByRole("cell", { name: "2026.10.2" })).toBeInTheDocument();
        expect(within(table).getByRole("cell", { name: "1.4.2" })).toBeInTheDocument();
        fireEvent.click(within(table).getByRole("button", { name: "SBOM 4차" }));
        expect(onOpenRun).toHaveBeenCalledWith("run-new");
        expect(screen.getByText(/실제 서버의 현재 배포 상태를 의미하지 않/)).toBeInTheDocument();
    });
    it("searches and filters through paginated API queries", async () => {
        render(<LibrariesPage initialQuery="sample"/>);
        await screen.findByRole("table", { name: "라이브러리 보유 환경" });
        fireEvent.change(screen.getByLabelText("라이브러리 환경"), { target: { value: "prod" } });
        fireEvent.change(screen.getByLabelText("라이브러리 버전"), { target: { value: "1.4.2" } });
        await waitFor(() => expect(api.fetchLibraries).toHaveBeenLastCalledWith(expect.objectContaining({ q: "sample", environmentId: "prod", version: "1.4.2", page: 1 })));
        fireEvent.click(screen.getByRole("button", { name: "초기화" }));
        await waitFor(() => expect(api.fetchLibraries).toHaveBeenLastCalledWith(expect.objectContaining({ q: "", environmentId: "", version: "" })));
    });
    it("defaults to ten rows and returns to page one when the row count changes", async () => {
        vi.mocked(api.fetchLibraries).mockResolvedValue({ ...page, total: 42 });
        render(<LibrariesPage />);
        const size = screen.getByRole("combobox", { name: "라이브러리 목록 페이지당 행 수" });
        expect(size).toHaveValue("10");
        await waitFor(() => expect(api.fetchLibraries).toHaveBeenLastCalledWith(expect.objectContaining({ page: 1, size: 10 })));
        fireEvent.click(await screen.findByRole("button", { name: "라이브러리 목록 다음 페이지" }));
        await waitFor(() => expect(api.fetchLibraries).toHaveBeenLastCalledWith(expect.objectContaining({ page: 2, size: 10 })));
        fireEvent.change(size, { target: { value: "25" } });
        await waitFor(() => expect(api.fetchLibraries).toHaveBeenLastCalledWith(expect.objectContaining({ page: 1, size: 25 })));
    });
    it("exposes historical evidence and related findings via accessible tabs", async () => {
        render(<LibrariesPage />);
        await screen.findByRole("table", { name: "라이브러리 보유 환경" });
        fireEvent.click(screen.getByRole("tab", { name: "변경 이력" }));
        expect(screen.getByText("1.4.0 → 1.4.2")).toBeInTheDocument();
        expect(screen.getByRole("link", { name: "회차 비교" })).toHaveAttribute("href", "/?page=compare&baseRunId=run-old&targetRunId=run-new");
        fireEvent.click(screen.getByRole("tab", { name: "연관 취약점" }));
        expect(screen.getByRole("table", { name: "라이브러리 연관 취약점" })).toHaveTextContent("CVE-2026-12345");
    });
    it("does not misrepresent failed loading as an empty successful catalog", async () => {
        vi.mocked(api.fetchLibraries).mockRejectedValue(new Error("권한을 확인할 수 없습니다"));
        render(<LibrariesPage />);
        expect(await screen.findByRole("alert")).toHaveTextContent("권한을 확인할 수 없습니다");
        expect(screen.queryByText("조건에 맞는 라이브러리가 없습니다.")).not.toBeInTheDocument();
    });
    it("preserves archived history without claiming current inventory", async () => {
        vi.mocked(api.fetchLibraries).mockResolvedValue({ ...page, items: [{ ...row, currentVersions: [], currentServiceCount: 0 }] });
        vi.mocked(api.fetchLibrary).mockResolvedValue({ ...detail, observations: [] });
        render(<LibrariesPage />);
        expect(await screen.findByText(/최신 완료 SBOM에서 관측되지 않았습니다/)).toBeInTheDocument();
        expect(screen.getByText("현재 관측 없음")).toBeInTheDocument();
    });
    it("ignores stale detail responses after selection changes", async () => {
        let resolveOld!: (value: LibraryDetail) => void;
        vi.mocked(api.fetchLibraries).mockResolvedValue({ ...page, items: [row, { ...row, key: "http", name: "sample-http" }] });
        vi.mocked(api.fetchLibrary).mockImplementation(key => key === "json" ? new Promise(resolve => { resolveOld = resolve; }) : Promise.resolve({ ...detail, key: "http", name: "sample-http", coordinate: "pkg:npm/sample-http" }));
        render(<LibrariesPage />);
        const httpRow = (await screen.findByRole("button", { name: "sample-http" })).closest("tr")!;
        fireEvent.click(within(httpRow).getAllByRole("cell")[2]);
        expect(await screen.findByRole("heading", { name: "sample-http" })).toBeInTheDocument();
        resolveOld(detail);
        await waitFor(() => expect(screen.queryByRole("heading", { name: "sample-json" })).not.toBeInTheDocument());
    });
});

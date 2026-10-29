import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import CveSearchPanel from "./CveSearch";
import { fetchCveCatalog, fetchCveDetail, type CveCatalogDetail, type CveCatalogPage } from "./cve-search-api";

vi.mock("./api", () => ({ previewMode: false }));
vi.mock("./cve-search-api", async original => ({ ...await original<typeof import("./cve-search-api")>(), fetchCveCatalog: vi.fn(), fetchCveDetail: vi.fn() }));
const product = { source: "cna" as const, sourceIdentifier: "issuer@example.test", vendor: "vendor", product: "example-json", condition: "발행기관 공지", ranges: [{ label: "1.0.0 이상 · 1.4.2 미만", status: "affected", versionType: "semver" }] };
const row = { id: "CVE-2026-10001", description: "Example description", status: "Analyzed", cvss: 8.1, products: [product], published: "2026-10-25", lastModified: "2026-10-29", versionMatch: "unknown" as const };
const page: CveCatalogPage = { state: "ready", bundleVersion: "one", dataAsOf: "2026-10-29", source: "승인 자료", items: [row], total: 21, page: 1, size: 20, versionSearchNote: "조건 불충분 시 확인 필요" };
const detail: CveCatalogDetail = { ...row, bundleVersion: "one", dataAsOf: "2026-10-29", affected: [], configurations: [], weaknesses: [], references: ["https://example.test/advisory"], applicabilityNote: "범위 상한을 수정 버전으로 단정하지 않습니다.", observations: { available: true, truncated: false, items: [{ runId: "run", service: "결제 API", environment: "운영", release: "2026.10.1", component: "example-json", version: "1.4.0", observedAt: "2026-10-29T00:20:00Z", analysisState: "completed", dataAsOf: "2026-10-29" }] } };

beforeEach(() => { vi.mocked(fetchCveCatalog).mockResolvedValue(structuredClone(page)); vi.mocked(fetchCveDetail).mockResolvedValue(structuredClone(detail)); });
afterEach(() => { cleanup(); vi.clearAllMocks(); });

it("searches software and version, switches source, and opens stored SBOM evidence", async () => {
  const onOpenRun = vi.fn(); render(<CveSearchPanel onOpenRun={onOpenRun}/>);
  await screen.findByText("Example description");
  expect(screen.getByText("제공 출처: issuer@example.test")).toBeInTheDocument();
  expect(screen.getByText("1.4.0")).toBeInTheDocument();
  expect(screen.getByText("2026.10.1")).toBeInTheDocument();
  expect(screen.getByText("버전·환경 조건 확인 필요")).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("CVE 소프트웨어명"), { target: { value: "example-json" } });
  fireEvent.change(screen.getByLabelText("CVE 검색 버전"), { target: { value: "1.4.0" } });
  fireEvent.click(screen.getByRole("button", { name: "검색" }));
  await waitFor(() => expect(fetchCveCatalog).toHaveBeenLastCalledWith({ q: "", vendor: "", product: "example-json", version: "1.4.0" }, 1));
  fireEvent.click(await screen.findByRole("tab", { name: "NVD 분석 조건" }));
  expect(screen.getByRole("tabpanel", { name: "NVD 분석 조건" })).toHaveTextContent("보존된 제품·버전 정보가 없습니다");
  fireEvent.click(screen.getByRole("button", { name: "SBOM 회차 보기" })); expect(onOpenRun).toHaveBeenCalledWith("run");
});

it("paginates and clearly distinguishes unavailable data from no CVEs", async () => {
  render(<CveSearchPanel/>); await screen.findByText("Example description");
  fireEvent.click(screen.getByRole("button", { name: "CVE 다음 페이지" }));
  await waitFor(() => expect(fetchCveCatalog).toHaveBeenLastCalledWith({ q: "", vendor: "", product: "", version: "" }, 2));
  vi.mocked(fetchCveCatalog).mockRejectedValueOnce(new Error("승인된 NVD 자료 없음"));
  fireEvent.click(screen.getByRole("button", { name: "검색" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("승인된 NVD 자료 없음");
  expect(screen.queryByText(/검색 조건에 맞는 CVE가 없습니다/)).not.toBeInTheDocument();
  expect(screen.queryByText("Example description")).not.toBeInTheDocument();
  vi.mocked(fetchCveCatalog).mockResolvedValueOnce({ ...page, items: [], total: 0 });
  fireEvent.click(screen.getByRole("button", { name: "다시 조회" }));
  expect(await screen.findByText(/검색 조건에 맞는 CVE가 없습니다/)).toBeInTheDocument();
});

it("ignores late details from a previous search", async () => {
  let oldDetail: (value: CveCatalogDetail) => void = () => {};
  vi.mocked(fetchCveDetail).mockImplementationOnce(() => new Promise(resolve => { oldDetail = resolve; }));
  render(<CveSearchPanel/>); await screen.findByText("CVE-2026-10001");
  vi.mocked(fetchCveCatalog).mockResolvedValueOnce({ ...page, items: [], total: 0 });
  fireEvent.click(screen.getByRole("button", { name: "검색" }));
  await screen.findByText(/검색 조건에 맞는 CVE가 없습니다/);
  oldDetail(detail);
  await waitFor(() => expect(screen.queryByText("Example description")).not.toBeInTheDocument());
});

it("pairs the matched software with its own range rather than the first CVE product", async () => {
  const alpha = { ...product, product: "alpha", ranges: [{ label: "1.0.0 이상 · 2.0.0 미만", status: "affected", versionType: "semver" }] };
  const beta = { ...product, product: "beta", ranges: [{ label: "3.0.0 이상 · 4.0.0 미만", status: "affected", versionType: "semver" }] };
  vi.mocked(fetchCveCatalog).mockResolvedValueOnce({ ...page, items: [{ ...row, products: [alpha, beta], matchedProducts: [beta] }] });
  render(<CveSearchPanel/>);
  expect(await screen.findByText("beta: 3.0.0 이상 · 4.0.0 미만")).toBeInTheDocument();
  expect(screen.queryByText("alpha: 1.0.0 이상 · 2.0.0 미만")).not.toBeInTheDocument();
});

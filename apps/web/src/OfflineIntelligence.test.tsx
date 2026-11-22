import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { OfflineIntelligencePanel, OfflineRunEvidence } from "./OfflineIntelligence";
import { request } from "./api";
vi.mock("./api", () => ({previewMode: false, request: vi.fn()}));
afterEach(() => {cleanup(); vi.resetAllMocks();});
const manifest = {sha256:"a", sources:[{kind:"vulnrichment",id:"cisa",dataDate:"2026-10-19",status:"stale",maxAgeDays:7,sha256:"proof",sourceUrl:"https://example.test"}],counts:{vulnrichment:1}};
it("keeps source freshness and response counts with reference imports managed centrally", async () => {
  vi.mocked(request).mockImplementation(async url => String(url).endsWith("/impact") ? {projects:[{runId:"r",service:"service",environment:"prod",release:"1",analysisState:"queued",findings:2,responseStates:{in_progress:1,open:1},overdue:1}],uniqueVulnerabilities:2,responseStates:{}} : {current:manifest,history:[{id:"snap",kind:"vulnrichment",sourceId:"cisa",dataDate:"2026-10-19",records:1,author:"admin"}]} as never);
  render(<OfflineIntelligencePanel />);
  expect(await screen.findByText("vulnrichment / cisa")).toBeInTheDocument();
  expect(screen.getByText("stale / 7")).toBeInTheDocument();
  expect(screen.getByRole("table", {name:"반입 참조 소스 현황"}).closest(".tracker-table-scroll")).not.toBeNull();
  expect(screen.getByRole("table", {name:"프로젝트 영향과 대응 현황"}).closest(".tracker-table-scroll")).not.toBeNull();
  expect(screen.getByRole("region", {name:"반입 소스 가로 스크롤"})).toHaveAttribute("tabindex", "0");
  expect(screen.getByText("in_progress: 1, open: 1")).toBeInTheDocument();
  expect(screen.queryByLabelText("참조 자료 JSON 반입")).not.toBeInTheDocument();
  expect(screen.getByText(/설정 → 취약점 데이터에서 서명된 통합 압축파일로 반입·적용/)).toBeInTheDocument();
});
it("submits exact non-PURL response target and preserves explicit stale evidence", async () => {
  vi.mocked(request).mockImplementation(async (url, options) => options?.method === "POST" ? {id:"event",component:"demo@1.0",vulnerabilityId:"CVE-1",state:"in_progress",owner:"team",rationale:"upgrade",dueAt:null} : String(url).endsWith("/responses") ? {items:[]} : {revisionId:"rev",analysisReady:true,snapshotChanged:true,summary:manifest,components:[],findings:[{id:"CVE-1",component:"demo",version:"1.0",offlineReference:{supplierVexConflict:true}}]} as never);
  render(<OfflineRunEvidence runId="run" canRespond canViewResponses />);
  const save = await screen.findByRole("button", {name:"대응 이력 저장"});
  expect(screen.getByText(/현재 반입 자료가 분석 당시와 다릅니다/)).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("대응 상태"), {target:{value:"in_progress"}});
  fireEvent.change(screen.getByLabelText("대응 담당자"), {target:{value:"team"}});
  fireEvent.change(screen.getByLabelText("대응 근거"), {target:{value:"upgrade"}});
  fireEvent.click(save);
  await waitFor(() => expect(request).toHaveBeenCalledWith("/api/v1/sbom-runs/run/responses", expect.objectContaining({method:"POST",body:JSON.stringify({component:"demo@1.0",vulnerabilityId:"CVE-1",expectedRevisionId:"rev",state:"in_progress",owner:"team",rationale:"upgrade",dueAt:null})})));
  expect(screen.getByText(/CVE-1 \/ demo@1.0/)).toBeInTheDocument();
});

it("shows readable current component evidence and explicit OVAL review outcomes", async () => {
  vi.mocked(request).mockResolvedValue({revisionId:"rev",analysisReady:true,snapshotChanged:false,summary:manifest,components:[{name:"example-alpha",version:"1.0",purl:"pkg:pypi/example-alpha@1.0",offlineReference:{lifecycle:[{endOfLife:true,source:{status:"fresh"},record:{eolDate:"2025-01-01"}}],packageMetadata:[{source:{status:"fresh"},record:{latestVersion:"2.0",status:"fresh",fetchedAt:"2026-10-19T00:00:00Z",expiresAt:"2999-01-01T00:00:00Z"}}],licenses:[{id:"MIT",status:"known"}],cpe:[{}],cpeMatch:[{}]}},{name:"missing",version:"1.0",offlineReference:{}}],findings:[{id:"CVE-1",component:"example-alpha",offlineReference:{cwe:[{}],ubuntuOval:[{evaluation:{status:"affected_review",reason:"dpkginfo_subset_evaluated"}}]}},{id:"CVE-2",component:"missing",offlineReference:{ubuntuOval:[{evaluation:{status:"unknown",reason:"dpkg_unavailable"}}]}}]} as never);
  render(<OfflineRunEvidence runId="run" canRespond={false} canViewResponses={false} />);
  expect(await screen.findByRole("table",{name:"구성요소별 오프라인 자료 활용"})).toHaveClass("tracker-evidence-components");
  expect(screen.getByRole("table",{name:"구성요소별 오프라인 자료 활용"}).closest(".tracker-table-scroll")).not.toBeNull();
  expect(screen.getByRole("table",{name:"취약점별 오프라인 자료 활용"})).toHaveClass("tracker-evidence-findings");
  expect(screen.getByRole("table",{name:"취약점별 오프라인 자료 활용"}).closest(".tracker-table-scroll")).not.toBeNull();
  expect(screen.getByText("지원 종료 · 2025-01-01")).toBeInTheDocument();
  expect(screen.getByText("유효한 관측 근거 · 자료 기준일 내")).toBeInTheDocument();
  expect(screen.getByText("MIT · 사전 확인")).toBeInTheDocument();
  expect(screen.getByText("사전 1개 / 적용 문자열 1개")).toBeInTheDocument();
  expect(screen.getByText("영향 있음 (검토 참고)")).toBeInTheDocument();
  expect(screen.getByText("판정 불가 · dpkg 없음")).toBeInTheDocument();
  expect(screen.getByText("일치 근거 없음 · 안전 판정 아님")).toBeInTheDocument();
});
it("keeps expired latest-version observations visible without calling them fresh", async () => {
  vi.mocked(request).mockResolvedValue({revisionId:"rev",analysisReady:true,snapshotChanged:true,summary:manifest,components:[{name:"expired",version:"1.0",offlineReference:{packageMetadata:[{source:{status:"fresh"},record:{latestVersion:"9.0",status:"fresh",expiresAt:"2000-01-01T00:00:00Z"}}]}}],findings:[]} as never);
  render(<OfflineRunEvidence runId="run" canRespond={false} canViewResponses={false} />);
  expect(await screen.findByText("관측값 만료 · 자료 기준일 내")).toBeInTheDocument();
  expect(screen.getByText("9.0")).toBeInTheDocument();
  expect(screen.queryByText("유효한 관측 근거 · 자료 기준일 내")).not.toBeInTheDocument();
  expect(screen.getByText(/현재 반입 자료가 분석 당시와 다릅니다/)).toBeInTheDocument();
});

it("pages component and vulnerability evidence independently", async () => {
  vi.mocked(request).mockResolvedValue({
    summary: { sources: [] },
    components: Array.from({ length: 12 }, (_, index) => ({ name: `package-${index + 1}`, version: "1.0" })),
    findings: Array.from({ length: 11 }, (_, index) => ({ id: `cve-${index + 1}`, component: "example" })),
  });
  render(<OfflineRunEvidence runId="run" canRespond={false} canViewResponses={false} />);
  const components = within(await screen.findByRole("table", { name: "구성요소별 오프라인 자료 활용" }));
  const findings = within(screen.getByRole("table", { name: "취약점별 오프라인 자료 활용" }));
  expect(components.getAllByRole("row")).toHaveLength(11);
  expect(findings.getAllByRole("row")).toHaveLength(11);

  fireEvent.click(screen.getByRole("button", { name: "취약점 근거 다음 페이지" }));
  expect(findings.getByText("cve-11 / example")).toBeVisible();
  expect(components.getByText("package-1 1.0")).toBeVisible();

  fireEvent.change(screen.getByRole("combobox", { name: "구성요소 자료 활용 페이지당 행 수" }), { target: { value: "25" } });
  expect(components.getByText("package-12 1.0")).toBeVisible();
  expect(findings.getAllByRole("row")).toHaveLength(2);
});

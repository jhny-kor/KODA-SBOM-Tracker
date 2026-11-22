import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { SsvcAssessmentsPanel } from "./SsvcAssessments";
import { EpssEvidence } from "./EpssEvidence";
import * as api from "./ssvcApi";
import type { SsvcAssessment, SsvcResult } from "./ssvcApi";

vi.mock("./api", () => ({ previewMode: false }));
vi.mock("./ssvcApi", () => ({ fetchSsvcAssessments: vi.fn(), submitSsvcAssessment: vi.fn() }));

const finding = { canonicalId: "CVE-2021-44228", component: "pkg:maven/log4j-core@2.14.1", version: "2.14.1" };
const assessment: SsvcAssessment = {
  id: "assessment", runId: "run", revisionId: "revision", serviceId: "service", environmentId: "prod", releaseId: "release", componentVersion: "2.14.1",
  component: finding.component, vulnerabilityId: finding.canonicalId, model: "ssvc:DT_DP:1.0.0", tableSha256: "a".repeat(64),
  inputs: { exploitation: "active", systemExposure: "open", automatable: "yes", humanImpact: "high" },
  outcome: "immediate", state: "assessed", stale: false, staleReasons: [], superseded: false,
  rationale: "운영 환경 노출 근거", references: ["SEC-1"], author: "reviewer", createdAt: "2026-10-19T00:00:00Z", evidence: { dataAsOf: "2026-10-19" },
};
const result: SsvcResult = { items: [], total: 0, page: 1, size: 20, model: assessment.model, revisionId: "revision", analysisReady: true, archived: false };

beforeEach(() => {
  vi.mocked(api.fetchSsvcAssessments).mockResolvedValue(result);
  vi.mocked(api.submitSsvcAssessment).mockResolvedValue(assessment);
});
afterEach(() => { cleanup(); vi.resetAllMocks(); });

it("submits exact current analysis target with manual inputs and evidence", async () => {
  render(<SsvcAssessmentsPanel runId="run" findings={[finding]} canManage />);
  const save = await screen.findByRole("button", { name: "SSVC 판단 저장" });
  await waitFor(() => expect(save).toBeEnabled());
  fireEvent.change(screen.getByLabelText("SSVC 악용 상태"), { target: { value: "active" } });
  fireEvent.change(screen.getByLabelText("SSVC 시스템 노출"), { target: { value: "open" } });
  fireEvent.change(screen.getByLabelText("SSVC 악용 자동화 가능성"), { target: { value: "yes" } });
  fireEvent.change(screen.getByLabelText("SSVC 업무·안전 영향"), { target: { value: "high" } });
  fireEvent.change(screen.getByLabelText("SSVC 판단 근거"), { target: { value: "운영 서비스의 노출 경로 확인" } });
  fireEvent.change(screen.getByLabelText("SSVC 근거 참조"), { target: { value: "SEC-1\nSEC-2" } });
  fireEvent.click(save);
  await waitFor(() => expect(api.submitSsvcAssessment).toHaveBeenCalledWith("run", {
    component: finding.component, vulnerabilityId: finding.canonicalId, expectedRevisionId: "revision", inputs: assessment.inputs,
    rationale: "운영 서비스의 노출 경로 확인", references: ["SEC-1", "SEC-2"],
  }));
  expect(await screen.findByRole("status")).toHaveTextContent("Immediate");
});

it("keeps unknown inputs null rather than inventing defer", async () => {
  vi.mocked(api.submitSsvcAssessment).mockResolvedValue({ ...assessment, outcome: null, state: "unassessed" });
  render(<SsvcAssessmentsPanel runId="run" findings={[finding]} canManage />);
  const save = await screen.findByRole("button", { name: "SSVC 판단 저장" });
  await waitFor(() => expect(save).toBeEnabled());
  fireEvent.change(screen.getByLabelText("SSVC 판단 근거"), { target: { value: "담당팀 확인 필요" } });
  fireEvent.click(save);
  await waitFor(() => expect(api.submitSsvcAssessment).toHaveBeenCalledWith("run", expect.objectContaining({ inputs: { exploitation: null, systemExposure: null, automatable: null, humanImpact: null } })));
  expect(await screen.findByRole("status")).toHaveTextContent("미평가 사유를 저장");
});

it("preserves exact version identity for a CPE product without a package URL", async () => {
  render(<SsvcAssessmentsPanel runId="run" findings={[{ canonicalId: "CVE-2026-0001", component: "widget", version: "1.2.0", sourceKind: "nvd_cpe" }]} canManage />);
  const save = await screen.findByRole("button", { name: "SSVC 판단 저장" });
  await waitFor(() => expect(save).toBeEnabled());
  fireEvent.change(screen.getByLabelText("SSVC 판단 근거"), { target: { value: "운영 장비 CPE 확인" } });
  fireEvent.click(save);
  await waitFor(() => expect(api.submitSsvcAssessment).toHaveBeenCalledWith("run", expect.objectContaining({ component: "widget@1.2.0", vulnerabilityId: "CVE-2026-0001" })));
});

it("shows immutable prior decision with explicit stale reasons and bounded history pagination", async () => {
  vi.mocked(api.fetchSsvcAssessments).mockResolvedValue({ ...result, items: [{ ...assessment, stale: true, staleReasons: ["evidence_changed"], superseded: true }], total: 21 });
  render(<SsvcAssessmentsPanel runId="run" findings={[finding]} canManage={false} />);
  expect(await screen.findByText(/Immediate · 즉시 대응 · 재평가 필요 · 이전 판단/)).toBeInTheDocument();
  expect(screen.getByText(/취약점 근거·데이터 변경/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "SSVC 판단 저장" })).not.toBeInTheDocument();
  fireEvent.click(screen.getByText("입력·근거 스냅샷 보기"));
  expect(screen.getByText(/결정표 SHA-256/)).toHaveTextContent("a".repeat(64));
  fireEvent.click(screen.getByRole("button", { name: "SSVC 판단 다음 페이지" }));
  await waitFor(() => expect(api.fetchSsvcAssessments).toHaveBeenLastCalledWith("run", 2));
});

it("disables saving on failed analysis, archives and fetch errors", async () => {
  vi.mocked(api.fetchSsvcAssessments).mockResolvedValue({ ...result, analysisReady: false, archived: true });
  render(<SsvcAssessmentsPanel runId="run" findings={[finding]} canManage />);
  expect(await screen.findByText("최신 분석이 완료된 후 평가할 수 있습니다.")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "SSVC 판단 저장" })).toBeDisabled();
  expect(screen.getByText("보관된 SBOM의 판단 이력입니다.")).toBeInTheDocument();
  vi.mocked(api.fetchSsvcAssessments).mockRejectedValue(new Error("접근 거절"));
  fireEvent.click(screen.getByRole("button", { name: "SSVC 새로고침" }));
  expect(await screen.findByRole("status")).toHaveTextContent("접근 거절");
  expect(screen.getByRole("button", { name: "SSVC 판단 저장" })).toBeDisabled();
});

it("shows historical EPSS with date and percentile without implying fresh evidence", () => {
  render(<EpssEvidence finding={{ epssObservedScore: .7, epssObservedPercentile: .95, epssObservedDate: "2026-10-01", epssStatus: "stale" }} />);
  expect(screen.getByText(/EPSS 70.00% · 백분위 95.00% · 2026-10-01 · 과거 관측값 \(stale\)/)).toBeInTheDocument();
});

it("keeps equal-height evidence fields and preserves drafts when the card is closed", async () => {
  render(<SsvcAssessmentsPanel runId="run" findings={[finding]} canManage />);
  await waitFor(() => expect(screen.getByRole("button", { name: "SSVC 판단 저장" })).toBeEnabled());
  const rationale = screen.getByRole("textbox", { name: "SSVC 판단 근거" });
  expect(screen.getByRole("textbox", { name: "SSVC 근거 참조" })).toHaveAttribute("rows", rationale.getAttribute("rows"));
  fireEvent.change(rationale, { target: { value: "검토 중인 판단 근거" } });
  const toggle = screen.getByRole("button", { name: "SSVC · 대응 우선순위" });
  fireEvent.click(toggle);
  expect(toggle).toHaveAttribute("aria-expanded", "false");
  expect(rationale).not.toBeVisible();
  fireEvent.click(toggle);
  expect(rationale).toBeVisible();
  expect(rationale).toHaveValue("검토 중인 판단 근거");
});

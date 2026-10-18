import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fetchRunPolicyViolations, fetchSbomPolicies, updateSbomPolicies } from "./api";
import { SbomPoliciesPanel } from "./SbomPolicies";
import { NativePolicyResult } from "./NativePolicyResult";
import { policyCountLabel } from "./policy";
import { canPage } from "./permissions";
import type { SbomPolicyDocument, SbomRun } from "./types";

vi.mock("./api", () => ({ previewMode: false, fetchSbomPolicies: vi.fn(), updateSbomPolicies: vi.fn(), fetchRunPolicyViolations: vi.fn() }));
const policy: SbomPolicyDocument = {
  version: 7, createdBy: "admin", createdAt: "2026-10-17T00:00:00Z", exceptions: [],
  rules: [{ id: "severity", name: "고위험 취약점", kind: "severity", action: "fail", enabled: true, values: ["critical", "high"] }],
};
const run: SbomRun = { id: "run", service: { id: "svc", name: "서비스", slug: "svc" }, environment: { id: "env", name: "환경", slug: "env" }, releaseVersion: "1", roundNumber: 1, state: "completed", sha256: "hash", componentCount: 1, vulnerabilityCount: 1, policyViolationCount: 0, dataAsOf: "2026-10-17", createdAt: "2026-10-17T00:00:00Z" };

beforeEach(() => { vi.mocked(fetchSbomPolicies).mockResolvedValue(structuredClone(policy)); });
afterEach(() => { cleanup(); vi.clearAllMocks(); });

describe("native SBOM policies", () => {
  it("allows policy-only permissions to open settings", () => {
    expect(canPage({ id: "p", username: "p", role: "analyst", active: true, permissions: ["policies.view"] }, "settings")).toBe(true);
  });
  it("shows immutable policy version to readers without save or add actions", async () => {
    render(<SbomPoliciesPanel canManage={false} />);
    expect(await screen.findByRole("heading", { name: "SBOM 정책 · v7" })).toBeInTheDocument();
    expect(screen.getByLabelText("규칙 1 이름")).toBeDisabled();
    expect(screen.queryByRole("button", { name: "정책 버전 저장" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "규칙 추가" })).not.toBeInTheDocument();
  });
  it("saves changes with the loaded version and shows new version", async () => {
    vi.mocked(updateSbomPolicies).mockResolvedValue({ ...policy, version: 8 });
    render(<SbomPoliciesPanel canManage />);
    fireEvent.change(await screen.findByLabelText("규칙 1 이름"), { target: { value: "운영 취약점" } });
    fireEvent.click(screen.getByRole("button", { name: "정책 버전 저장" }));
    await waitFor(() => expect(updateSbomPolicies).toHaveBeenCalledWith(expect.objectContaining({ version: 7, rules: [expect.objectContaining({ name: "운영 취약점" })] })));
    expect(await screen.findByRole("status")).toHaveTextContent("정책 v8을 저장했습니다");
  });
  it("retains draft and exposes concurrent edit errors", async () => {
    vi.mocked(updateSbomPolicies).mockRejectedValue(new Error("정책이 변경되었습니다. 다시 불러오세요."));
    render(<SbomPoliciesPanel canManage />);
    await screen.findByLabelText("규칙 1 이름");
    fireEvent.click(screen.getByRole("button", { name: "정책 버전 저장" }));
    expect(await screen.findByRole("status")).toHaveTextContent("정책이 변경되었습니다");
    expect(screen.getByLabelText("규칙 1 이름")).toHaveValue("고위험 취약점");
  });
  it("recovers after a load failure through reload", async () => {
    vi.mocked(fetchSbomPolicies).mockRejectedValueOnce(new Error("연결 실패"));
    render(<SbomPoliciesPanel canManage />);
    expect(await screen.findByRole("status")).toHaveTextContent("연결 실패");
    fireEvent.click(screen.getByRole("button", { name: "다시 불러오기" }));
    expect(await screen.findByLabelText("규칙 1 이름")).toHaveValue("고위험 취약점");
  });
  it("adds a reasoned expiring exception and omits an empty optional vulnerability ID", async () => {
    vi.mocked(updateSbomPolicies).mockResolvedValue({ ...policy, version: 8 });
    render(<SbomPoliciesPanel canManage />);
    await screen.findByLabelText("규칙 1 이름");
    fireEvent.change(screen.getByLabelText("구성요소 식별자"), { target: { value: "pkg:pypi/demo@1" } });
    fireEvent.change(screen.getByLabelText("예외 사유"), { target: { value: "검토 승인" } });
    fireEvent.change(screen.getByLabelText("만료 시각 (현재 시간대)"), { target: { value: "2099-10-17T12:00" } });
    fireEvent.click(screen.getByRole("button", { name: "예외 추가" }));
    expect(screen.getByText("검토 승인")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "정책 버전 저장" }));
    await waitFor(() => expect(updateSbomPolicies).toHaveBeenCalled());
    const exception = vi.mocked(updateSbomPolicies).mock.calls[0][0].exceptions[0];
    expect(exception).toMatchObject({ component: "pkg:pypi/demo@1", reason: "검토 승인", ruleId: "severity" });
    expect(exception).not.toHaveProperty("vulnerabilityId");
    expect(exception.expiresAt).toMatch(/Z$/);
  });
  it("never labels unevaluated or failed policies as zero violations", () => {
    expect(policyCountLabel(run)).toBe("미평가");
    expect(policyCountLabel({ ...run, policyState: "failed" })).toBe("평가 실패");
    render(<NativePolicyResult result={{ ...run, policyState: "failed", policyError: "Grype 분석 실패" }} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Grype 분석 실패");
    expect(screen.queryByText("통과")).not.toBeInTheDocument();
    expect(screen.queryByText(/활성 위반·경고·정보 0건/)).not.toBeInTheDocument();
  });
  it("fetches policy result pages without embedding all rows", async () => {
    vi.mocked(fetchRunPolicyViolations).mockResolvedValueOnce({ items: [{ policyName: "첫 페이지", component: "demo", action: "warn" }], total: 26, page: 1, size: 25 })
      .mockResolvedValueOnce({ items: [{ policyName: "둘째 페이지", component: "demo2", action: "warn" }], total: 26, page: 2, size: 25 });
    render(<NativePolicyResult result={{ ...run, analysisId: "analysis-1", policyState: "completed", policyStatus: "warn" }} runId="run" />);
    expect(await screen.findByText("첫 페이지")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "정책 결과 다음" }));
    expect(await screen.findByText("둘째 페이지")).toBeInTheDocument();
    expect(fetchRunPolicyViolations).toHaveBeenLastCalledWith("run", 2, 25, "analysis-1");
  });
  it("exposes result fetch failure and retry without showing a clean table", async () => {
    vi.mocked(fetchRunPolicyViolations).mockRejectedValueOnce(new Error("결과 연결 실패")).mockResolvedValueOnce({ items: [], total: 0, page: 1, size: 25 });
    render(<NativePolicyResult result={{ ...run, policyState: "completed", policyStatus: "pass" }} runId="run" />);
    expect(await screen.findByRole("alert")).toHaveTextContent("결과 연결 실패");
    expect(screen.queryByText("적용한 정책의 위반·경고·정보가 없습니다.")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "정책 결과 다시 불러오기" }));
    expect(await screen.findByText("적용한 정책의 위반·경고·정보가 없습니다.")).toBeInTheDocument();
  });
  it("shows exception evidence independently of active count", () => {
    render(<NativePolicyResult result={{ ...run, policyState: "completed", policyStatus: "pass", policyVersion: 7, policyViolations: [{ policyId: "severity", policyName: "고위험 취약점", component: "pkg:pypi/demo@1", action: "fail", suppressed: true, reason: "Critical", exception: { reason: "점검 승인", expiresAt: "2099-10-17T00:00:00Z" } }] }} />);
    expect(screen.getByText("정책 예외")).toBeInTheDocument();
    expect(screen.getByText(/점검 승인/)).toHaveTextContent("2099-10-17 09:00:00");
    expect(screen.getByText("통과")).toBeInTheDocument();
  });
});

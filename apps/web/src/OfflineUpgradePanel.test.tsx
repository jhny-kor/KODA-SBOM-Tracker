import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { request } from "./api";
import OfflineUpgradePanel from "./OfflineUpgradePanel";

vi.mock("./api", () => ({ request: vi.fn() }));
const apiRequest = vi.mocked(request);
afterEach(() => { cleanup(); apiRequest.mockReset(); });

it("shows scoped history and distinguishes conditions from actual build and run records", async () => {
  const summary = { id: "batch", ecosystem: "maven", coordinate: "pkg:maven/org.example/core",
    createdAt: "2026-11-08T10:00:00Z", highestConditionVersion: "2.8", highestVerifiedVersion: "2.7" };
  apiRequest.mockResolvedValueOnce({ baseline: { releaseVersion: "1.0", roundNumber: 1 }, service: "결제", environment: "운영",
    candidates: [], javaDeployments: [] }).mockResolvedValueOnce({ items: [summary], hasMore: false })
    .mockResolvedValueOnce({ ...summary, platform: { server: "WAS1", os: "Linux", architecture: "x86_64" }, currentVersions: ["2.6"],
      candidates: [
        { version: "2.8", conditionStatus: "conditions_met", reasons: ["Java 11 요구사항 충족"], build: { status: "passed", reference: "CI #28" }, runtime: { status: "failed" } },
        { version: "2.9", conditionStatus: "conflict", reasons: ["후보 요구 Java 17"], build: { status: "not_reported" }, runtime: { status: "not_reported" } },
      ] });
  render(<OfflineUpgradePanel runId="base" canManage={false} />);
  expect(apiRequest).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "폐쇄망 후보 버전 일괄 검토" }));
  fireEvent.click(await screen.findByRole("button", { name: "결과 보기" }));
  expect(await screen.findByText(/조건 충족 최고 버전/)).toHaveTextContent("2.8");
  expect(screen.getByText(/빌드·실행 모두 통과한 최고 버전/)).toHaveTextContent("2.7");
  const row = screen.getByRole("row", { name: /2\.8 조건 충족/ });
  expect(within(row).getByText("통과")).toBeInTheDocument();
  expect(within(row).getByText("실패")).toBeInTheDocument();
  expect(screen.getByText("후보 요구 Java 17")).toBeInTheDocument();
  expect(screen.queryByLabelText("일괄 검토 JSON")).not.toBeInTheDocument();
});

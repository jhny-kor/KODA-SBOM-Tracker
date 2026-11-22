import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { request } from "./api";
import ExternalReadTokens from "./ExternalReadTokens";
import JavaUpgradePanel from "./JavaUpgradePanel";
import { SharedAISettingsPanel, TrackerAISummary } from "./SharedAI";

vi.mock("./api", () => ({ request: vi.fn() }));
const apiRequest = vi.mocked(request);
afterEach(() => { cleanup(); apiRequest.mockReset(); });

it("issues an environment-scoped external token and dismisses the one-time credential", async () => {
  apiRequest.mockResolvedValueOnce([]).mockResolvedValueOnce({
    id: "token-id", name: "배포 대시보드", serviceId: "s1", environmentId: "prod",
    expiresAt: "2099-01-01T00:00:00Z", token: "koda_read_example",
  });
  render(<ExternalReadTokens services={[{ id: "s1", name: "결제", slug: "payment" }]} environments={[{ id: "prod", name: "운영", slug: "prod" }]} />);
  fireEvent.change(await screen.findByLabelText("연동 이름"), { target: { value: "배포 대시보드" } });
  fireEvent.change(screen.getByLabelText("서비스"), { target: { value: "s1" } });
  fireEvent.change(screen.getByLabelText("환경"), { target: { value: "prod" } });
  fireEvent.click(screen.getByRole("button", { name: "조회 토큰 발급" }));
  expect(await screen.findByText("koda_read_example")).toBeInTheDocument();
  expect(JSON.parse(apiRequest.mock.calls[1][1]?.body as string)).toMatchObject({ serviceId: "s1", environmentId: "prod", days: 30 });
  fireEvent.click(screen.getByRole("button", { name: "닫기" }));
  expect(screen.queryByText("koda_read_example")).not.toBeInTheDocument();
});

it("lazily loads deployment evidence and displays a declared Java conflict", async () => {
  const deployment = { id: "d1", runId: "r1", target: "운영 WAS", environmentId: "prod", javaMajor: 11, os: "Linux", architecture: "x86_64" };
  apiRequest.mockResolvedValueOnce({ items: [deployment], truncated: false })
    .mockResolvedValueOnce({ items: [], truncated: false })
    .mockResolvedValueOnce({
      status: "declared_conflict", deployment, currentVersions: ["1.0"], candidateVersions: ["2.0"],
      dependencyPaths: [["root", "dependency"]], affectedDeployments: [], componentChanges: null,
      vulnerabilityComparison: { status: "not_comparable", reason: "candidate_sbom_required" },
    });
  render(<JavaUpgradePanel runId="r1" serviceId="s1" canManage={false} />);
  expect(apiRequest).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Java/Maven 버전 영향 검토" }));
  fireEvent.change(await screen.findByLabelText("Maven PURL"), { target: { value: "pkg:maven/org.example/app" } });
  fireEvent.change(screen.getByLabelText("후보 버전"), { target: { value: "2.0" } });
  fireEvent.change(screen.getByLabelText("후보 최소 Java 버전"), { target: { value: "17" } });
  fireEvent.change(screen.getByLabelText("최소 Java 버전 근거"), { target: { value: "release notes" } });
  fireEvent.click(screen.getByRole("button", { name: "버전 영향 검토" }));
  expect(await screen.findByText("입력한 최소 Java 요구 버전과 충돌")).toBeInTheDocument();
  expect(screen.getByText("root → dependency")).toBeInTheDocument();
  expect(screen.getByText("후보 SBOM을 선택해야 합니다.")).toBeInTheDocument();
  expect(JSON.parse(apiRequest.mock.calls[2][1]?.body as string)).toMatchObject({ deploymentId: "d1", candidateVersion: "2.0", minimumJavaMajor: 17 });
});

it("clears the submitted API key and displays AI output as literal text", async () => {
  const settings = { endpointConfigured: true, baseUrl: "https://ai.internal/v1", model: "inside", hasKey: true };
  apiRequest.mockResolvedValueOnce({ endpointConfigured: false, baseUrl: null, model: null, hasKey: false })
    .mockResolvedValueOnce(settings).mockResolvedValueOnce({ summary: "<b>검토 참고</b>" });
  render(<><SharedAISettingsPanel /><TrackerAISummary runId="r1" /></>);
  const address = await screen.findByLabelText("사내 AI 서버 주소");
  const key = screen.getByLabelText("AI API 키");
  fireEvent.change(address, { target: { value: settings.baseUrl } });
  fireEvent.change(screen.getByLabelText("모델 ID"), { target: { value: settings.model } });
  fireEvent.change(key, { target: { value: "example-key" } });
  fireEvent.click(screen.getByRole("button", { name: "설정 저장" }));
  await waitFor(() => expect(key).toHaveValue(""));
  expect(JSON.parse(apiRequest.mock.calls[1][1]?.body as string)).toMatchObject({ baseUrl: settings.baseUrl, model: settings.model });
  fireEvent.click(screen.getByRole("button", { name: "사내 AI로 요약" }));
  expect(await screen.findByText("<b>검토 참고</b>")).toBeInTheDocument();
  expect(document.querySelector("b")).toBeNull();
});

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import * as api from "./quality-api";
import { SbomQualityPanel } from "./SbomQuality";
import type { QualityProfile, QualityRevision } from "./quality-api";
vi.mock("./api", () => ({ previewMode: false, request: vi.fn() }));
vi.mock("./quality-api", async original => ({ ...await original<typeof import("./quality-api")>(), fetchQualityRevisions: vi.fn(), createQualityRevision: vi.fn(), fetchQualityIssues: vi.fn(), fetchQualityProfile: vi.fn(), saveQualityProfile: vi.fn() }));
const profile: QualityProfile = { projectId: "project-native-id", name: "납품 기준", version: 4, mode: "enforce", maxErrors: 0, maxWarnings: null, maxMissingIdentityRatio: 0.1, maxUnresolvedRefs: 0, maxAgeDays: 90 };
const revision: QualityRevision = { id: "quality-2", runId: "run", sequence: 2, state: "completed", profileSnapshot: profile, summary: { componentCount: 2, errorCount: 1, warningCount: 2, missingIdentityCount: 1, missingIdentityRatio: 0.5, unresolvedRefCount: 1, score: null, qualityStatus: "fail", fieldStatus: { identity: { missing: 1 } } }, createdAt: "2026-10-18T00:00:00Z", engineVersion: "1", originalSha256: "a".repeat(64), error: null, comparison: { previousRevisionId: "quality-1", errorDelta: -1, warningDelta: 2 } };
const older = { ...revision, id: "quality-1", sequence: 1, profileSnapshot: { ...profile, version: 3, mode: "warn" as const }, comparison: null };
const issue = { id: "issue-1", ruleId: "identity.missing", severity: "error" as const, path: "$.components[0].components[0]", bomRef: "child", componentName: "nested-child", message: "식별자 누락", observed: null, expected: "PURL, CPE 또는 SWID", remediation: "패키지 식별자를 원본 SBOM에 추가하세요." };
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(api.fetchQualityRevisions).mockResolvedValue({ items: [revision, older], total: 2, page: 1, size: 20 });
  vi.mocked(api.fetchQualityIssues).mockResolvedValue({ items: [issue], total: 1, page: 1, size: 20 });
  vi.mocked(api.fetchQualityProfile).mockResolvedValue(profile);
});
afterEach(cleanup);
function mount(options: Partial<Parameters<typeof SbomQualityPanel>[0]> = {}) { return render(<SbomQualityPanel runId="run" canRerun canViewProfiles canManage {...options} />); }

it("shows nested source evidence and a failed enforced criterion independently of vulnerabilities", async () => {
  mount(); expect(await screen.findByText("nested-child")).toBeInTheDocument();
  expect(screen.getByText("$.components[0].components[0]")).toBeInTheDocument();
  expect(screen.getByText("패키지 식별자를 원본 SBOM에 추가하세요.")).toBeInTheDocument();
  expect(screen.getByText(/기준 미달 · 납품 기준 v4 · 강제 기준/)).toBeInTheDocument();
  expect(screen.getByText(/오류 -1건 · 경고 \+2건/)).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "품질 CSV" })).toHaveAttribute("href", "/api/v1/sbom-runs/run/quality-export?revisionId=quality-2&format=csv");
});
it("selects an immutable older revision and exports that revision", async () => {
  mount(); await screen.findByText("nested-child"); fireEvent.change(screen.getByLabelText("품질 리비전"), { target: { value: "quality-1" } });
  await waitFor(() => expect(api.fetchQualityIssues).toHaveBeenLastCalledWith("run", "quality-1", 1, "", ""));
  expect(screen.getByText(/납품 기준 v3 · 경고 모드/)).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "품질 JSON" })).toHaveAttribute("href", expect.stringContaining("revisionId=quality-1"));
});
it("sends issue filters and pagination to the server", async () => {
  vi.mocked(api.fetchQualityIssues).mockResolvedValue({ items: [issue], total: 41, page: 1, size: 20 });
  mount(); await screen.findByText("nested-child"); fireEvent.click(screen.getByRole("button", { name: "품질 이슈 다음 페이지" }));
  await waitFor(() => expect(api.fetchQualityIssues).toHaveBeenLastCalledWith("run", "quality-2", 2, "", ""));
  fireEvent.change(screen.getByLabelText("품질 심각도"), { target: { value: "error" } });
  await waitFor(() => expect(api.fetchQualityIssues).toHaveBeenLastCalledWith("run", "quality-2", 1, "error", ""));
  fireEvent.change(screen.getByLabelText("품질 규칙 ID"), { target: { value: "identity.missing" } });
  await waitFor(() => expect(api.fetchQualityIssues).toHaveBeenLastCalledWith("run", "quality-2", 1, "error", "identity.missing"));
});
it("reruns quality and refreshes the latest stored history", async () => {
  vi.mocked(api.createQualityRevision).mockResolvedValue(revision); mount(); await screen.findByText("nested-child");
  fireEvent.click(screen.getByRole("button", { name: "품질 재진단" }));
  await waitFor(() => expect(api.createQualityRevision).toHaveBeenCalledWith("run"));
  await waitFor(() => expect(api.fetchQualityRevisions).toHaveBeenCalledTimes(2));
});
it("does not represent an evaluation failure as a successful empty report", async () => {
  vi.mocked(api.fetchQualityRevisions).mockResolvedValue({ items: [{ ...revision, state: "failed", error: "원본 해시가 일치하지 않습니다.", summary: { ...revision.summary, qualityStatus: "failed" } }], total: 1, page: 1, size: 20 });
  vi.mocked(api.fetchQualityIssues).mockResolvedValue({ items: [], total: 0, page: 1, size: 20 });
  mount(); expect(await screen.findByText("원본 해시가 일치하지 않습니다.")).toBeInTheDocument();
  expect(await screen.findByText("진단 실패 상태입니다. 통과로 간주하지 않습니다.")).toBeInTheDocument();
  expect(screen.queryByText("발견된 품질 이슈가 없습니다.")).not.toBeInTheDocument();
});
it("preserves optimistic version and selected project when saving criteria", async () => {
  vi.mocked(api.saveQualityProfile).mockResolvedValue({ ...profile, version: 5, maxErrors: 2 });
  mount(); await screen.findByText("nested-child"); fireEvent.click(screen.getByRole("tab", { name: "프로젝트별 품질 기준" }));
  expect(await screen.findByLabelText("품질 기준 이름")).toHaveValue("납품 기준");
  expect(api.fetchQualityProfile).toHaveBeenCalledWith("project-native-id");
  fireEvent.change(screen.getByLabelText("품질 허용 오류 수"), { target: { value: "2" } });
  fireEvent.click(screen.getByRole("button", { name: "품질 기준 새 버전 저장" }));
  await waitFor(() => expect(api.saveQualityProfile).toHaveBeenCalledWith("project-native-id", expect.objectContaining({ version: 4, maxErrors: 2, mode: "enforce" })));
  expect(await screen.findByText(/품질 기준 v5을 저장했습니다/)).toBeInTheDocument();
});
it("requires loading a changed project scope before saving and supports default criteria", async () => {
  mount(); await screen.findByText("nested-child"); fireEvent.click(screen.getByRole("tab", { name: "프로젝트별 품질 기준" })); await screen.findByLabelText("품질 기준 이름");
  fireEvent.change(screen.getByLabelText("품질 기준 프로젝트 ID"), { target: { value: "" } });
  expect(screen.getByRole("button", { name: "품질 기준 새 버전 저장" })).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "기준 불러오기" }));
  await waitFor(() => expect(api.fetchQualityProfile).toHaveBeenLastCalledWith(""));
});
it("keeps profiles read only and prevents rerun for archived or unauthorized runs", async () => {
  mount({ canManage: false, archived: true }); await screen.findByText("nested-child");
  expect(screen.getByRole("button", { name: "품질 재진단" })).toBeDisabled();
  fireEvent.click(screen.getByRole("tab", { name: "프로젝트별 품질 기준" }));
  expect(await screen.findByLabelText("품질 기준 이름")).toBeDisabled();
  expect(screen.queryByRole("button", { name: "품질 기준 새 버전 저장" })).not.toBeInTheDocument();
});
it("does not hide a profile conflict and retains the observed version for explicit reload", async () => {
  vi.mocked(api.saveQualityProfile).mockRejectedValue(new Error("기준이 변경되었습니다. 다시 조회하세요."));
  mount(); await screen.findByText("nested-child"); fireEvent.click(screen.getByRole("tab", { name: "프로젝트별 품질 기준" })); await screen.findByLabelText("품질 기준 이름");
  fireEvent.click(screen.getByRole("button", { name: "품질 기준 새 버전 저장" }));
  expect(await screen.findByText("기준이 변경되었습니다. 다시 조회하세요.")).toBeInTheDocument();
  expect(screen.getByLabelText("품질 기준 이름")).toHaveValue("납품 기준");
});

it("shows non-applicable identity coverage instead of reporting zero percent for an empty SBOM", async () => {
  vi.mocked(api.fetchQualityRevisions).mockResolvedValue({ items: [{ ...revision, summary: { ...revision.summary, componentCount: 0, missingIdentityCount: 0, missingIdentityRatio: null } }], total: 1, page: 1, size: 20 });
  mount(); expect(await screen.findByText("0 (적용 불가)")).toBeInTheDocument();
  expect(screen.queryByText("0 (0.0%)")).not.toBeInTheDocument();
});

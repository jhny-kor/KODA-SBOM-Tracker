import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import * as api from "./quality-api";
import { SbomQualityPanel } from "./SbomQuality";
import type { QualityProfile, QualityRevision } from "./quality-api";
vi.mock("./api", () => ({ previewMode: false, request: vi.fn() }));
vi.mock("./quality-api", async original => ({ ...await original<typeof import("./quality-api")>(), fetchQualityRevisions: vi.fn(), createQualityRevision: vi.fn(), fetchQualityIssues: vi.fn(), fetchQualityProfile: vi.fn(), saveQualityProfile: vi.fn(), fetchEffectiveQualityProfile: vi.fn(), fetchQualityTagProfiles: vi.fn() }));
const profile: QualityProfile = { projectId: "project-native-id", name: "납품 기준", version: 4, mode: "enforce", maxErrors: 0, maxWarnings: null, maxMissingIdentityRatio: 0.1, maxUnresolvedRefs: 0, maxAgeDays: 90 };
const revision: QualityRevision = { id: "quality-2", runId: "run", sequence: 2, state: "completed", profileSnapshot: profile, summary: { componentCount: 2, errorCount: 1, warningCount: 2, missingIdentityCount: 1, missingIdentityRatio: 0.5, unresolvedRefCount: 1, score: null, qualityStatus: "fail", fieldStatus: { identity: { missing: 1 } } }, createdAt: "2026-10-18T00:00:00Z", engineVersion: "1", originalSha256: "a".repeat(64), error: null, comparison: { previousRevisionId: "quality-1", errorDelta: -1, warningDelta: 2 } };
const older = { ...revision, id: "quality-1", sequence: 1, profileSnapshot: { ...profile, version: 3, mode: "warn" as const }, comparison: null };
const issue = { id: "issue-1", ruleId: "identity.missing", severity: "error" as const, path: "$.components[0].components[0]", bomRef: "child", componentName: "nested-child", message: "식별자 누락", observed: null, expected: "PURL, CPE 또는 SWID", remediation: "패키지 식별자를 원본 SBOM에 추가하세요." };
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(api.fetchQualityRevisions).mockResolvedValue({ items: [revision, older], total: 2, page: 1, size: 20 });
  vi.mocked(api.fetchQualityIssues).mockResolvedValue({ items: [issue], total: 1, page: 1, size: 20 });
  vi.mocked(api.fetchQualityProfile).mockResolvedValue(profile);
  vi.mocked(api.fetchEffectiveQualityProfile).mockResolvedValue({ profile, project: { id: "project-native-id", sourceId: "native", sourceProjectId: "source-project", tags: ["production"] } });
  vi.mocked(api.fetchQualityTagProfiles).mockResolvedValue({ items: [], total: 0, page: 1, size: 20 });
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
  await waitFor(() => expect(api.fetchQualityIssues).toHaveBeenLastCalledWith("run", "quality-1", 1, "", "", 10));
  expect(screen.getByText(/납품 기준 v3 · 경고 모드/)).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "품질 JSON" })).toHaveAttribute("href", expect.stringContaining("revisionId=quality-1"));
});
it("sends issue filters and pagination to the server", async () => {
  vi.mocked(api.fetchQualityIssues).mockResolvedValue({ items: [issue], total: 41, page: 1, size: 20 });
  mount(); await screen.findByText("nested-child"); fireEvent.click(screen.getByRole("button", { name: "품질 이슈 다음 페이지" }));
  await waitFor(() => expect(api.fetchQualityIssues).toHaveBeenLastCalledWith("run", "quality-2", 2, "", "", 10));
  fireEvent.change(screen.getByLabelText("품질 이슈 페이지당 행 수"), { target: { value: "25" } });
  await waitFor(() => expect(api.fetchQualityIssues).toHaveBeenLastCalledWith("run", "quality-2", 1, "", "", 25));
  fireEvent.change(screen.getByLabelText("품질 심각도"), { target: { value: "error" } });
  await waitFor(() => expect(api.fetchQualityIssues).toHaveBeenLastCalledWith("run", "quality-2", 1, "error", "", 25));
  fireEvent.change(screen.getByLabelText("품질 규칙 ID"), { target: { value: "identity.missing" } });
  await waitFor(() => expect(api.fetchQualityIssues).toHaveBeenLastCalledWith("run", "quality-2", 1, "error", "identity.missing", 25));
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

it("shows category numerators and contributions without representing a non-applicable domain as 100", async () => {
  vi.mocked(api.fetchQualityRevisions).mockResolvedValue({ items: [{ ...revision, summary: { ...revision.summary, score: 83.75, blockingIssueCount: 1, scoreDetails: { domains: {
    identity: { score: 75, applicable: true, numerator: 3, denominator: 4, weight: 30, weightedContribution: 22.5 },
    graph: { score: 100, applicable: true, numerator: 4, denominator: 4, weight: 20, weightedContribution: 20 },
    integrity: { score: null, applicable: false, numerator: 0, denominator: 0, weight: 10, weightedContribution: null },
  } } } }], total: 1, page: 1, size: 20 });
  mount(); expect(await screen.findByText("가중 품질 점수 83.75 / 100")).toBeInTheDocument();
  expect(screen.getByText("3 / 4")).toBeInTheDocument(); expect(screen.getByText("22.5")).toBeInTheDocument();
  expect(screen.getByText("적용 불가")).toBeInTheDocument(); expect(screen.getByText(/높은 점수로 필수 오류를 상쇄할 수 없습니다/)).toBeInTheDocument();
});
it("keeps old unscored revisions unscored rather than displaying zero", async () => {
  mount(); expect(await screen.findByText("점수 없음 · 이전 엔진 또는 적용 불가")).toBeInTheDocument();
  expect(screen.queryByText(/가중 품질 점수 0/)).not.toBeInTheDocument();
});
it("edits the child scope and shows immutable parent-tag inheritance provenance", async () => {
  const inherited: QualityProfile = { ...profile, projectId: null, sourceId: "source-a", tag: "regulated", priority: 20, resolution: { kind: "parent_tag", projectId: "child-id", inheritedFrom: "parent-id", sourceId: "source-a", depth: 1, chain: [{ projectId: "child-id", sourceProjectId: "child", tags: [], active: true, profileVersion: 0, profileInherited: false }, { projectId: "parent-id", sourceProjectId: "parent", tags: ["regulated"], active: true, profileVersion: 0, profileInherited: false }] } };
  vi.mocked(api.fetchQualityRevisions).mockResolvedValue({ items: [{ ...revision, profileSnapshot: inherited }], total: 1, page: 1, size: 20 });
  vi.mocked(api.fetchEffectiveQualityProfile).mockResolvedValue({ profile: inherited, project: { id: "child-id", sourceId: "source-a", sourceProjectId: "child", tags: [] } });
  mount(); expect(await screen.findByText(/적용 경로: 부모 태그 기준/)).toBeInTheDocument(); expect(screen.getByText(/태그 regulated \(우선순위 20\)/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole("tab", { name: "프로젝트별 품질 기준" })); await screen.findByLabelText("품질 기준 이름");
  expect(api.fetchQualityProfile).toHaveBeenCalledWith("child-id"); expect(api.fetchQualityProfile).not.toHaveBeenCalledWith("parent-id");
});
it("validates weight sum before saving and sends explicit score threshold", async () => {
  vi.mocked(api.saveQualityProfile).mockResolvedValue({ ...profile, version: 5 });
  mount(); await screen.findByText("nested-child"); fireEvent.click(screen.getByRole("tab", { name: "프로젝트별 품질 기준" })); await screen.findByLabelText("품질 기준 이름");
  fireEvent.change(screen.getByLabelText("품질 식별 가중치"), { target: { value: "40" } });
  expect(screen.getByText(/합계가 100이어야 합니다/)).toBeInTheDocument(); expect(screen.getByRole("button", { name: "품질 기준 새 버전 저장" })).toBeDisabled();
  fireEvent.change(screen.getByLabelText("품질 의존성 관계 가중치"), { target: { value: "10" } });
  fireEvent.change(screen.getByLabelText("품질 최소 점수"), { target: { value: "92.5" } });
  fireEvent.click(screen.getByRole("button", { name: "품질 기준 새 버전 저장" }));
  await waitFor(() => expect(api.saveQualityProfile).toHaveBeenCalledWith("project-native-id", expect.objectContaining({ minScore: 92.5, scoreWeights: { identity: 40, graph: 10, license: 20, provenance: 20, integrity: 10 } })));
});
it("edits a source-scoped tag criterion with priority and server version", async () => {
  const tagged: QualityProfile = { ...profile, projectId: null, sourceId: "source-a", tag: "regulated", priority: 10 };
  vi.mocked(api.fetchQualityProfile).mockResolvedValueOnce(profile).mockResolvedValue(tagged);
  vi.mocked(api.fetchQualityTagProfiles).mockResolvedValue({ items: [tagged], total: 1, page: 1, size: 20 });
  vi.mocked(api.saveQualityProfile).mockResolvedValue({ ...tagged, priority: 30, version: 5 });
  mount(); await screen.findByText("nested-child"); fireEvent.click(screen.getByRole("tab", { name: "프로젝트별 품질 기준" })); await screen.findByLabelText("품질 기준 이름");
  fireEvent.change(screen.getByLabelText("품질 기준 편집 범위"), { target: { value: "tag" } });
  fireEvent.change(screen.getByLabelText("품질 기준 원본 ID"), { target: { value: "source-a" } }); fireEvent.change(screen.getByLabelText("품질 기준 태그"), { target: { value: "regulated" } });
  expect(screen.getByRole("button", { name: "품질 기준 새 버전 저장" })).toBeDisabled(); fireEvent.click(screen.getByRole("button", { name: "기준 불러오기" }));
  expect(await screen.findByLabelText("품질 태그 우선순위")).toHaveValue(10); expect(api.fetchQualityProfile).toHaveBeenLastCalledWith("", { sourceId: "source-a", tag: "regulated" });
  expect(await screen.findByText("regulated · 우선순위 10 · v4")).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("품질 태그 우선순위"), { target: { value: "30" } }); fireEvent.click(screen.getByRole("button", { name: "품질 기준 새 버전 저장" }));
  await waitFor(() => expect(api.saveQualityProfile).toHaveBeenCalledWith("", expect.objectContaining({ priority: 30, version: 4 }), { sourceId: "source-a", tag: "regulated" }));
});
it("disables an override as a versioned inheritance choice", async () => {
  vi.mocked(api.saveQualityProfile).mockResolvedValue({ ...profile, inherit: true, version: 5 });
  mount(); await screen.findByText("nested-child"); fireEvent.click(screen.getByRole("tab", { name: "프로젝트별 품질 기준" })); await screen.findByLabelText("품질 기준 이름");
  fireEvent.click(screen.getByLabelText("품질 기준 상속 사용")); expect(screen.getByLabelText("품질 기준 이름")).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "품질 기준 새 버전 저장" }));
  await waitFor(() => expect(api.saveQualityProfile).toHaveBeenCalledWith("project-native-id", expect.objectContaining({ inherit: true, version: 4 })));
  expect(await screen.findByText(/품질 기준 v5을 저장했습니다/)).toBeInTheDocument();
});
it("serializes tag scope and score controls without widening the API target", async () => {
  const actual = await vi.importActual<typeof import("./quality-api")>("./quality-api");
  const transport = await import("./api");
  vi.mocked(transport.request).mockResolvedValue(profile);
  await actual.saveQualityProfile("unused-project", { ...profile, scoreWeights: { identity: 40, graph: 10, license: 20, provenance: 20, integrity: 10 }, minScore: 95, priority: 7, inherit: true }, { sourceId: "source/a", tag: "규제 & prod" });
  const [url, init] = vi.mocked(transport.request).mock.calls.at(-1)!;
  expect(url).toBe("/api/v1/quality-profiles?sourceId=source%2Fa&tag=%EA%B7%9C%EC%A0%9C+%26+prod");
  expect(JSON.parse(String(init?.body))).toEqual(expect.objectContaining({ expectedVersion: 4, minScore: 95, priority: 7, inherit: true, scoreWeights: { identity: 40, graph: 10, license: 20, provenance: 20, integrity: 10 } }));
  expect(JSON.parse(String(init?.body))).not.toHaveProperty("projectId");
});
it("does not alias distinct source/tag targets that contain colon separators", async () => {
  vi.mocked(api.fetchQualityProfile).mockResolvedValue(profile);
  mount(); await screen.findByText("nested-child"); fireEvent.click(screen.getByRole("tab", { name: "프로젝트별 품질 기준" })); await screen.findByLabelText("품질 기준 이름");
  fireEvent.change(screen.getByLabelText("품질 기준 편집 범위"), { target: { value: "tag" } });
  fireEvent.change(screen.getByLabelText("품질 기준 원본 ID"), { target: { value: "a:b" } }); fireEvent.change(screen.getByLabelText("품질 기준 태그"), { target: { value: "c" } });
  fireEvent.click(screen.getByRole("button", { name: "기준 불러오기" })); await screen.findByLabelText("품질 태그 우선순위");
  expect(screen.getByRole("button", { name: "품질 기준 새 버전 저장" })).toBeEnabled();
  fireEvent.change(screen.getByLabelText("품질 기준 원본 ID"), { target: { value: "a" } }); fireEvent.change(screen.getByLabelText("품질 기준 태그"), { target: { value: "b:c" } });
  expect(screen.getByRole("button", { name: "품질 기준 새 버전 저장" })).toBeDisabled();
});
it("allows a zero quality score and zero score threshold without treating them as absent", async () => {
  vi.mocked(api.fetchQualityRevisions).mockResolvedValue({ items: [{ ...revision, summary: { ...revision.summary, score: 0, minScore: 0, scoreThresholdViolated: false }, comparison: { previousRevisionId: "quality-1", errorDelta: 0, warningDelta: 0, scoreDelta: 0 } }], total: 1, page: 1, size: 20 });
  mount(); expect(await screen.findByText("가중 품질 점수 0 / 100")).toBeInTheDocument();
  expect(screen.getByText("점수 하한 0점")).toBeInTheDocument(); expect(screen.getByText(/점수 0점/)).toBeInTheDocument();
  expect(screen.queryByText("점수 없음 · 이전 엔진 또는 적용 불가")).not.toBeInTheDocument();
});

it("trims only redundant fractional zeroes in scores, thresholds, ratios and comparisons", async () => {
  vi.mocked(api.fetchQualityRevisions).mockResolvedValue({ items: [{ ...revision,
    summary: { ...revision.summary, score: 50, minScore: 42.5, missingIdentityCount: 0, missingIdentityRatio: 0,
      fieldStatus: { identity: "available", integrity: "declared_only", license: "syntax_only" } },
    comparison: { previousRevisionId: "quality-1", errorDelta: 0, warningDelta: 0, scoreDelta: 1.25 },
  }], total: 1, page: 1, size: 20 });
  mount(); expect(await screen.findByText("가중 품질 점수 50 / 100")).toBeInTheDocument();
  expect(screen.getByText("점수 하한 42.5점")).toBeInTheDocument();
  expect(screen.getByText("0 (0%)")).toBeInTheDocument();
  expect(screen.getByText(/점수 \+1.25점/)).toBeInTheDocument();
  expect(screen.getByText("선언된 해시만 검사 (실제 파일 대조 전)").parentElement).toHaveClass("quality-field-wide");
  expect(screen.getByText("구문 검사 (법률상 호환성 판정 전)").parentElement).toHaveClass("quality-field-wide");
});

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import EnvironmentAdministrators from "./EnvironmentAdministrators";
import RunMetadataEditor from "./RunMetadataEditor";
import { fetchEnvironmentAdministrators, fetchRunEditPermission, saveEnvironmentAdministrators, updateRunMetadata, type RunEditPermission } from "./environment-admin-api";

vi.mock("./api", () => ({ previewMode: false }));
vi.mock("./environment-admin-api", () => ({ fetchEnvironmentAdministrators: vi.fn(), fetchRunEditPermission: vi.fn(), saveEnvironmentAdministrators: vi.fn(), updateRunMetadata: vi.fn() }));
const user = { id: "u1", username: "환경 담당자", role: "viewer", active: true, status: "active" };
const permission: RunEditPermission = { canEdit: true, canChangeScope: true, reason: null, editableEnvironmentIds: ["prod"], metadata: { serviceId: "svc", environmentId: "prod", releaseVersion: "1.0", note: "원래 메모" }, services: [{ id: "svc", name: "결제 API", slug: "pay" }], environments: [{ id: "prod", name: "운영", slug: "prod" }] };
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(fetchEnvironmentAdministrators).mockResolvedValue({ environments: [{ id: "prod", name: "운영", slug: "prod", active: true, administrators: [] }], users: [user] });
  vi.mocked(fetchRunEditPermission).mockResolvedValue(permission);
  vi.mocked(saveEnvironmentAdministrators).mockResolvedValue({ environmentId: "prod", userIds: ["u1"] });
  vi.mocked(updateRunMetadata).mockResolvedValue({ ...permission.metadata, runId: "run", roundNumber: 2, reanalysisPending: true });
});
afterEach(cleanup);

describe("environment administrator settings", () => {
  it("saves the selected environment and selected user ids", async () => {
    render(<EnvironmentAdministrators />);
    const checkbox = await screen.findByRole("checkbox", { name: /환경 담당자/ });
    expect(screen.getByRole("button", { name: "환경 관리자 저장" })).toBeDisabled();
    fireEvent.click(checkbox);
    fireEvent.click(screen.getByRole("button", { name: "환경 관리자 저장" }));
    await waitFor(() => expect(saveEnvironmentAdministrators).toHaveBeenCalledWith("prod", ["u1"]));
    expect(await screen.findByRole("status")).toHaveTextContent("저장했습니다");
  });
  it("keeps the selection and reports a server denial instead of claiming success", async () => {
    vi.mocked(saveEnvironmentAdministrators).mockRejectedValue(new Error("전체 관리자만 지정할 수 있습니다"));
    render(<EnvironmentAdministrators />);
    fireEvent.click(await screen.findByRole("checkbox", { name: /환경 담당자/ }));
    fireEvent.click(screen.getByRole("button", { name: "환경 관리자 저장" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("전체 관리자만");
    expect(screen.getByRole("checkbox")).toBeChecked();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });
  it("allows stale inactive assignments to be removed", async () => {
    vi.mocked(fetchEnvironmentAdministrators).mockResolvedValue({ environments: [{ id: "prod", name: "운영", slug: "prod", active: true, administrators: [{ ...user, active: false, status: "inactive" }] }], users: [] });
    render(<EnvironmentAdministrators />);
    fireEvent.click(await screen.findByRole("button", { name: "지정 해제" }));
    fireEvent.click(screen.getByRole("button", { name: "환경 관리자 저장" }));
    await waitFor(() => expect(saveEnvironmentAdministrators).toHaveBeenCalledWith("prod", []));
  });
  it("preserves another environment's unsaved selections when one environment is saved", async () => {
    const environments = [{ id: "prod", name: "운영", slug: "prod", active: true, administrators: [] as typeof user[] }, { id: "qa", name: "검증", slug: "qa", active: true, administrators: [] as typeof user[] }];
    vi.mocked(fetchEnvironmentAdministrators).mockResolvedValueOnce({ environments, users: [user] }).mockResolvedValue({ environments: [environments[0], { ...environments[1], administrators: [user] }], users: [user] });
    render(<EnvironmentAdministrators />);
    fireEvent.click(await screen.findByRole("checkbox", { name: /환경 담당자/ }));
    fireEvent.click(screen.getByRole("button", { name: /^검증$/ }));
    fireEvent.click(screen.getByRole("checkbox", { name: /환경 담당자/ }));
    fireEvent.click(screen.getByRole("button", { name: "환경 관리자 저장" }));
    await screen.findByRole("status");
    await waitFor(() => expect(screen.getByRole("button", { name: /^검증$/ })).toBeEnabled());
    fireEvent.click(screen.getByRole("button", { name: /^운영$/ }));
    expect(screen.getByRole("checkbox", { name: /환경 담당자/ })).toBeChecked();
    expect(screen.getByRole("button", { name: "환경 관리자 저장" })).toBeEnabled();
  });
});

describe("SBOM metadata editor", () => {
  it("hides edits when the server does not grant the environment", async () => {
    vi.mocked(fetchRunEditPermission).mockResolvedValue({ ...permission, canEdit: false });
    render(<RunMetadataEditor runId="run" onSaved={() => {}} />);
    await waitFor(() => expect(fetchRunEditPermission).toHaveBeenCalledWith("run"));
    expect(screen.queryByRole("button", { name: "SBOM 등록 정보 수정" })).not.toBeInTheDocument();
  });
  it("sends metadata fields and reports reanalysis after a successful edit", async () => {
    const onSaved = vi.fn();
    render(<RunMetadataEditor runId="run" onSaved={onSaved} />);
    fireEvent.click(await screen.findByRole("button", { name: "SBOM 등록 정보 수정" }));
    fireEvent.change(screen.getByLabelText("수정 릴리스"), { target: { value: "1.1" } });
    fireEvent.click(screen.getByRole("button", { name: "등록 정보 저장" }));
    await waitFor(() => expect(updateRunMetadata).toHaveBeenCalledWith("run", { releaseVersion: "1.1" }));
    expect(await screen.findByRole("status")).toHaveTextContent("새 정책 분석을 예약");
    expect(onSaved).toHaveBeenCalledOnce();
  });
  it("locks scope changes but permits a note on note-only runs", async () => {
    vi.mocked(fetchRunEditPermission).mockResolvedValue({ ...permission, canChangeScope: false, reason: "보관된 회차는 메모만 수정할 수 있습니다" });
    render(<RunMetadataEditor runId="run" onSaved={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: "SBOM 등록 정보 수정" }));
    expect(screen.getByLabelText("수정 환경")).toBeDisabled();
    expect(screen.getByLabelText("수정 서비스")).toBeDisabled();
    expect(screen.getByLabelText("수정 릴리스")).toBeDisabled();
    expect(screen.getByLabelText("수정 메모")).toBeEnabled();
    fireEvent.change(screen.getByLabelText("수정 메모"), { target: { value: "사유 보완" } });
    fireEvent.click(screen.getByRole("button", { name: "등록 정보 저장" }));
    await waitFor(() => expect(updateRunMetadata).toHaveBeenCalledWith("run", { note: "사유 보완" }));
  });
  it("reports a committed edit and refreshes the list even when permission refresh fails", async () => {
    vi.mocked(fetchRunEditPermission).mockResolvedValueOnce(permission).mockRejectedValue(new Error("후속 조회 실패"));
    const onSaved = vi.fn();
    render(<RunMetadataEditor runId="run" onSaved={onSaved} />);
    fireEvent.click(await screen.findByRole("button", { name: "SBOM 등록 정보 수정" }));
    fireEvent.change(screen.getByLabelText("수정 메모"), { target: { value: "저장된 메모" } });
    fireEvent.click(screen.getByRole("button", { name: "등록 정보 저장" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("저장은 완료");
    expect(screen.getByRole("status")).toHaveTextContent("저장");
    expect(onSaved).toHaveBeenCalledOnce();
  });
});

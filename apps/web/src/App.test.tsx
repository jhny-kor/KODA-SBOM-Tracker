import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import App, { ComponentInspector, KodaPortalLink, LoginPage, SettingsPage } from "./App";
import { allowedPages, canPermission, dataAccess, hasPermissions, pageForPermissions } from "./permissions";

afterEach(() => {
  cleanup();
  window.history.replaceState(null, "", "/");
});

describe("KODA SBOM Tracker", () => {
  it("offers LDAP as an explicit login choice", () => {
    render(<LoginPage onAuthenticated={() => {}} />);
    expect(screen.getByRole("checkbox", { name: "LDAP 사용" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "회원가입" }));
    expect(screen.getByRole("button", { name: "가입 신청" })).toBeInTheDocument();
    expect(screen.getByLabelText("비밀번호 확인")).toBeInTheDocument();
  });

  it("uses only explicit permissions in real auth users", () => {
    const manager = { id: "u1", username: "manager", role: "manager", active: true, permissions: ["runs.view"] };
    expect(canPermission(manager, "runs.view")).toBe(true);
    expect(canPermission(manager, "users.manage")).toBe(false);
    expect(allowedPages(manager)).toEqual(["runs"]);
  });

  it("honors wildcard permissions", () => {
    const admin = { id: "u1", username: "admin", role: "admin", active: true, permissions: ["*"] };
    expect(allowedPages(admin)).toHaveLength(5);
  });

  it("redirects direct and refreshed access to the first allowed page", () => {
    const user = { id: "u1", username: "viewer", role: "viewer", active: true, permissions: ["runs.view"] };
    expect(pageForPermissions(user, "settings")).toBe("runs");
    expect(pageForPermissions(user, "runs")).toBe("runs");
    expect(dataAccess({ ...user, permissions: ["dashboard.view"] })).toEqual({ runs: false, catalogs: false });
    expect(hasPermissions({ ...user, permissions: ["sbom.upload"] }, "sbom.upload", "services.view")).toBe(false);
  });

  it("shows a users-only manager settings surface", () => {
    render(<SettingsPage
      users={[{ id: "u2", username: "analyst", role: "analyst", active: true }]}
      services={[]} tokens={[]} dtrackStatus={null}
      policies={[{ role: "admin", permissions: ["roles.manage"] }]}
      roleCatalog={["roles.manage"]} bundles={[]} auditEvents={[]}
      isAdmin={false} canVulnerability={false} canVulnerabilityManage={false} canAudit={false}
      canUsers canTokens={false} canDtrack={false}
      canPolicyEdit={false} canRoles={false} onSync={async () => {}} onActivate={async () => {}}
      onPolicyChanged={async () => {}} onChanged={() => {}}
    />);
    expect(screen.getByRole("heading", { name: "사용자 1명" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /API 토큰/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Dependency-Track 연결" })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "역할 정책" })).not.toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "관리자" })).not.toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "매니저" })).not.toBeInTheDocument();
  });

  it("distinguishes pending signup approval from inactive users", () => {
    render(<SettingsPage
      users={[
        { id: "pending", username: "new-user", role: "viewer", active: false, status: "pending" },
        { id: "inactive", username: "stopped-user", role: "viewer", active: false, status: "inactive" },
      ]}
      services={[]} tokens={[]} dtrackStatus={null}
      policies={[{ role: "admin", permissions: ["roles.manage"] }]}
      roleCatalog={["roles.manage"]} bundles={[]} auditEvents={[]}
      isAdmin canVulnerability={false} canVulnerabilityManage={false} canAudit={false}
      canUsers canTokens={false} canDtrack={false}
      canPolicyEdit canRoles onSync={async () => {}} onActivate={async () => {}}
      onPolicyChanged={async () => {}} onChanged={() => {}}
    />);
    expect(screen.getByText("승인 대기")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "승인" })).toBeInTheDocument();
    expect(screen.getByText("비활성")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "활성화" })).toBeInTheDocument();
  });

  it("groups administrator security data under Korean settings tabs", () => {
    render(<SettingsPage
      users={[]} services={[]} tokens={[]} dtrackStatus={null}
      policies={[{ role: "admin", permissions: ["audit.view", "vulnerability.view"] }]}
      roleCatalog={["audit.view", "vulnerability.view"]}
      bundles={[{ id: "bundle-1", version: "2026.08", dataAsOf: "2026-08-01", nvdDataAsOf: "2026-08-01", kevDataAsOf: "2026-08-01", grypeDbSchema: "6", aliasCount: 1, kevCount: 1, manifestSha256: "secret-sha", active: true, importedAt: "2026-08-01T00:00:00Z" }]}
      auditEvents={[{ id: "audit-1", actor: "admin", action: "login", targetType: "session", targetId: "1", detail: { sha256: "secret-sha", round: 1 }, createdAt: "2026-08-01T00:00:00Z" }]}
      isAdmin canVulnerability canVulnerabilityManage canAudit
      canUsers={false} canTokens={false} canDtrack={false} canPolicyEdit canRoles
      onSync={async () => {}} onActivate={async () => {}}
      onPolicyChanged={async () => {}} onChanged={() => {}}
    />);
    expect(screen.getByRole("tab", { name: "권한 관리" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "취약점 데이터" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "감사 로그" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "취약점 데이터" }));
    expect(screen.getByRole("heading", { name: "취약점 데이터" })).toBeInTheDocument();
    expect(screen.queryByText("secret-sha")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "감사 로그" }));
    expect(screen.getByRole("heading", { name: "감사 로그" })).toBeInTheDocument();
    expect(screen.queryByText("secret-sha")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "권한 관리" }));
    expect(screen.getByText("관리자")).toBeInTheDocument();
    expect(screen.getByText("감사 로그 조회")).toBeInTheDocument();
  });

  it("hides artifact and Dependency-Track links without action permissions", () => {
    const change = { identityKey: "pkg:a", change: "changed" as const, name: "a", purl: "pkg:a", fields: [] };
    const comparison = {
      base: { runId: "a", sha256: "a".repeat(64), dataAsOf: null, artifactUrl: "/a" },
      target: { runId: "b", sha256: "b".repeat(64), dataAsOf: null, artifactUrl: "/b" },
      summary: { componentsAdded: 0, componentsRemoved: 0, componentsChanged: 1, vulnerabilitiesAdded: 0, vulnerabilitiesRemoved: 0, policiesChanged: 0 },
      components: [], vulnerabilities: [], policies: [],
    };
    const { rerender } = render(<ComponentInspector change={change} comparison={comparison} can={() => false} />);
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
    rerender(<ComponentInspector change={change} comparison={comparison} can={(permission) => permission === "artifact.download"} />);
    expect(screen.getAllByRole("link")).toHaveLength(2);
    expect(screen.queryByRole("link", { name: /Dependency-Track/ })).not.toBeInTheDocument();
  });

  it("opens the KODA security analysis portal in a new browser context", () => {
    render(<KodaPortalLink />);
    const link = screen.getByRole("link", { name: "KODA 보안 분석" });
    expect(link).toHaveAttribute("href", "/koda/");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expect(link.querySelector("svg path")).toBeInTheDocument();
  });

  it("renders dense run history and opens comparison", () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: "SBOM 회차" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "완료" })).toHaveValue("completed");
    expect(screen.queryByRole("button", { name: "알림" })).not.toBeInTheDocument();
    expect(screen.getAllByText("결제 API").length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("button", { name: "회차 비교" }));
    expect(screen.getByRole("heading", { name: "회차 비교" })).toBeInTheDocument();
    expect(screen.getByText("구성요소 추가")).toBeInTheDocument();
  });

  it("searches run history by component metadata", async () => {
    render(<App />);
    fireEvent.change(screen.getByRole("textbox", { name: "전체 검색" }), { target: { value: "httpclient" } });
    expect(await screen.findByRole("cell", { name: "결제 API" })).toBeInTheDocument();
    expect(screen.queryByText("회원 서비스")).not.toBeInTheDocument();
  });

  it("colors comparison vulnerability status by severity", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "회차 비교" }));
    await screen.findByText("구성요소 추가");
    fireEvent.click(screen.getByRole("tab", { name: "취약점" }));
    expect(await screen.findByText("높음")).toHaveClass("severity-pill", "high");
    expect(screen.getByText("중간")).toHaveClass("severity-pill", "medium");
  });

  it("logs out from the account accordion", async () => {
    render(<App />);
    const accountButton = screen.getByRole("button", { name: "보안운영팀" });
    expect(accountButton).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(accountButton);
    expect(accountButton).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText("미리보기 사용자")).toBeInTheDocument();
    expect(screen.getByText("관리자")).toBeInTheDocument();
    const logoutButton = screen.getByRole("button", { name: "로그아웃" });
    expect(logoutButton).toBeEnabled();
    fireEvent.click(logoutButton);
    await waitFor(() => expect(screen.getByRole("heading", { name: "KODA SBOM Tracker" })).toBeInTheDocument());
  });

  it("opens upload dialog", () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: /SBOM 업로드/ }));
    expect(screen.getByRole("dialog", { name: "SBOM 업로드" })).toBeInTheDocument();
  });

  it("shows analysis charts on the server dashboard", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "대시보드" }));
    expect(await screen.findByRole("img", { name: "업로드별 구성요소와 취약점 추이" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "최신 SBOM 심각도" })).toBeInTheDocument();
    expect(screen.getByText("OPERATIONS SBOM PORTFOLIO")).toBeInTheDocument();
  });

  it("opens a run from a KODA deep link", async () => {
    window.history.replaceState(null, "", "/?runId=run-1");
    render(<App />);
    expect(screen.getByRole("heading", { name: "1.4.2 · 3차" })).toBeInTheDocument();
    expect(screen.getByRole("dialog", { name: "1.4.2 · 3차" })).toHaveClass("detail-modal");
    expect(screen.queryByText("SHA-256")).not.toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "구성요소 검색" })).toBeInTheDocument();
    expect(screen.getAllByRole("combobox", { name: "상세 페이지당 행 수" })).toHaveLength(2);
    await waitFor(() => expect(screen.getByText((_, element) => element?.tagName === "LI" && element.textContent?.includes("r1 · 완료 ·") === true)).toBeInTheDocument());
    expect(screen.getAllByText("결제 API").length).toBeGreaterThan(0);
  });
});

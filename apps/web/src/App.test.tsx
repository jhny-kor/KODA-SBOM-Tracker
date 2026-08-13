import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import App, { ComponentInspector, LoginPage, SettingsPage } from "./App";
import { allowedPages, canPermission, dataAccess, hasPermissions, pageForPermissions } from "./permissions";

afterEach(() => {
  cleanup();
  window.history.replaceState(null, "", "/");
});

describe("KODA SBOM Tracker", () => {
  it("offers LDAP as an explicit login choice", () => {
    render(<LoginPage onAuthenticated={() => {}} />);
    expect(screen.getByRole("checkbox", { name: "LDAP 사용" })).toBeInTheDocument();
  });

  it("uses only explicit permissions in real auth users", () => {
    const manager = { id: "u1", username: "manager", role: "manager", active: true, permissions: ["runs.view"] };
    expect(canPermission(manager, "runs.view")).toBe(true);
    expect(canPermission(manager, "users.manage")).toBe(false);
    expect(allowedPages(manager)).toEqual(["runs"]);
  });

  it("honors wildcard permissions", () => {
    const admin = { id: "u1", username: "admin", role: "admin", active: true, permissions: ["*"] };
    expect(allowedPages(admin)).toHaveLength(7);
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
      roleCatalog={["roles.manage"]} canUsers canTokens={false} canDtrack={false}
      canPolicyEdit={false} canRoles={false} onPolicyChanged={async () => {}} onChanged={() => {}}
    />);
    expect(screen.getByRole("heading", { name: "사용자 1명" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /API 토큰/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Dependency-Track 연결" })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "역할 정책" })).not.toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "관리자" })).not.toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "매니저" })).not.toBeInTheDocument();
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

  it("renders dense run history and opens comparison", () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: "SBOM 회차" })).toBeInTheDocument();
    expect(screen.getAllByText("결제 API").length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("button", { name: "회차 비교" }));
    expect(screen.getByRole("heading", { name: "회차 비교" })).toBeInTheDocument();
    expect(screen.getByText("구성요소 추가")).toBeInTheDocument();
  });

  it("opens the account accordion and closes it with Escape", () => {
    render(<App />);
    const accountButton = screen.getByRole("button", { name: "보안운영팀" });
    expect(accountButton).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(accountButton);
    expect(accountButton).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText("미리보기 사용자")).toBeInTheDocument();
    expect(screen.getByText("관리자")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "로그아웃" })).toBeDisabled();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(accountButton).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByText("미리보기 사용자")).not.toBeInTheDocument();
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

  it("opens a run from a KODA deep link", () => {
    window.history.replaceState(null, "", "/?runId=run-1");
    render(<App />);
    expect(screen.getByRole("heading", { name: "1.4.2 · 3차" })).toBeInTheDocument();
    expect(screen.getAllByText("결제 API").length).toBeGreaterThan(0);
  });
});

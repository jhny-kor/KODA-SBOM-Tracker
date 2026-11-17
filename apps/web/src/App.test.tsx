import { demoRuns } from "./demo";
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App, { Dashboard, ComponentInspector, KodaPortalLink, LoginPage, SettingsPage } from "./App";
import { formatSeoulDateTime } from "./format";
import { allowedPages, canPermission, dataAccess, hasPermissions, pageForPermissions } from "./permissions";

beforeEach(() => { vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} }); });
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  window.history.replaceState(null, "", "/");
});

describe("KODA SBOM Tracker", () => {
  it("expands the sidebar from the KODA logo without navigating", () => {
    render(<App />);
    const collapse = screen.queryByRole("button", { name: "사이드바 접기" });
    if (collapse) fireEvent.click(collapse);
    const logo = screen.getByRole("button", { name: "KODA 로고로 사이드바 펼치기" });
    expect(logo).toHaveAttribute("aria-expanded", "false");
    const url = window.location.href;
    fireEvent.click(logo);
    expect(logo).toHaveAttribute("aria-expanded", "true");
    expect(document.querySelector(".app-shell")).not.toHaveClass("is-collapsed");
    expect(window.location.href).toBe(url);
  });

  it("shows sample LDAP settings without allowing a save", async () => {
    window.history.replaceState(null, "", "/?page=settings");
    render(<App />);
    fireEvent.click(await screen.findByRole("tab", { name: "LDAP 로그인" }));
    expect(await screen.findByLabelText("LDAP 서버")).toHaveValue("ldap.example.com");
    expect(screen.getByRole("button", { name: "샘플 모드 · 저장 안 함" })).toBeDisabled();
    expect(screen.getByRole("note")).toHaveTextContent("실제 연결·저장은 하지 않습니다");
  });

  it("offers LDAP as an explicit login choice", () => {
    render(<LoginPage onAuthenticated={() => {}} />);
    expect(screen.getByLabelText("아이디")).toBeInTheDocument();
    expect(screen.getByLabelText("비밀번호")).toBeInTheDocument();
    expect(screen.getByRole("checkbox", { name: "LDAP 사용" })).toBeChecked();
    expect(screen.getByRole("img", { name: "KODA" })).toHaveAttribute("src", "/KODA.ico");
    fireEvent.click(screen.getByRole("button", { name: "회원가입" }));
    expect(screen.getByRole("button", { name: "가입 신청" })).toBeInTheDocument();
    expect(screen.getByLabelText("비밀번호 확인")).toBeInTheDocument();
  });

  it("uses only explicit permissions in real auth users", () => {
    const manager = { id: "u1", username: "manager", role: "manager", active: true, permissions: ["runs.view"] };
    expect(canPermission(manager, "runs.view")).toBe(true);
    expect(canPermission(manager, "users.manage")).toBe(false);
    expect(allowedPages(manager)).toEqual(["runs", "libraries", "guide"]);
  });

  it("honors wildcard permissions", () => {
    const admin = { id: "u1", username: "admin", role: "admin", active: true, permissions: ["*"] };
    expect(allowedPages(admin)).toHaveLength(6);
  });

  it("redirects direct and refreshed access to the first allowed page", () => {
    const user = { id: "u1", username: "viewer", role: "viewer", active: true, permissions: ["runs.view"] };
    expect(pageForPermissions(user, "settings")).toBe("runs");
    expect(pageForPermissions(user, "runs")).toBe("runs");
    expect(dataAccess({ ...user, permissions: ["dashboard.view"] })).toEqual({ runs: false, catalogs: false });
    expect(hasPermissions({ ...user, permissions: ["sbom.upload"] }, "sbom.upload", "services.view")).toBe(false);
    expect(pageForPermissions({ ...user, permissions: ["services.view"] }, "settings")).toBe("settings");
    expect(pageForPermissions({ ...user, permissions: [] }, "dashboard")).toBe("guide");
    expect(formatSeoulDateTime("2026-08-28T00:00:00Z")).toBe("2026-08-28 09:00:00");
    expect(formatSeoulDateTime("2026-08-28T00:00:00")).toBe("2026-08-28 09:00:00");
  });

  it("shows service settings to services.view without management actions", () => {
    render(<SettingsPage
      users={[]} services={[{ id: "svc", name: "결제 API", slug: "payment", active: true }]}
      environments={[{ id: "prod", name: "운영", slug: "prod", active: true, sortOrder: 1 }]}
      tokens={[]} ldapSettings={null} policies={[]} roleCatalog={[]}
      bundles={[]} auditEvents={[]} isAdmin={false} canVulnerability={false}
      canVulnerabilityManage={false} canAudit={false} canUsers={false} canTokens={false}
      canPolicyEdit={false} canRoles={false} canServices
      canCatalogManage={false} initialTab="services" onSync={async () => {}}
      onActivate={async () => {}} onPolicyChanged={async () => {}} onLdapChanged={() => {}}
      onChanged={() => {}}
    />);
    expect(screen.getByRole("tab", { name: "서비스·환경" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "서비스 1개" })).toBeInTheDocument();
    expect(screen.getByText("운영")).toBeInTheDocument();
    expect(screen.queryByRole("columnheader", { name: "상태" })).not.toBeInTheDocument();
    expect(within(screen.getByRole("row", { name: /결제 API/ })).getByRole("button", { name: "연동 ID 복사" })).toHaveAttribute("title", "svc");
    expect(within(screen.getByRole("row", { name: /운영/ })).getByRole("button", { name: "연동 ID 복사" })).toHaveAttribute("title", "prod");
    expect(screen.queryByRole("button", { name: "삭제" })).not.toBeInTheDocument();
  });

  it("reveals the GitLab delivery token with its Tracker service ID", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ id: "token-1", name: "group-project", token: "koda_secret", serviceId: "svc-uuid" }), { status: 201, headers: { "Content-Type": "application/json" } }));
    render(<SettingsPage
      users={[]} services={[{ id: "svc-uuid", name: "group/project", slug: "group-project", active: true }]}
      tokens={[]} ldapSettings={null} policies={[]} roleCatalog={[]}
      bundles={[]} auditEvents={[]} isAdmin canVulnerability={false}
      canVulnerabilityManage={false} canAudit={false} canUsers={false} canTokens
      canPolicyEdit={false} canRoles={false}
      onSync={async () => {}} onActivate={async () => {}} onPolicyChanged={async () => {}}
      onLdapChanged={() => {}} onChanged={() => {}}
    />);
    fireEvent.click(screen.getByRole("button", { name: "API 토큰 발급" }));
    fireEvent.change(screen.getByLabelText("토큰 이름"), { target: { value: "group-project" } });
    fireEvent.change(screen.getByLabelText("허용 서비스"), { target: { value: "svc-uuid" } });
    fireEvent.click(screen.getByRole("button", { name: "확인" }));
    expect(await screen.findByText("koda_secret")).toBeInTheDocument();
    expect(screen.getByText("svc-uuid")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "토큰 복사" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "서비스 ID 복사" })).toBeInTheDocument();
  });

  it("shows GitLab connection readiness inside the integration settings tab", () => {
    render(<SettingsPage
      users={[]} services={[{ id: "svc-uuid", name: "group/project", slug: "gitlab-42-a1b2c3d4e5f6", active: true }]}
      environments={[{ id: "env-uuid", name: "GitLab 소스", slug: "gitlab-source", active: true, sortOrder: 50 }]}
      tokens={[{ id: "token-1", name: "group-project", serviceId: "svc-uuid", active: true, createdAt: "2026-08-29T00:00:00Z" }]} ldapSettings={null} policies={[]} roleCatalog={[]}
      bundles={[]} auditEvents={[]} isAdmin canVulnerability={false}
      canVulnerabilityManage={false} canAudit={false} canUsers={false} canTokens
      canPolicyEdit={false} canRoles={false} canServices
      canCatalogManage={false} onSync={async () => {}} onActivate={async () => {}}
      onPolicyChanged={async () => {}} onLdapChanged={() => {}} onChanged={() => {}}
    />);
    expect(screen.queryByRole("tab", { name: "GitLab 연동" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "연동 설정" }));
    expect(screen.getByRole("heading", { name: "KODA GitLab 자동 연동" })).toBeInTheDocument();
    expect(screen.getByText("GitLab 저장소 → KODA 점검·CycloneDX 생성 → Tracker 회차 수신·분석 → KODA가 GitLab 결과 MR·취약점 이슈 저장")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "기존 외부 시스템 연결" })).not.toBeInTheDocument();
    expect(screen.getByText("gitlab-source 환경이 자동 준비되었습니다.")).toBeInTheDocument();
    expect(screen.getByRole("row", { name: /group\/project.*활성/ })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "자동 생성 항목 보기" }));
    expect(screen.getByRole("heading", { name: "서비스 1개" })).toBeInTheDocument();
  });



  it("orders catalog actions and hides deleted services and environments", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<SettingsPage
      users={[]} services={[{ id: "svc", name: "결제 API", slug: "payment", active: true }]}
      environments={[{ id: "prod", name: "운영", slug: "prod", active: true, sortOrder: 1 }]}
      tokens={[]} ldapSettings={null} policies={[]} roleCatalog={[]}
      bundles={[]} auditEvents={[]} isAdmin={false} canVulnerability={false}
      canVulnerabilityManage={false} canAudit={false} canUsers={false} canTokens={false}
      canPolicyEdit={false} canRoles={false} canServices
      canCatalogManage initialTab="services" onSync={async () => {}}
      onActivate={async () => {}} onPolicyChanged={async () => {}} onLdapChanged={() => {}}
      onChanged={() => {}}
    />);
    const serviceAdd = screen.getByRole("button", { name: "서비스 추가" });
    expect(within(serviceAdd.parentElement as HTMLElement).getAllByRole("button").map((button) => button.textContent)).toEqual(["서비스 추가", "환경 추가"]);
    fireEvent.click(within(screen.getByRole("row", { name: /결제 API/ })).getByRole("button", { name: "삭제" }));
    await waitFor(() => expect(screen.queryByRole("row", { name: /결제 API/ })).not.toBeInTheDocument());
    fireEvent.click(within(screen.getByRole("row", { name: /운영/ })).getByRole("button", { name: "삭제" }));
    await waitFor(() => expect(screen.queryByRole("row", { name: /운영/ })).not.toBeInTheDocument());
  });

  it("shows a users-only manager settings surface", () => {
    render(<SettingsPage
      users={[{ id: "u2", username: "analyst", role: "analyst", active: true }]}
      services={[]} tokens={[]} ldapSettings={null}
      policies={[{ role: "admin", permissions: ["roles.manage"] }]}
      roleCatalog={["roles.manage"]} bundles={[]} auditEvents={[]}
      isAdmin={false} canVulnerability={false} canVulnerabilityManage={false} canAudit={false}
      canUsers canTokens={false}
      canPolicyEdit={false} canRoles={false} onSync={async () => {}} onActivate={async () => {}}
      onPolicyChanged={async () => {}} onLdapChanged={() => {}} onChanged={() => {}}
    />);
    expect(screen.getByRole("heading", { name: "사용자 1명" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /API 토큰/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "기존 외부 시스템 연결" })).not.toBeInTheDocument();
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
      services={[]} tokens={[]} ldapSettings={null}
      policies={[{ role: "admin", permissions: ["roles.manage"] }]}
      roleCatalog={["roles.manage"]} bundles={[]} auditEvents={[]}
      isAdmin canVulnerability={false} canVulnerabilityManage={false} canAudit={false}
      canUsers canTokens={false}
      canPolicyEdit canRoles onSync={async () => {}} onActivate={async () => {}}
      onPolicyChanged={async () => {}} onLdapChanged={() => {}} onChanged={() => {}}
    />);
    expect(screen.getByText("승인 대기")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "승인" })).toBeInTheDocument();
    expect(screen.getByText("비활성")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "활성화" })).toBeInTheDocument();
  });

  it("groups administrator security data under Korean settings tabs", () => {
    render(<SettingsPage
      users={[]} services={[]} tokens={[]} ldapSettings={null}
      policies={[{ role: "admin", permissions: ["audit.view", "vulnerability.view"] }]}
      roleCatalog={["audit.view", "vulnerability.view"]}
      bundles={[{ id: "bundle-1", version: "2026.08", dataAsOf: "2026-08-01", nvdDataAsOf: "2026-08-01", kevDataAsOf: "2026-08-01", grypeDbSchema: "6", aliasCount: 1, kevCount: 1, manifestSha256: "secret-sha", active: true, importedAt: "2026-08-01T00:00:00Z" }]}
      auditEvents={[{ id: "audit-1", actor: "admin", action: "login", targetType: "session", targetId: "1", detail: { sha256: "secret-sha", round: 1 }, createdAt: "2026-08-01T00:00:00Z" }]}
      isAdmin canVulnerability canVulnerabilityManage canAudit
      canUsers={false} canTokens={false} canPolicyEdit canRoles
      onSync={async () => {}} onActivate={async () => {}}
      onPolicyChanged={async () => {}} onLdapChanged={() => {}} onChanged={() => {}}
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
    expect(screen.getAllByText("관리자")).toHaveLength(2);
    expect(screen.queryByText("감사 로그 조회")).not.toBeInTheDocument();
  });

  it("groups permissions and disables sbom.delete outside the admin role", () => {
    const catalog = ["dashboard.view", "services.view", "runs.view", "compare.view", "vulnerability.view", "audit.view", "settings.view", "sbom.upload", "catalog.manage", "users.manage", "sbom.delete"];
    render(<SettingsPage
      users={[]} services={[]} tokens={[]} ldapSettings={null}
      policies={[{ role: "admin", permissions: ["sbom.delete"] }, { role: "viewer", permissions: [] }]}
      roleCatalog={catalog} bundles={[]} auditEvents={[]} isAdmin canVulnerability={false}
      canVulnerabilityManage={false} canAudit={false} canUsers={false} canTokens={false}
      canPolicyEdit canRoles onSync={async () => {}} onActivate={async () => {}}
      onPolicyChanged={async () => {}} onLdapChanged={() => {}} onChanged={() => {}}
    />);
    fireEvent.click(screen.getByRole("tab", { name: "권한 관리" }));
    for (const name of ["화면 접근 권한", "기능 제어", "SBOM·분석", "운영 관리", "계정·권한"]) {
      expect(screen.getAllByRole("heading", { name }).length).toBeGreaterThan(0);
    }
    const screenAccess = screen.getByRole("group", { name: "관리자 화면 접근 권한" });
    for (const name of ["대시보드", "SBOM 회차", "회차 비교", "설정"]) {
      expect(within(screenAccess).getByRole("checkbox", { name })).toBeInTheDocument();
    }
    for (const name of ["서비스", "취약점 데이터", "감사 로그", "대시보드 조회"]) {
      expect(within(screenAccess).queryByRole("checkbox", { name })).not.toBeInTheDocument();
    }
    const deletePermissions = screen.getAllByRole("checkbox", { name: "회차 영구 삭제" });
    expect(deletePermissions[0]).toBeEnabled();
    expect(deletePermissions[1]).toBeDisabled();
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
    expect(screen.queryByRole("link", { name: /기존 외부 시스템/ })).not.toBeInTheDocument();
  });

  it("opens the KODA security analysis portal in a new browser context", () => {
    render(<KodaPortalLink />);
    const link = screen.getByRole("link", { name: "KODA 보안 분석" });
    expect(link).toHaveAttribute("href", "/koda/");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expect(link.querySelector("svg image")).toHaveAttribute("href", "/KODA.ico");
  });

  it("renders dense run history and opens comparison", () => {
    const { container } = render(<App />);
    expect(screen.getByRole("heading", { name: "대시보드" })).toBeInTheDocument();
    expect(screen.getAllByText("구성요소 유형").length).toBeGreaterThan(0);
    const sparklinePoint = container.querySelector(".preview-sparkline circle");
    expect(sparklinePoint).not.toBeNull();
    fireEvent.mouseEnter(sparklinePoint!);
    expect(screen.getByRole("tooltip")).toHaveTextContent(/#\d+.*CVE 기준일.*\d+/);
    fireEvent.mouseLeave(sparklinePoint!);
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();
    const trendPoint = container.querySelector(".preview-chart .preview-chart-point");
    expect(trendPoint).not.toBeNull();
    fireEvent.mouseEnter(trendPoint!);
    expect(screen.getByRole("tooltip")).toHaveTextContent(/구성요소 · #\d+.*CVE 기준일/);
    expect(container.querySelector(".preview-chart-point title")).not.toBeInTheDocument();
    expect(screen.queryByText("연결 상태: 오프라인")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "SBOM 회차" }));
    expect(screen.getByRole("heading", { name: "SBOM 회차" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "페이지당 행 수" })).toHaveValue("10");
    expect(screen.getByRole("option", { name: "완료" })).toHaveValue("completed");
    expect(screen.queryByRole("button", { name: "알림" })).not.toBeInTheDocument();
    expect(screen.getAllByText("결제 API").length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("button", { name: "회차 비교" }));
    expect(screen.getByRole("heading", { name: "회차 비교" })).toBeInTheDocument();
    expect(screen.getByText("구성요소 추가")).toBeInTheDocument();
  });

  it("opens the common user guide from the bottom sidebar menu", () => {
    const { container } = render(<App />);
    const guide = screen.getByRole("button", { name: "사용 가이드" });
    expect(guide.closest("nav")).toHaveAttribute("aria-label", "도움말 메뉴");
    fireEvent.click(guide);
    expect(screen.getByRole("heading", { name: "사용 가이드" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "주요 기능" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "용어 설명" })).toBeInTheDocument();
    const guidePage = screen.getByRole("heading", { name: "사용 가이드" }).closest("section") as HTMLElement;
    expect(container.querySelectorAll(".guide-lead > span")).toHaveLength(2);
    expect(screen.getByText("SBOM (Software Bill of Materials)", { selector: "dt" })).toBeInTheDocument();
    expect(screen.getByText("CVE (Common Vulnerabilities and Exposures)", { selector: "dt" })).toBeInTheDocument();
    expect(screen.getByText("CVSS (Common Vulnerability Scoring System)", { selector: "dt" })).toBeInTheDocument();
    expect(screen.getByText("NVD (National Vulnerability Database)", { selector: "dt" })).toBeInTheDocument();
    expect(screen.getByText("KEV (Known Exploited Vulnerabilities)", { selector: "dt" })).toBeInTheDocument();
    for (const removed of [/Dependency-Track/, /LDAP/, /RBAC/, /분석 리비전/]) expect(within(guidePage).queryByText(removed)).not.toBeInTheDocument();
    expect(window.location.search).toContain("page=guide");
  });

  it("searches run history by component metadata", async () => {
    render(<App />);
    fireEvent.change(screen.getByRole("textbox", { name: "전체 검색" }), { target: { value: "httpclient" } });
    expect(await screen.findByRole("cell", { name: "결제 API" })).toBeInTheDocument();
    expect(screen.queryByRole("cell", { name: "회원 서비스" })).not.toBeInTheDocument();
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
    const accountButton = screen.getByRole("button", { name: "preview" });
    expect(accountButton).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(accountButton);
    expect(accountButton).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText("미리보기 사용자")).toBeInTheDocument();
    expect(screen.getByText("관리자")).toBeInTheDocument();
    expect(screen.queryByText("로컬 미리보기 모드에서는 서버 세션을 사용하지 않습니다.")).not.toBeInTheDocument();
    const logoutButton = screen.getByRole("button", { name: "로그아웃" });
    expect(logoutButton).toBeEnabled();
    fireEvent.click(logoutButton);
    await waitFor(() => expect(screen.getByRole("heading", { name: "KODA SBOM Tracker" })).toBeInTheDocument());
  });

  it("opens upload dialog", () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: /SBOM 업로드/ }));
    expect(screen.getByRole("dialog", { name: "SBOM 업로드" })).toBeInTheDocument();
    expect(screen.getByText("지원 형식: CycloneDX 1.4, 1.5, 1.6, 1.7 (JSON/XML) · SPDX 2.3 (JSON)")).toBeInTheDocument();
    expect(screen.getByLabelText("SBOM 파일")).toHaveAccessibleDescription(/CycloneDX 1\.4, 1\.5, 1\.6, 1\.7.*SPDX 2\.3/);
    expect(screen.getByLabelText("SBOM 파일")).toHaveAttribute("accept", expect.stringContaining(".json,.xml,.zip,.tar,.tar.gz,.tgz,.7z"));
    expect(screen.getByLabelText("SBOM 파일")).toHaveAttribute("accept", expect.stringContaining(".xlsx"));
    expect(screen.getByLabelText("SBOM 파일")).toHaveAccessibleDescription(/Excel \(\.xlsx, 최대 10 MiB\)/);
    expect(screen.getByLabelText("SBOM 파일")).toHaveAccessibleDescription(/ZIP.*TAR\.GZ\/TGZ.*TAR.*7Z.*JSON\/XML 문서 파일만 정확히 1개/);
    expect(screen.getByLabelText("SBOM 파일")).toHaveAccessibleDescription(/README 등 동반 파일은 허용하지 않습니다/);
    expect(screen.getByLabelText("SBOM 파일")).toHaveAttribute("accept", expect.not.stringContaining(".rar"));
    expect(screen.getByLabelText("SBOM 파일")).toHaveAccessibleDescription(/최대 500 MiB/);
  });

  it("shows analysis charts on the server dashboard", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "대시보드" }));
    const chart = await screen.findByRole("img", { name: "업로드별 구성요소와 취약 구성요소 추이" });
    expect(chart).toBeInTheDocument();
    const point = chart.querySelector('[aria-label="취약 구성요소 · #1 · 회원 서비스/검증 · 2 · CVE 기준일 2025-05-21"]');
    expect(point).not.toBeNull();
    fireEvent.mouseEnter(point!);
    expect(screen.getByRole("tooltip")).toHaveTextContent("취약 구성요소 · #1 · 회원 서비스/검증 · 2");
    expect(screen.getByRole("heading", { name: "최신 SBOM 심각도" })).toBeInTheDocument();
    expect(screen.getByText("OPERATIONS SBOM PORTFOLIO")).toBeInTheDocument();
  });

  it("shows default role policies in preview mode", () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "설정" }));
    fireEvent.click(screen.getByRole("tab", { name: "권한 관리" }));
    const admin = screen.getByRole("group", { name: "관리자 기능 제어" });
    const viewer = screen.getByRole("group", { name: "조회자 기능 제어" });
    expect(within(admin).getByRole("checkbox", { name: "회차 영구 삭제" })).toBeChecked();
    expect(within(viewer).getByRole("checkbox", { name: "회차 영구 삭제" })).toBeDisabled();
  });

  it("shows the distinct vulnerable component total in the SBOM round table", async () => {
    window.history.replaceState(null, "", "/?page=runs");
    render(<App />);
    const column = await screen.findByRole("columnheader", { name: "취약 구성요소" });
    const row = (await screen.findByText("결제 API", { selector: "td *" })).closest("tr")!;
    expect(within(row).getAllByRole("cell")[(column as HTMLTableCellElement).cellIndex]).toHaveTextContent(/^4$/);
  });

  it("opens a run from a KODA deep link", async () => {
    window.history.replaceState(null, "", "/?runId=run-1");
    render(<App />);
    expect(screen.getByRole("heading", { name: "1.4.2 · 3차" })).toBeInTheDocument();
    const detail = screen.getByRole("dialog", { name: "1.4.2 · 3차" });
    expect(detail).toHaveClass("detail-modal");
    expect(within(detail).getByText("취약 구성요소", { selector: "dt" }).nextElementSibling).toHaveTextContent("4개");
    expect(screen.queryByText("SHA-256")).not.toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "구성요소 검색" })).toBeInTheDocument();
    expect(screen.getAllByRole("combobox", { name: "상세 페이지당 행 수" })).toHaveLength(2);
    await waitFor(() => expect(screen.getByText((_, element) => element?.tagName === "LI" && element.textContent?.includes("r1 · 완료 ·") === true)).toBeInTheDocument());
    expect(await screen.findByText("높음")).toHaveClass("severity-pill", "high");
    expect(screen.getByRole("cell", { name: "9.8" })).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "KEV" })).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "4.5.14, 5.0.0" })).toBeInTheDocument();
    expect(screen.getAllByText("결제 API").length).toBeGreaterThan(0);
  });
  it("opens the exact history comparison pair and clears it when navigating away", async () => {
    window.history.replaceState(null, "", "/?page=compare&baseRunId=run-4&targetRunId=run-1");
    render(<App />);
    await waitFor(() => expect(screen.getByRole("combobox", { name: "기준 회차" })).toHaveValue("run-4"));
    expect(screen.getByRole("combobox", { name: "비교 회차" })).toHaveValue("run-1");
    fireEvent.click(screen.getByRole("button", { name: "라이브러리" }));
    expect(new URLSearchParams(window.location.search).has("baseRunId")).toBe(false);
    expect(new URLSearchParams(window.location.search).has("targetRunId")).toBe(false);
    expect(await screen.findByRole("heading", { name: "라이브러리" })).toBeInTheDocument();
  });
});


it("plots vulnerable components below the total on one shared scale", () => {
  const run = { ...demoRuns[0], componentCount: 100, vulnerableComponentCount: 10 };
  render(<Dashboard runs={[run]} onUpload={() => {}} standalone={false} canUpload={false} />);
  const total = document.querySelector('circle[aria-label^="구성요소 ·"]');
  const vulnerable = document.querySelector('circle[aria-label^="취약 구성요소 ·"]');
  expect(total).not.toBeNull();
  expect(vulnerable).not.toBeNull();
  expect(Number(vulnerable!.getAttribute("cy"))).toBeGreaterThan(Number(total!.getAttribute("cy")));
});

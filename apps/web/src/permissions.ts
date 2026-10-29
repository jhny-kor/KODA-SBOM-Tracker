import type { AuthUser } from "./types";

export type Page = "dashboard" | "runs" | "libraries" | "compare" | "settings" | "guide";

export const PAGE_PERMISSIONS: Record<Exclude<Page, "guide">, string> = {
  dashboard: "dashboard.view",
  runs: "runs.view",
  libraries: "runs.view",
  compare: "compare.view",
  settings: "settings.view",
};

export function permissionSet(user: AuthUser | null) {
  return new Set(user?.permissions || []);
}

export function canPermission(user: AuthUser | null, permission: string) {
  const permissions = permissionSet(user);
  return permissions.has("*") || permissions.has(permission);
}

export function canPage(user: AuthUser | null, page: Page) {
  if (page === "guide") return Boolean(user?.active);
  return page === "settings"
    ? canPermission(user, "catalog.manage") || canPermission(user, "vulnerability.view") || canPermission(user, "metadata.view") || canPermission(user, "metadata.manage") || canPermission(user, "settings.view") || canPermission(user, "services.view") || canPermission(user, "policies.view") || canPermission(user, "policies.manage") || canPermission(user, "reanalysis.view") || canPermission(user, "reanalysis.manage") || canPermission(user, "notifications.view") || canPermission(user, "notifications.manage")
    : canPermission(user, PAGE_PERMISSIONS[page]);
}

export function hasPermissions(user: AuthUser | null, ...permissions: string[]) {
  return permissions.every((permission) => canPermission(user, permission));
}

export function allowedPages(user: AuthUser | null) {
  return ([...Object.keys(PAGE_PERMISSIONS), "guide"] as Page[]).filter((page) => canPage(user, page));
}

export function pageForPermissions(user: AuthUser | null, requested: Page) {
  if (canPage(user, requested)) return requested;
  return allowedPages(user)[0] || null;
}

export function dataAccess(user: AuthUser | null) {
  return { runs: canPermission(user, "runs.view"), catalogs: canPermission(user, "services.view") };
}

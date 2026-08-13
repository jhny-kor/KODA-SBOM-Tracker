import type { AuthUser } from "./types";

export type Page = "dashboard" | "services" | "runs" | "compare" | "settings";

export const PAGE_PERMISSIONS: Record<Page, string> = {
  dashboard: "dashboard.view",
  services: "services.view",
  runs: "runs.view",
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

export function hasPermissions(user: AuthUser | null, ...permissions: string[]) {
  return permissions.every((permission) => canPermission(user, permission));
}

export function allowedPages(user: AuthUser | null) {
  return (Object.keys(PAGE_PERMISSIONS) as Page[]).filter((page) => canPermission(user, PAGE_PERMISSIONS[page]));
}

export function pageForPermissions(user: AuthUser | null, requested: Page) {
  return canPermission(user, PAGE_PERMISSIONS[requested]) ? requested : allowedPages(user)[0] || null;
}

export function dataAccess(user: AuthUser | null) {
  return { runs: canPermission(user, "runs.view"), catalogs: canPermission(user, "services.view") };
}

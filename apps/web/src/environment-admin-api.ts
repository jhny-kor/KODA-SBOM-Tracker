import { previewMode, request, standaloneMode } from "./api";
import { demoRuns } from "./demo";
import type { CatalogItem } from "./types";

export interface EnvironmentAdministrator {
  id: string;
  username: string;
  role: string;
  active: boolean;
  status: string;
}
export interface EnvironmentAssignments {
  environments: (CatalogItem & { administrators: EnvironmentAdministrator[] })[];
  users: EnvironmentAdministrator[];
}
export interface RunMetadata {
  serviceId: string;
  environmentId: string;
  releaseVersion: string;
  note: string;
}
export interface RunEditPermission {
  canEdit: boolean;
  reason: string | null;
  editableEnvironmentIds: string[];
  canChangeScope?: boolean;
  metadata: RunMetadata;
  services: CatalogItem[];
  environments: CatalogItem[];
}

export async function fetchEnvironmentAdministrators(): Promise<EnvironmentAssignments> {
  if (previewMode) {
    const users = [
      { id: "sample-prod-admin", username: "운영 담당자", role: "analyst", active: true, status: "active" },
      { id: "sample-qa-admin", username: "검증 담당자", role: "viewer", active: true, status: "active" },
    ];
    return { users, environments: [...new Map(demoRuns.map(run => [run.environment.id, run.environment])).values()].map((env, index) => ({ ...env, active: true, administrators: [users[index % users.length]] })) };
  }
  return request<EnvironmentAssignments>("/api/v1/environment-administrators");
}

export function saveEnvironmentAdministrators(environmentId: string, userIds: string[]) {
  if (previewMode) return Promise.reject(new Error("샘플 화면에서는 관리자 지정을 저장하지 않습니다."));
  return request<{ environmentId: string; userIds: string[] }>(`/api/v1/environment-administrators/${encodeURIComponent(environmentId)}`, {
    method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ userIds }),
  });
}

export async function fetchRunEditPermission(runId: string): Promise<RunEditPermission> {
  if (standaloneMode) return { canEdit: false, canChangeScope: false, reason: "로컬 미리보기에서는 서버 등록 정보를 수정하지 않습니다.", editableEnvironmentIds: [], metadata: { serviceId: "", environmentId: "", releaseVersion: "", note: "" }, services: [], environments: [] };
  if (previewMode) {
    const run = demoRuns.find(item => item.id === runId) || demoRuns[0];
    const environments = [...new Map(demoRuns.map(item => [item.environment.id, { ...item.environment, active: true }])).values()];
    return {
      canEdit: true, reason: "샘플 화면에서는 입력 항목을 확인할 수 있으며 저장하지 않습니다.",
      canChangeScope: true, editableEnvironmentIds: environments.map(item => item.id),
      metadata: { serviceId: run.service.id, environmentId: run.environment.id, releaseVersion: run.releaseVersion, note: run.note || "" },
      services: [...new Map(demoRuns.map(item => [item.service.id, { ...item.service, active: true }])).values()], environments,
    };
  }
  return request<RunEditPermission>(`/api/v1/sbom-runs/${encodeURIComponent(runId)}/edit-permission`);
}

export function updateRunMetadata(runId: string, metadata: Partial<RunMetadata>) {
  if (previewMode) return Promise.reject(new Error("샘플 화면에서는 SBOM 정보를 저장하지 않습니다."));
  return request<RunMetadata & { runId: string; roundNumber: number; reanalysisPending: boolean }>(`/api/v1/sbom-runs/${encodeURIComponent(runId)}/metadata`, {
    method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(metadata),
  });
}

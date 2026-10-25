import { request } from "./api";

export type SsvcInputs = {
  exploitation: "none" | "public poc" | "active" | null;
  systemExposure: "small" | "controlled" | "open" | null;
  automatable: "no" | "yes" | null;
  humanImpact: "low" | "medium" | "high" | "very high" | null;
};
export type SsvcAssessmentInput = {
  component: string; vulnerabilityId: string; expectedRevisionId: string;
  inputs: SsvcInputs; rationale: string; references: string[]; reviewAt?: string;
};
export type SsvcAssessment = Omit<SsvcAssessmentInput, "expectedRevisionId"> & {
  id: string; runId: string; revisionId: string; componentVersion: string;
  serviceId: string; environmentId: string; releaseId: string;
  model: string; tableSha256: string; outcome: string | null; state: string;
  stale: boolean; staleReasons: string[]; superseded: boolean;
  author: string; createdAt: string; evidence: Record<string, unknown>;
};
export type SsvcResult = {
  items: SsvcAssessment[]; total: number; page: number; size: number;
  model: string; revisionId: string | null; analysisReady: boolean; archived: boolean;
};

export function fetchSsvcAssessments(runId: string, page = 1): Promise<SsvcResult> {
  return request(`/api/v1/sbom-runs/${encodeURIComponent(runId)}/ssvc?page=${page}&size=20`);
}

export function submitSsvcAssessment(runId: string, body: SsvcAssessmentInput): Promise<SsvcAssessment> {
  return request(`/api/v1/sbom-runs/${encodeURIComponent(runId)}/ssvc`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
}

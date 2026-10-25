import type { AnalysisRevisionSummary } from "./types";

/** Pick the latest attempted analysis, including failures, rather than a prior successful one. */
export function latestAnalysisRevision(analyses?: AnalysisRevisionSummary[]) {
  return analyses?.reduce<AnalysisRevisionSummary | undefined>((latest, value) => !latest || value.sequence > latest.sequence ? value : latest, undefined);
}

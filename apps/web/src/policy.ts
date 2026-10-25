import { analysisAvailable } from "./analysisAvailability";
import type { NativePolicyFields } from "./types";

export function policyCountLabel(result: NativePolicyFields & { policyViolationCount?: number }): string {
  if (!analysisAvailable(result)) return "미평가";
  if (result.policyState === "failed") return "평가 실패";
  if (result.policyState !== "completed") return "미평가";
  return `${result.policyViolationCount ?? 0}`;
}

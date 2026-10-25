import type { NativePolicyFields } from "./types";

export function analysisAvailable(result: (NativePolicyFields & {state?: string}) | null | undefined): boolean {
  if (!result || result.analysisAvailable === false) return false;
  const state = result.analysisState ?? result.state;
  return state === undefined || state === "completed" || state === "archived";
}
export function analysisUnavailableReason(result: (NativePolicyFields & {error?: string | null}) | null | undefined): string {
  return result?.analysisUnavailableReason || result?.error || "취약점 분석이 완료되지 않았습니다. 승인된 자료와 분석 상태를 확인하세요.";
}

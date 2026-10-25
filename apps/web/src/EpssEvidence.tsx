/** Observed historical scores stay visible; only epssScore is policy eligible. */
export function EpssEvidence({ finding }: { finding: Record<string, unknown> }) {
  const fresh = typeof finding.epssScore === "number";
  const score = fresh ? finding.epssScore : finding.epssObservedScore;
  const percentile = fresh ? finding.epssPercentile : finding.epssObservedPercentile;
  const date = fresh ? finding.epssDate : finding.epssObservedDate;
  const status = String(finding.epssStatus || "미수집");
  return typeof score === "number" ? <span>EPSS {(score * 100).toFixed(2)}%{typeof percentile === "number" ? ` · 백분위 ${(percentile * 100).toFixed(2)}%` : ""} · {String(date || "기준일 미확인")} · {fresh ? status : `과거 관측값 (${status})`}</span> : <span>EPSS {status}</span>;
}

/** Observed historical scores stay visible; only epssScore is policy eligible. */
export function EpssEvidence({ finding, stacked = false }: { finding: Record<string, unknown>; stacked?: boolean }) {
  const fresh = typeof finding.epssScore === "number";
  const score = fresh ? finding.epssScore : finding.epssObservedScore;
  const percentile = fresh ? finding.epssPercentile : finding.epssObservedPercentile;
  const date = fresh ? finding.epssDate : finding.epssObservedDate;
  const status = String(finding.epssStatus || "미수집");
  if (typeof score !== "number") return <span>EPSS {status}</span>;

  const values = [`EPSS ${(score * 100).toFixed(2)}%`];
  if (typeof percentile === "number") values.push(`백분위 ${(percentile * 100).toFixed(2)}%`);
  values.push(String(date || "기준일 미확인"), fresh ? status : `과거 관측값 (${status})`);
  return stacked
    ? <div className="epss-evidence-stacked">{values.map((value, index) => <span key={index}>{value}</span>)}</div>
    : <span>{values.join(" · ")}</span>;
}

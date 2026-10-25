import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { CpeCoverage } from "./CpeCoverage";
import { latestAnalysisRevision } from "./analysisRevision";
import type { AnalysisRevisionSummary, CpeApplicabilitySummary } from "./types";

afterEach(cleanup);
const summary: CpeApplicabilitySummary = { version: "koda-offline-cpe-v1", status: "completed", inputCpes: 3, invalidCpes: 0, unmatchedProducts: 0, evaluatedCves: 20, unknownCves: 0, affectedCves: 0, addedFindings: 0, matchedExisting: 0, legacyDetailsOnly: 0, inventoryComplete: false };
const analysis = (value?: CpeApplicabilitySummary, state: AnalysisRevisionSummary["state"] = "completed"): AnalysisRevisionSummary => ({ id: "r3", sequence: 3, state, dataAsOf: "2026-10-19", dataSources: value ? { cpeApplicability: value } : {} });

it("shows completed scoped evaluation without calling a zero result safe", () => {
  render(<CpeCoverage analysis={analysis(summary)} />);
  const panel = screen.getByRole("region", { name: "오프라인 CPE 평가 범위" });
  expect(within(panel).getByText(/제공 CPE 조건 평가 완료/)).toBeInTheDocument();
  expect(within(panel).getByText("평가한 CVE").nextSibling).toHaveTextContent("20개");
  expect(within(panel).getByText("영향 확인 CVE").nextSibling).toHaveTextContent("0개");
  expect(within(panel).getByText(/전체 제품·환경의 안전을 보장하지 않습니다/)).toBeInTheDocument();
  expect(within(panel).getByText(/누락 환경 조건은 판정 불가/)).toBeInTheDocument();
});

it("shows invalid, unmatched, unknown and legacy-data counts with incomplete warning", () => {
  render(<CpeCoverage analysis={analysis({ ...summary, status: "incomplete", invalidCpes: 1, unmatchedProducts: 2, unknownCves: 7, indexIncompleteCves: 1, legacyDetailsOnly: 40, unresolved: [{ id: "CVE-2026-12345", reason: "NVD applicability complexity limit exceeded" }] })} />);
  expect(screen.getByText(/평가 범위 불완전/)).toBeInTheDocument();
  expect(screen.getByText("유효하지 않은 CPE").nextSibling).toHaveTextContent("1개");
  expect(screen.getByText("적용 조건이 없는 제품").nextSibling).toHaveTextContent("2개");
  expect(screen.getByText("조건 판정 불가 CVE").nextSibling).toHaveTextContent("7개");
  expect(screen.getByText("적용 조건 없는 과거 NVD 레코드").nextSibling).toHaveTextContent("40개");
  expect(screen.getByText("적용 조건 형식·복잡도 확인 필요 CVE").nextSibling).toHaveTextContent("1개");
  expect(screen.getByText(/CVE-2026-12345: NVD applicability complexity limit exceeded/)).toBeInTheDocument();
  expect(screen.getByText(/미평가·미판정 항목을 취약점 없음으로 집계해서는 안 됩니다/)).toBeInTheDocument();
});

it("explains missing product conditions and never fills absent counts with zero", () => {
  render(<CpeCoverage analysis={analysis({ status: "unavailable", reason: "No indexed applicability conditions for supplied products; absence is not proof of safety" })} />);
  expect(screen.getByText(/적용 자료 이용 불가/)).toBeInTheDocument();
  expect(screen.getByText(/평가 사유: 제공한 제품에 대한 적용 조건/)).toBeInTheDocument();
  expect(screen.getByText("입력 CPE").nextSibling).toHaveTextContent("확인 불가");
});

it("explains unevaluated CPE identities and missing legacy evidence", () => {
  const { rerender } = render(<CpeCoverage analysis={analysis({ status: "not_evaluated", inputCpes: 0, reason: "No concrete CPE 2.3 identities supplied; no package-name inference performed" })} />);
  expect(screen.getByText(/CPE 미평가/)).toBeInTheDocument();
  expect(screen.getByText(/제품 이름으로 CPE를 추정하지 않습니다/)).toBeInTheDocument();
  rerender(<CpeCoverage analysis={analysis()} />);
  expect(screen.getByText(/구버전 분석 또는 미평가 상태/)).toBeInTheDocument();
});

it("does not present successful old coverage as a completed latest analysis", () => {
  expect(latestAnalysisRevision([])).toBeUndefined();
  const old = { ...analysis(summary), sequence: 1 };
  expect(latestAnalysisRevision([old, analysis(summary, "failed")])?.state).toBe("failed");
  const { rerender } = render(<CpeCoverage analysis={analysis(summary, "failed")} />);
  expect(screen.getByText(/최신 분석이 완료되지 않았습니다/)).toBeInTheDocument();
  rerender(<CpeCoverage loading />);
  expect(screen.getByText(/불러오는 중/)).toBeInTheDocument();
  rerender(<CpeCoverage />);
  expect(screen.getByText(/분석 리비전이 없습니다/)).toBeInTheDocument();
});

it("groups desktop metrics into two label/value pairs and spans long explanations", () => {
  render(<CpeCoverage analysis={analysis(summary)} />);
  const table = screen.getByRole("table", { name: "CPE 평가 항목별 현황" });
  const rows = within(table).getAllByRole("row");
  expect(rows).toHaveLength(6);
  expect(within(rows[0]).getAllByRole("rowheader")).toHaveLength(2);
  expect(within(rows[0]).getAllByRole("cell")).toHaveLength(2);
  expect(screen.getByText("인벤토리 전체성").nextSibling).toHaveAttribute("colspan", "3");
});

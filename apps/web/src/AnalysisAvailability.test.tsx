import "@testing-library/jest-dom/vitest";
import {cleanup, render, screen, within} from "@testing-library/react";
import {afterEach, expect, it} from "vitest";
import {Dashboard} from "./App";
import {NativePolicyResult} from "./NativePolicyResult";
import {analysisAvailable, analysisUnavailableReason} from "./analysisAvailability";
import {policyCountLabel} from "./policy";
import {demoRuns} from "./demo";
afterEach(cleanup);
it("refuses numeric zero and stale policy pass for unavailable or failed current analysis", () => {
  const failed={analysisAvailable:false,analysisState:"failed" as const,analysisUnavailableReason:"승인된 통합 자료 없음",policyState:"completed" as const,policyStatus:"pass" as const,policyViolationCount:0};
  expect(analysisAvailable(failed)).toBe(false);
  expect(analysisUnavailableReason(failed)).toBe("승인된 통합 자료 없음");
  expect(policyCountLabel(failed)).toBe("미평가");
  render(<NativePolicyResult result={failed}/>);
  expect(screen.queryByText("통과")).not.toBeInTheDocument();
  expect(screen.getByText("미평가")).toBeInTheDocument();
});
it("keeps explicitly selected completed historical revisions available",()=>{
  expect(analysisAvailable({state:"completed"})).toBe(true);
  expect(analysisAvailable({state:"failed"})).toBe(false);
  expect(analysisAvailable({analysisState:"running"})).toBe(false);
  expect(analysisAvailable({analysisAvailable:true,analysisState:"completed"})).toBe(true);
});
it("shows missing-data reason and unevaluated vulnerability metrics in the dashboard",()=>{
  render(<Dashboard runs={[{...demoRuns[0],state:"completed",analysisAvailable:false,analysisState:"failed",analysisUnavailableReason:"승인된 통합 자료 없음",vulnerabilityCount:0,kevCount:0}]} onUpload={()=>{}} standalone={false} canUpload={false}/>);
  expect(screen.getByRole("alert")).toHaveTextContent("승인된 통합 자료 없음");
  const severity=screen.getByText("최신 SBOM 심각도").closest("article")!;
  expect(within(severity).getByText("미평가")).toBeInTheDocument();
  expect(within(severity).queryByText("0건")).not.toBeInTheDocument();
  expect(within(severity).queryByText("최신 분석에 취약점 레코드가 없습니다.")).not.toBeInTheDocument();
});

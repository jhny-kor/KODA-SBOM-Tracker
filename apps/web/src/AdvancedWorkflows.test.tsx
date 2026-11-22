import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as api from "./api";
import { ReanalysisSchedulePanel } from "./ReanalysisSchedule";
import { NotificationsPanel } from "./Notifications";
import { VexReviewsPanel } from "./VexReviews";
import { SbomPoliciesPanel } from "./SbomPolicies";
import { canPage } from "./permissions";
import type { ReanalysisSchedule, VexReview } from "./types";
vi.mock("./api", () => ({ previewMode:false,fetchReanalysisSchedule:vi.fn(),fetchReanalysisCycles:vi.fn(),updateReanalysisSchedule:vi.fn(),queueReanalysisCycle:vi.fn(),fetchVexReviews:vi.fn(),submitVexReview:vi.fn(),decideVexReview:vi.fn(),fetchReviewEvents:vi.fn(),commentVexReview:vi.fn(),importVex:vi.fn(),fetchNotifications:vi.fn(),markNotificationRead:vi.fn(),fetchNotificationDeliveries:vi.fn(),fetchNotificationSettings:vi.fn(),retryNotificationDelivery:vi.fn(),fetchSbomPolicies:vi.fn(),updateSbomPolicies:vi.fn(),validateSbomPolicyExpression:vi.fn() }));
const schedule:ReanalysisSchedule={version:2,enabled:false,intervalMinutes:60,onDataUpdate:true,latestOnly:false,serviceIds:[],environmentIds:[]};
const review:VexReview={id:"review-1",component:"pkg:pypi/demo@1",vulnerabilityId:"CVE-2026-1",state:"not_affected",justification:"code_not_reachable",detail:"도달 경로를 검토함",response:[],status:"submitted",author:"author",createdAt:"2026-10-18T00:00:00Z"};
const finding={component:"pkg:pypi/demo@1",canonicalId:"CVE-2026-1"};
const catalogs=[{id:"service-a",name:"서비스 A",slug:"a"}];
const longFinding = { component: `pkg:maven/example/${"very-long-library-coordinate-".repeat(12)}@1.0.0`, canonicalId: "CVE-2026-20001" };
beforeEach(()=>{
 vi.mocked(api.fetchReanalysisSchedule).mockResolvedValue(structuredClone(schedule));
 vi.mocked(api.fetchReanalysisCycles).mockResolvedValue({items:[],total:0,page:1,size:10});
 vi.mocked(api.fetchVexReviews).mockResolvedValue({items:[review],total:1,page:1,size:10});
 vi.mocked(api.fetchReviewEvents).mockResolvedValue({items:[{id:"event",kind:"submitted",actor:"author",comment:"요청",createdAt:review.createdAt}]});
 vi.mocked(api.fetchNotifications).mockResolvedValue({items:[{id:"notification",title:"정책 위반",message:"고위험 발견",read:false,createdAt:review.createdAt}],total:1,unreadCount:1,page:1,size:10});
 vi.mocked(api.fetchNotificationDeliveries).mockResolvedValue({items:[{id:"delivery",status:"failed",attempts:3,lastError:"timeout",createdAt:review.createdAt}],total:1,page:1,size:10});
 vi.mocked(api.fetchNotificationSettings).mockResolvedValue({webhookEnabled:true,webhookConfigured:true,webhookHost:"hooks.example",secretConfigured:true});
 vi.mocked(api.fetchSbomPolicies).mockResolvedValue({version:3,rules:[{id:"cel",name:"고급 규칙",kind:"cel",enabled:true,action:"fail",values:[],expression:"vulnerability.kev",target:"vulnerability",serviceIds:["service-a"]}],exceptions:[]});
});
afterEach(()=>{cleanup();vi.resetAllMocks();});
describe("native advanced workflows",()=>{
 it("preserves the selected long finding and native form fields when submitting VEX",async()=>{
  vi.mocked(api.submitVexReview).mockResolvedValue(review);
  render(<VexReviewsPanel runId="run" findings={[finding,longFinding]} username="author" canManage canApprove={false}/>);
  const target=await screen.findByLabelText("VEX 대상 취약점") as HTMLSelectElement;
  expect(target.options[1].textContent).toContain(longFinding.component);
  fireEvent.change(target,{target:{value:"1"}});
  fireEvent.change(screen.getByLabelText("VEX 상태"),{target:{value:"exploitable"}});
  fireEvent.change(screen.getByLabelText("VEX 증거"),{target:{value:"긴 좌표의 실제 선택값 검증"}});
  fireEvent.click(screen.getByRole("button",{name:"검토 요청 제출"}));
  await waitFor(()=>expect(api.submitVexReview).toHaveBeenCalledWith("run",expect.objectContaining({component:longFinding.component,vulnerabilityId:longFinding.canonicalId,state:"exploitable"})));
 });
 it("allows notification and schedule readers to access settings",()=>{for(const permission of ["notifications.view","reanalysis.view"])expect(canPage({id:"u",username:"u",role:"analyst",active:true,permissions:[permission]},"settings")).toBe(true);});
 it("saves all-round schedule and scopes with loaded version",async()=>{
  vi.mocked(api.updateReanalysisSchedule).mockResolvedValue({...schedule,version:3});render(<ReanalysisSchedulePanel canManage services={catalogs}/>);fireEvent.click(await screen.findByLabelText("자동 재분석 사용"));const select=screen.getByLabelText("재분석 서비스 범위")as HTMLSelectElement;select.options[0].selected=true;fireEvent.change(select);fireEvent.click(screen.getByRole("button",{name:"재분석 일정 저장"}));await waitFor(()=>expect(api.updateReanalysisSchedule).toHaveBeenCalledWith(expect.objectContaining({version:2,enabled:true,latestOnly:false,serviceIds:["service-a"]})));
 });
 it("schedule readers cannot save or queue",async()=>{render(<ReanalysisSchedulePanel canManage={false}/>);expect(await screen.findByLabelText("자동 재분석 사용")).toBeDisabled();expect(screen.queryByRole("button",{name:"재분석 일정 저장"})).not.toBeInTheDocument();expect(screen.queryByText("현재 저장된 범위 지금 재분석")).not.toBeInTheDocument();});
 it("reports queue failure without completion claim",async()=>{vi.mocked(api.queueReanalysisCycle).mockRejectedValue(new Error("사이클이 실행 중입니다"));render(<ReanalysisSchedulePanel canManage/>);fireEvent.click(await screen.findByRole("button",{name:"현재 저장된 범위 지금 재분석"}));expect(await screen.findByRole("status")).toHaveTextContent("사이클이 실행 중입니다");});
 it("shows cycle backlog and paginates",async()=>{vi.mocked(api.fetchReanalysisCycles).mockResolvedValue({items:[{id:"cycle",reason:"interval",state:"running",createdAt:review.createdAt,totalCount:100,pendingCount:70,enqueuedCount:30,completedCount:25,failedCount:5,skippedCount:0}],total:11,page:1,size:10});render(<ReanalysisSchedulePanel canManage={false}/>);expect(await screen.findByText("70")).toBeInTheDocument();fireEvent.click(screen.getByRole("button",{name:"재분석 이력 다음 페이지"}));await waitFor(()=>expect(api.fetchReanalysisCycles).toHaveBeenLastCalledWith(2));});
 it("validates CEL and saves project scope",async()=>{vi.mocked(api.validateSbomPolicyExpression).mockResolvedValue({valid:true,runtime:"cel-expr-python"});vi.mocked(api.updateSbomPolicies).mockResolvedValue({version:4,rules:[],exceptions:[]});render(<SbomPoliciesPanel canManage services={catalogs}/>);fireEvent.change(await screen.findByLabelText("규칙 1 CEL 조건"),{target:{value:'project.slug == "orders"'}});fireEvent.change(screen.getByLabelText("규칙 1 CEL 대상"),{target:{value:"project"}});fireEvent.click(screen.getByRole("button",{name:"CEL 문법 검증"}));await waitFor(()=>expect(api.validateSbomPolicyExpression).toHaveBeenCalledWith('project.slug == "orders"',"project"));expect(await screen.findByText(/CEL 컴파일 성공/)).toBeInTheDocument();fireEvent.click(screen.getByRole("button",{name:"정책 버전 저장"}));await waitFor(()=>expect(api.updateSbomPolicies).toHaveBeenCalledWith(expect.objectContaining({rules:[expect.objectContaining({serviceIds:["service-a"],target:"project"})]})));});
 it("ignores stale CEL validation after the expression changes",async()=>{
  let complete: ((value: {valid:boolean;runtime:string}) => void) | undefined;
  vi.mocked(api.validateSbomPolicyExpression).mockImplementation(()=>new Promise((resolve)=>{complete=resolve;}));
  render(<SbomPoliciesPanel canManage/>);fireEvent.click(await screen.findByRole("button",{name:"CEL 문법 검증"}));
  fireEvent.change(screen.getByLabelText("규칙 1 CEL 조건"),{target:{value:"bad.expression"}});
  complete?.({valid:true,runtime:"CEL"});await waitFor(()=>expect(screen.queryByText(/CEL 컴파일 성공/)).not.toBeInTheDocument());
 });
 it("displays CEL errors",async()=>{vi.mocked(api.validateSbomPolicyExpression).mockRejectedValue(new Error("unknown identifier"));render(<SbomPoliciesPanel canManage/>);fireEvent.click(await screen.findByRole("button",{name:"CEL 문법 검증"}));expect(await screen.findByText(/CEL 검증 실패: unknown identifier/)).toBeInTheDocument();});
 it("submits exact finding with evidence",async()=>{vi.mocked(api.submitVexReview).mockResolvedValue(review);render(<VexReviewsPanel runId="run" findings={[finding]} username="author" canManage canApprove={false}/>);fireEvent.change(screen.getByLabelText("VEX 상태"),{target:{value:"not_affected"}});fireEvent.change(screen.getByLabelText("VEX 판단 사유"),{target:{value:"code_not_reachable"}});fireEvent.change(screen.getByLabelText("VEX 증거"),{target:{value:"실제 경로 검토"}});fireEvent.click(screen.getByRole("button",{name:"검토 요청 제출"}));await waitFor(()=>expect(api.submitVexReview).toHaveBeenCalledWith("run",expect.objectContaining({component:"pkg:pypi/demo@1",vulnerabilityId:"CVE-2026-1",state:"not_affected",detail:"실제 경로 검토"})));expect(await screen.findByRole("status")).toHaveTextContent("다른 승인자의 승인 후 새 분석부터");});
 it("blocks author approval and shows decision errors",async()=>{const{rerender}=render(<VexReviewsPanel runId="run" findings={[]} username="author" canManage={false} canApprove/>);expect(await screen.findByText("본인이 요청한 검토는 다른 승인자가 승인해야 합니다.")).toBeInTheDocument();expect(screen.queryByRole("button",{name:"검토 승인"})).not.toBeInTheDocument();rerender(<VexReviewsPanel runId="run" findings={[]} username="reviewer" canManage={false} canApprove/>);vi.mocked(api.decideVexReview).mockRejectedValue(new Error("승인 권한이 없습니다"));fireEvent.change(screen.getByLabelText("검토 review-1 결정 사유"),{target:{value:"증거 확인"}});fireEvent.click(screen.getByRole("button",{name:"검토 승인"}));expect(await screen.findByRole("status")).toHaveTextContent("승인 권한이 없습니다");});
 it("loads history and submits comments",async()=>{vi.mocked(api.commentVexReview).mockResolvedValue({id:"new",createdAt:review.createdAt});render(<VexReviewsPanel runId="run" findings={[]} canManage canApprove={false}/>);fireEvent.click(await screen.findByRole("button",{name:"검토 이력 보기"}));expect(await screen.findByText(/submitted · 요청/)).toBeInTheDocument();fireEvent.change(screen.getByLabelText("검토 review-1 의견"),{target:{value:"재현 근거 첨부"}});fireEvent.click(screen.getByRole("button",{name:"의견 등록"}));await waitFor(()=>expect(api.commentVexReview).toHaveBeenCalledWith("review-1","재현 근거 첨부"));});
 it("marks inbox read without exposing administration",async()=>{vi.mocked(api.markNotificationRead).mockResolvedValue({});render(<NotificationsPanel canManage={false}/>);fireEvent.click(await screen.findByRole("button",{name:"읽음 표시"}));await waitFor(()=>expect(api.markNotificationRead).toHaveBeenCalledWith("notification"));expect(api.fetchNotificationDeliveries).not.toHaveBeenCalled();expect(screen.getByText(/확인하는 내부 알림함입니다/)).toBeInTheDocument();});
 it("does not offer retries for pending or retry deliveries",async()=>{
  vi.mocked(api.fetchNotificationDeliveries).mockResolvedValue({items:[{id:"pending",status:"pending",attempts:1,createdAt:review.createdAt},{id:"retry",status:"retry",attempts:2,createdAt:review.createdAt}],total:2,page:1,size:10});
  render(<NotificationsPanel canManage/>);expect(await screen.findByText("pending")).toBeInTheDocument();expect(screen.getByText("retry")).toBeInTheDocument();expect(screen.queryByRole("button",{name:"전송 재시도"})).not.toBeInTheDocument();
 });
 it("retries failed delivery with management permission",async()=>{vi.mocked(api.retryNotificationDelivery).mockResolvedValue({});render(<NotificationsPanel canManage/>);expect(await screen.findByText("timeout")).toBeInTheDocument();expect(screen.getByText(/hooks.example/)).toBeInTheDocument();fireEvent.click(screen.getByRole("button",{name:"전송 재시도"}));await waitFor(()=>expect(api.retryNotificationDelivery).toHaveBeenCalledWith("delivery"));});
});

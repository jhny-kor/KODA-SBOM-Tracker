import "@testing-library/jest-dom/vitest";
import { cleanup,fireEvent,render,screen,waitFor,within } from "@testing-library/react";
import { afterEach,beforeEach,expect,it,vi } from "vitest";
import * as api from "./api";
import { ProjectCatalogPanel } from "./ProjectCatalog";
import type { NativeProject } from "./api";
import type { SbomRun } from "./types";
vi.mock("./api",async original=>({...await original<typeof import("./api")>(),previewMode:false,fetchProjectCatalog:vi.fn(),fetchProjectRuns:vi.fn()}));
const project:NativeProject={id:"project-id",sourceId:"native",sourceProjectId:"portal",serviceId:"s",environmentId:"e",name:"연결 검증",version:"1.0",parentProjectId:null,tags:[],isLatest:true,active:true,revision:1};
const run:SbomRun={id:"run-id",service:{id:"s",name:"검증 서비스",slug:"service"},environment:{id:"e",name:"운영",slug:"prod"},releaseVersion:"1.0",roundNumber:2,state:"completed",sha256:"hash",componentCount:6,vulnerabilityCount:3,policyViolationCount:1,dataAsOf:"2026-10-19",createdAt:"2026-10-20T00:00:00Z",analysisAvailable:true,analysisState:"completed"};
beforeEach(()=>{vi.resetAllMocks();vi.mocked(api.fetchProjectCatalog).mockResolvedValue({items:[project],total:1,page:1,size:20});vi.mocked(api.fetchProjectRuns).mockResolvedValue({items:[run],total:1,page:1,size:10});});afterEach(cleanup);
async function openProject(){fireEvent.click(await screen.findByRole("button",{name:/연결 검증 · 1.0/}));}
it("loads connected runs only when a project is opened and routes to the existing result detail",async()=>{
 const open=vi.fn();render(<ProjectCatalogPanel canManage canViewRuns onOpenRun={open}/>);
 await screen.findByRole("button",{name:/연결 검증/});expect(api.fetchProjectRuns).not.toHaveBeenCalled();await openProject();
 const link=await screen.findByRole("link",{name:"점검결과 보기"});expect(api.fetchProjectRuns).toHaveBeenCalledWith("project-id",1);expect(link).toHaveAttribute("href","/?page=runs&runId=run-id");
 const row=link.closest("tr")!;expect(within(row).getByText("2차 / 1.0")).toBeInTheDocument();expect(within(row).getByText("검증 서비스 / 운영")).toBeInTheDocument();expect(within(row).getByText("3")).toBeInTheDocument();
 fireEvent.click(link);expect(open).toHaveBeenCalledWith(run);expect(api.fetchProjectRuns).toHaveBeenCalledTimes(1);
});
it("allows readonly catalog users to view results without enabling management",async()=>{
 render(<ProjectCatalogPanel canManage={false} canViewRuns/>);await openProject();expect(await screen.findByRole("link",{name:"점검결과 보기"})).toBeInTheDocument();expect(screen.getByLabelText("project-id 태그")).toBeDisabled();expect(screen.queryByRole("button",{name:"프로젝트 범위 저장"})).not.toBeInTheDocument();
});
it("does not offer or fetch result data without run access",async()=>{
 render(<ProjectCatalogPanel canManage/>);await screen.findByText(/연결된 회차와 점검결과를 보려면/);expect(screen.queryByRole("button",{name:/연결 검증/})).not.toBeInTheDocument();expect(api.fetchProjectRuns).not.toHaveBeenCalled();
});
it("paginates inside the selected project without mixing rows",async()=>{
 vi.mocked(api.fetchProjectRuns).mockResolvedValueOnce({items:[run],total:11,page:1,size:10}).mockResolvedValueOnce({items:[{...run,id:"older",roundNumber:1}],total:11,page:2,size:10});render(<ProjectCatalogPanel canManage canViewRuns/>);await openProject();await screen.findByRole("link",{name:"점검결과 보기"});fireEvent.click(screen.getByRole("button",{name:"연결된 회차 다음"}));await screen.findByText("1차 / 1.0");expect(api.fetchProjectRuns).toHaveBeenLastCalledWith("project-id",2);expect(screen.queryByText("2차 / 1.0")).not.toBeInTheDocument();
});
it("reports failed loads and retries without pretending the project has no results",async()=>{
 vi.mocked(api.fetchProjectRuns).mockRejectedValueOnce(new Error("접근 확인 필요"));render(<ProjectCatalogPanel canManage canViewRuns/>);await openProject();expect(await screen.findByRole("alert")).toHaveTextContent("접근 확인 필요");expect(screen.queryByText(/연결된 SBOM 회차가 없습니다/)).not.toBeInTheDocument();fireEvent.click(screen.getByRole("button",{name:"회차 새로고침"}));expect(await screen.findByRole("link",{name:"점검결과 보기"})).toBeInTheDocument();
});
it("shows an explicit empty association and no result link",async()=>{
 vi.mocked(api.fetchProjectRuns).mockResolvedValue({items:[],total:0,page:1,size:10});render(<ProjectCatalogPanel canManage canViewRuns/>);await openProject();expect(await screen.findByText(/연결된 SBOM 회차가 없습니다/)).toBeInTheDocument();expect(screen.queryByRole("link",{name:"점검결과 보기"})).not.toBeInTheDocument();
});
it("distinguishes pending analysis from a zero-finding assessment",async()=>{
 vi.mocked(api.fetchProjectRuns).mockResolvedValue({items:[{...run,analysisAvailable:false,analysisState:"queued",vulnerabilityCount:0,policyViolationCount:0}],total:1,page:1,size:10});render(<ProjectCatalogPanel canManage canViewRuns/>);await openProject();expect(await screen.findByText("분석 대기")).toBeInTheDocument();expect(screen.getAllByText("미평가")).toHaveLength(2);expect(screen.getByRole("link",{name:"회차 상세 보기"})).toBeInTheDocument();
});
it("closes an in-flight project and ignores the completed stale request",async()=>{
 let resolve!:(v:Awaited<ReturnType<typeof api.fetchProjectRuns>>)=>void;vi.mocked(api.fetchProjectRuns).mockImplementationOnce(()=>new Promise(r=>{resolve=r}));render(<ProjectCatalogPanel canManage canViewRuns/>);await openProject();await waitFor(()=>expect(api.fetchProjectRuns).toHaveBeenCalledTimes(1));await openProject();resolve({items:[run],total:1,page:1,size:10});await waitFor(()=>expect(screen.queryByRole("link",{name:"점검결과 보기"})).not.toBeInTheDocument());expect(screen.getByRole("button",{name:/연결 검증/})).toHaveAttribute("aria-expanded","false");
});

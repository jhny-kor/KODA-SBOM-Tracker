import "@testing-library/jest-dom/vitest";
import { cleanup,fireEvent,render,screen,waitFor } from "@testing-library/react";
import { afterEach,beforeEach,expect,it,vi } from "vitest";
import * as api from "./api";
import { ProjectCatalogPanel } from "./ProjectCatalog";
import { SbomPoliciesPanel } from "./SbomPolicies";
import type { NativeProject,ProjectSyncSource } from "./api";

vi.mock("./api",async original=>({...await original<typeof import("./api")>(),previewMode:false,fetchProjectCatalog:vi.fn(),fetchProjectSyncSources:vi.fn(),updateNativeProject:vi.fn(),createProjectSyncSource:vi.fn(),fetchCollectionMetrics:vi.fn(),runProjectSync:vi.fn(),fetchSbomPolicies:vi.fn(),updateSbomPolicies:vi.fn()}));
const project:NativeProject={id:"native-id",sourceId:"native",sourceProjectId:"app-v1",serviceId:"s",environmentId:"e",name:"sample",version:"1",parentProjectId:null,tags:["prod"],isLatest:true,active:true,revision:7};
const source:ProjectSyncSource={id:"source-id",name:"원본",baseUrl:"http://source.test",enabled:true,intervalMinutes:10,state:"retrying",attempts:2,version:4};
beforeEach(()=>{vi.resetAllMocks();vi.mocked(api.fetchProjectCatalog).mockResolvedValue({items:[project],total:1,page:1,size:20});vi.mocked(api.fetchProjectSyncSources).mockResolvedValue({items:[source],total:1,page:1,size:20});});
afterEach(cleanup);

it("saves dynamic tags and parent against the observed project revision",async()=>{
  vi.mocked(api.updateNativeProject).mockResolvedValue({...project,revision:8});render(<ProjectCatalogPanel canManage/>);
  fireEvent.change(await screen.findByLabelText("native-id 태그"),{target:{value:"prod, critical"}});fireEvent.change(screen.getByLabelText("native-id 부모"),{target:{value:"root-project"}});
  fireEvent.click(screen.getByRole("button",{name:"프로젝트 범위 저장"}));await waitFor(()=>expect(api.updateNativeProject).toHaveBeenCalledWith(project,{tags:["prod","critical"],parentProjectId:"root-project",isLatest:true,active:true,collectionLogic:"NONE",collectionTag:null}));
});

it("shows durable retry state and enqueues a source retry without credentials",async()=>{
  vi.mocked(api.runProjectSync).mockResolvedValue({...source,state:"idle"});render(<ProjectCatalogPanel canManage/>);
  expect(await screen.findByText(/재시도 대기/)).toBeInTheDocument();fireEvent.click(screen.getByRole("button",{name:"지금 동기화·재시도"}));await waitFor(()=>expect(api.runProjectSync).toHaveBeenCalledWith(source.id));
});

it("clears source API key after a failed registration",async()=>{
  vi.mocked(api.createProjectSyncSource).mockRejectedValue(new Error("원본 연결 실패"));render(<ProjectCatalogPanel canManage/>);await screen.findByLabelText("native-id 태그");
  fireEvent.click(screen.getByText("자동 동기화 원본 등록",{selector:"summary"}));const form=screen.getByRole("group",{name:"읽기 전용 원본 연결"});
  const {within}=await import("@testing-library/react");fireEvent.change(within(form).getByLabelText("연결 이름"),{target:{value:"test"}});fireEvent.change(within(form).getByLabelText("원본 주소"),{target:{value:"http://source.test"}});const key=within(form).getByLabelText("원본 API 키");fireEvent.change(key,{target:{value:"private-test-key"}});fireEvent.submit(form.closest("form")!);
  await screen.findByText("원본 연결 실패");expect(key).toHaveValue("");expect(api.createProjectSyncSource).toHaveBeenCalledWith(expect.objectContaining({allowedOrigins:["http://source.test"],apiKey:"private-test-key",enabled:false}));
});

it("keeps nonadmin catalog controls read-only",async()=>{
  render(<ProjectCatalogPanel canManage={false}/>);expect(await screen.findByLabelText("native-id 태그")).toBeDisabled();expect(screen.queryByRole("button",{name:"지금 동기화·재시도"})).not.toBeInTheDocument();expect(screen.queryByText("자동 동기화 원본 등록",{selector:"summary"})).not.toBeInTheDocument();
});

it("preserves calendar helper specs and dynamic scope when saving an imported policy",async()=>{
  const scope={sourceId:"source",projectIds:["parent"],tags:["prod"],includeChildren:true,onlyLatest:true};const spec={id:"age",subject:"AGE",operator:"NUMERIC_GREATER_THAN",value:"P1Y",timeZone:"UTC",publicationField:"currentVersionPublishedAt"};
  const policy={version:5,rules:[{id:"rule",name:"age",kind:"cel" as const,target:"component" as const,expression:'component.legacyConditions["age"]',legacyConditions:[spec],projectScope:scope,action:"fail" as const,enabled:true,values:[]}],exceptions:[]};
  vi.mocked(api.fetchSbomPolicies).mockResolvedValue(policy);vi.mocked(api.updateSbomPolicies).mockResolvedValue({...policy,version:6});render(<SbomPoliciesPanel canManage/>);
  expect(await screen.findByLabelText("규칙 1 프로젝트 원본")).toHaveValue("source");expect(screen.getByLabelText("규칙 1 CEL 대상")).toBeDisabled();fireEvent.click(screen.getByRole("button",{name:"정책 버전 저장"}));await waitFor(()=>expect(api.updateSbomPolicies).toHaveBeenCalledWith(expect.objectContaining({rules:[expect.objectContaining({projectScope:scope,legacyConditions:[spec]})]})));
});

it("saves collection selection and exposes coverage with missing child analyses",async()=>{
  vi.mocked(api.fetchProjectCatalog).mockResolvedValue({items:[{...project,collectionLogic:"AGGREGATE_DIRECT_CHILDREN"}],total:1,page:1,size:20});
  vi.mocked(api.fetchCollectionMetrics).mockResolvedValue({projectId:project.id,collectionLogic:"AGGREGATE_DIRECT_CHILDREN",collectionTag:null,generatedAt:"2026-10-18T00:00:00Z",coverage:{selectedProjectCount:2,analyzedProjectCount:1,missingProjectCount:1,staleProjectCount:0,complete:false},totals:{componentCount:4,vulnerabilityCount:3,vulnerableComponentCount:1,kevCount:0,policyViolationCount:1,suppressedVulnerabilityCount:0,severityCounts:{High:3},uniqueVulnerabilityCount:2},projects:[]});
  render(<ProjectCatalogPanel canManage/>);fireEvent.click(await screen.findByRole("button",{name:"Collection 지표 조회"}));expect(await screen.findByText(/일부 분석 미반영/)).toBeInTheDocument();expect(screen.getByText(/미분석 1개/)).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("native-id Collection 방식"),{target:{value:"AGGREGATE_LATEST_VERSION_CHILDREN"}});fireEvent.click(screen.getByRole("button",{name:"프로젝트 범위 저장"}));await waitFor(()=>expect(api.updateNativeProject).toHaveBeenCalledWith(projectWithCollection(),expect.objectContaining({collectionLogic:"AGGREGATE_LATEST_VERSION_CHILDREN"})));
});
function projectWithCollection(){return {...project,collectionLogic:"AGGREGATE_DIRECT_CHILDREN"};}

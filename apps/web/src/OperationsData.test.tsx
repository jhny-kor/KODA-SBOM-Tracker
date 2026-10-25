import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as api from "./api";
import { PackageMetadataPanel } from "./OperationsData";
import { SettingsPage } from "./App";
import { SbomPoliciesPanel } from "./SbomPolicies";
import { NativePolicyResult } from "./NativePolicyResult";
import { canPage } from "./permissions";
import type { RunMetadataItem } from "./api";
import type { SbomPolicyDocument } from "./types";

const { mode } = vi.hoisted(() => ({mode:{preview:false}}));
vi.mock("./api", async (importOriginal) => ({...await importOriginal<typeof import("./api")>(),get previewMode(){return mode.preview;},fetchMetadataStatus:vi.fn(),fetchRunMetadata:vi.fn(),refreshRunMetadata:vi.fn(),importMetadata:vi.fn(),importEpssSnapshot:vi.fn(),fetchMigrations:vi.fn(),stageMigration:vi.fn(),stageRemoteMigration:vi.fn(),applyMigration:vi.fn(),fetchSbomPolicies:vi.fn(),updateSbomPolicies:vi.fn()}));
const metadata:RunMetadataItem={component:{identityKey:"component",name:"demo",version:"1.0",purl:"pkg:pypi/demo@1.0"},metadata:{purl:"pkg:pypi/demo@1.0",ecosystem:"pypi",currentVersion:"1.0",status:"fresh",latestVersion:"2.0",currentVersionPublishedAt:"2025-01-01T00:00:00Z",latestPublishedAt:"2026-01-01T00:00:00Z",ageDays:500,versionDistance:3,sourceKind:"public_registry",fetchedAt:"2026-10-18T01:00:00Z",expiresAt:"2026-10-19T01:00:00Z",sourceUrls:["https://pypi.org/pypi/demo/json"]}};
const policy:SbomPolicyDocument={version:7,rules:[{id:"info",name:"정보 정책",kind:"kev",enabled:true,action:"info",values:[],runIds:["source-run"]}],exceptions:[{id:"exception",ruleId:"info",component:"pkg:pypi/demo@1",runId:"source-run",reason:"원본 검토 보존",expiresAt:null}]};
const settingsProps={users:[],services:[],environments:[],tokens:[],ldapSettings:null,policies:[],roleCatalog:[],bundles:[],auditEvents:[],isAdmin:false,canVulnerability:false,canVulnerabilityManage:false,canAudit:false,canUsers:false,canTokens:false,canPolicyEdit:false,canRoles:false,onSync:async()=>{},onActivate:async()=>{},onPolicyChanged:async()=>{},onLdapChanged:()=>{},onChanged:()=>{}};
beforeEach(()=>{
 mode.preview=false;
 vi.mocked(api.fetchMetadataStatus).mockResolvedValue({enabled:true,supportedEcosystems:["pypi","maven"],ttlSeconds:86400,counts:{queued:1,completed:10}});
 vi.mocked(api.fetchRunMetadata).mockResolvedValue({items:[structuredClone(metadata)],total:1,page:1,size:10});
 vi.mocked(api.fetchSbomPolicies).mockResolvedValue(structuredClone(policy));
});
afterEach(()=>{cleanup();vi.resetAllMocks();});
describe("operations data workflow",()=>{
 it("opens settings for exact metadata and migration grants",()=>{for(const permission of ["metadata.view","metadata.manage","catalog.manage"])expect(canPage({id:"u",username:"u",role:"analyst",active:true,permissions:[permission]},"settings")).toBe(true);});
 it("shows metadata tabs only with metadata permission, not policy or admin role",async()=>{
  const{rerender}=render(<SettingsPage {...settingsProps} isAdmin canSbomPolicies/>);expect(screen.queryByRole("tab",{name:"패키지 메타데이터"})).not.toBeInTheDocument();expect(screen.queryByRole("tab",{name:"기존 시스템 이관"})).not.toBeInTheDocument();
  rerender(<SettingsPage {...settingsProps} canMetadata/>);expect(await screen.findByRole("tab",{name:"취약점 데이터"})).toBeInTheDocument();expect(screen.queryByRole("tab",{name:"패키지 메타데이터"})).not.toBeInTheDocument();fireEvent.click(await screen.findByText("패키지 버전·출시일 관측 현황 (고급)",{selector:"summary"}));await screen.findByText(/자동 수집 활성/);expect(screen.queryByLabelText("패키지 캐시 가져오기")).not.toBeInTheDocument();
 });
 it("shows last known stale values without claiming current registry freshness",async()=>{vi.mocked(api.fetchRunMetadata).mockResolvedValue({items:[{...metadata,metadata:{...metadata.metadata,status:"stale",sourceKind:"offline_import"}}],total:1,page:1,size:10});render(<PackageMetadataPanel canManage={false} runId="run"/>);expect(await screen.findByText("유효기간 만료 · 과거 관측")).toBeInTheDocument();expect(screen.getByText("과거 관측값이며 현재 최신 여부를 보증하지 않습니다.")).toBeInTheDocument();expect(screen.getByText("오프라인 반입 자료")).toBeInTheDocument();expect(screen.getByText("2.0")).toBeInTheDocument();expect(screen.getByText(/2026-10-18 10:00:00/)).toBeInTheDocument();});
 it("labels repository file timestamps separately from first publication",async()=>{vi.mocked(api.fetchRunMetadata).mockResolvedValue({items:[{...metadata,metadata:{...metadata.metadata,currentVersionPublishedAtBasis:"artifact_last_modified",latestPublishedAtBasis:"artifact_last_modified",fieldStatus:{currentVersionPublishedAt:"repository_timestamp"},versionDistance:null}}],total:1,page:1,size:10});render(<PackageMetadataPanel canManage={false} runId="run"/>);expect(await screen.findAllByText("저장소 파일 시각 (최초 출시일 미확정)")).toHaveLength(2);expect(screen.getByRole("cell",{name:/파일 시각 경과 500일/})).toBeInTheDocument();expect(screen.getByRole("cell",{name:/릴리스 개수 미제공/})).toBeInTheDocument();});
 it("does not present metadata failures as empty successful results",async()=>{vi.mocked(api.fetchRunMetadata).mockRejectedValue(new Error("캐시 연결 실패"));render(<PackageMetadataPanel canManage={false} runId="run"/>);expect(await screen.findByRole("status")).toHaveTextContent("캐시 연결 실패");expect(screen.getByText(/메타데이터 조회에 실패했습니다/)).toBeInTheDocument();expect(screen.queryByText("이 회차에 메타데이터를 조회할 구성요소가 없습니다.")).not.toBeInTheDocument();});
 it("paginates metadata and reports queued work without analysis completion",async()=>{vi.mocked(api.fetchRunMetadata).mockResolvedValue({items:[metadata],total:11,page:1,size:10});vi.mocked(api.refreshRunMetadata).mockResolvedValue({queued:3,cached:2,unsupported:1,invalid:4,deferred:5});render(<PackageMetadataPanel canManage runId="run"/>);await screen.findByText("유효한 관측 캐시");fireEvent.click(screen.getByRole("button",{name:"패키지 메타데이터 다음"}));await waitFor(()=>expect(api.fetchRunMetadata).toHaveBeenLastCalledWith("run",2));fireEvent.click(screen.getByRole("button",{name:"이 회차 메타데이터 수집 접수"}));expect(await screen.findByRole("status")).toHaveTextContent("수집 접수 3건 · 캐시 2건 · 미지원 1건 · 식별자 오류 4건 · 후속 처리 5건");expect(screen.getByRole("status")).toHaveTextContent("수집 완료 후 새 분석");});
 it("restricts cache export to managers and keeps export page explicit",async()=>{const{rerender}=render(<PackageMetadataPanel canManage={false}/>);await screen.findByText(/자동 수집 활성/);expect(screen.queryByRole("link")).not.toBeInTheDocument();rerender(<PackageMetadataPanel canManage/>);fireEvent.change(screen.getByLabelText("캐시 내보내기 페이지"),{target:{value:"2"}});expect(screen.getByRole("link",{name:"캐시 2페이지 내려받기 (최대 1,000개)"})).toHaveAttribute("href","/api/v1/package-metadata/export?page=2&size=1000");});
 it("routes all package and EPSS imports through the unified bundle while retaining cache observations",async()=>{const{rerender}=render(<PackageMetadataPanel canManage/>);await screen.findByText(/자동 수집 활성/);expect(screen.getByText(/공개 참조 자료에서 통합 tar.gz로 진행/)).toBeInTheDocument();expect(screen.queryByLabelText("패키지 캐시 가져오기")).not.toBeInTheDocument();expect(screen.queryByLabelText("FIRST EPSS CSV 가져오기")).not.toBeInTheDocument();expect(document.querySelector('input[type="file"]')).toBeNull();expect(api.importMetadata).not.toHaveBeenCalled();rerender(<PackageMetadataPanel canManage runId="run"/>);await screen.findByText("유효한 관측 캐시");expect(document.querySelector('input[type="file"]')).toBeNull();expect(screen.getByRole("button",{name:"이 회차 메타데이터 수집 접수"})).toBeInTheDocument();});
 it("preserves indefinite source exceptions and exact run scope through a policy save",async()=>{vi.mocked(api.updateSbomPolicies).mockResolvedValue({...policy,version:8});render(<SbomPoliciesPanel canManage/>);expect(await screen.findByText("만료 없음 (무기한)")).toBeInTheDocument();expect(screen.getByText("고정 회차 범위 1개 · 이관 시점의 원본 범위")).toBeInTheDocument();expect(screen.getAllByText("source-run")).toHaveLength(2);const row=screen.getByText("원본 검토 보존").closest("tr")!;expect(within(row).queryByText(/ · 만료/)).not.toBeInTheDocument();expect(screen.getByLabelText("규칙 1 처리")).toHaveValue("info");fireEvent.click(screen.getByRole("button",{name:"정책 버전 저장"}));await waitFor(()=>expect(api.updateSbomPolicies).toHaveBeenCalledWith(expect.objectContaining({rules:[expect.objectContaining({runIds:["source-run"]})],exceptions:[expect.objectContaining({runId:"source-run",expiresAt:null})]})));});
 it("clears hidden CEL expressions when changing to a built-in policy kind",async()=>{
  vi.mocked(api.fetchSbomPolicies).mockResolvedValue({...policy,rules:[{...policy.rules[0],kind:"cel",expression:"vulnerability.kev",target:"vulnerability"}]});vi.mocked(api.updateSbomPolicies).mockResolvedValue({...policy,version:8});
  render(<SbomPoliciesPanel canManage/>);fireEvent.change(await screen.findByLabelText("규칙 1 조건"),{target:{value:"kev"}});fireEvent.click(screen.getByRole("button",{name:"정책 버전 저장"}));await waitFor(()=>expect(api.updateSbomPolicies).toHaveBeenCalledWith(expect.objectContaining({rules:[expect.objectContaining({kind:"kev",expression:""})]})));
 });
 it("labels INFO decisions and no-expiry evidence accurately",()=>{render(<NativePolicyResult result={{policyState:"completed",policyStatus:"info",policyViolationCount:1,policyViolations:[{policyName:"정보 정책",action:"info",component:"demo"},{policyName:"예외 정책",action:"info",component:"demo",suppressed:true,exception:{reason:"원본 예외",expiresAt:null}}],analysisMetrics:{policyInfoCount:1}}}/>);expect(screen.getAllByText("정보")).toHaveLength(2);expect(screen.getByText("정책 정보")).toBeInTheDocument();expect(screen.getByText(/원본 예외 · 만료 없음 \(무기한\)/)).toBeInTheDocument();});
});

it("keeps EPSS cache export available without individual file imports", async()=>{
 render(<PackageMetadataPanel canManage/>);
 await screen.findByText(/자동 수집 활성/);
 fireEvent.click(screen.getByText("EPSS 관측 캐시 내보내기",{selector:"summary"}));
 expect(screen.getByRole("link",{name:"EPSS 1페이지 내려받기 (최대 1,000개)"})).toHaveAttribute("href","/api/v1/vulnerability-intelligence/export?page=1&size=1000");
 expect(document.querySelector('input[type="file"]')).toBeNull();
 expect(api.importEpssSnapshot).not.toHaveBeenCalled();
});

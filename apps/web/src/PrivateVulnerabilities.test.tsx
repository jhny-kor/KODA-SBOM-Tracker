import "@testing-library/jest-dom/vitest";
import {cleanup,fireEvent,render,screen,waitFor} from "@testing-library/react";
import {afterEach,beforeEach,expect,it,vi} from "vitest";
import * as api from "./api";
import {PrivateVulnerabilitiesPanel} from "./PrivateVulnerabilities";
import type {PrivateAdvisory} from "./api";
vi.mock("./api",async original=>({...await original<typeof import("./api")>(),previewMode:false,fetchPrivateAdvisories:vi.fn(),createPrivateAdvisory:vi.fn(),updatePrivateAdvisory:vi.fn(),fetchPrivateAdvisoryHistory:vi.fn()}));
const item:PrivateAdvisory={id:"advisory",revision:3,createdAt:"2026-10-18T00:00:00Z",updatedAt:"2026-10-18T00:00:00Z",advisoryId:"KODA-2026-001",title:"사내 라이브러리",description:"sample",severity:"High",cvssScore:8,cwes:[79],aliases:[],references:[],state:"draft",affected:[{purl:"pkg:maven/org.example/lib",versions:["1.0"],ranges:[],fixedVersions:["2.0"]}]};
beforeEach(()=>{vi.resetAllMocks();vi.mocked(api.fetchPrivateAdvisories).mockResolvedValue({items:[item],total:1,page:1,size:20});vi.mocked(api.createPrivateAdvisory).mockResolvedValue({...item,revision:1,affectedRunsQueued:0});vi.mocked(api.updatePrivateAdvisory).mockResolvedValue({...item,state:"published",revision:4,affectedRunsQueued:2});});
afterEach(cleanup);
it("preserves comma entry while typing and saves multiple versions and aliases",async()=>{render(<PrivateVulnerabilitiesPanel canManage/>);await screen.findByText(item.title);fireEvent.click(screen.getByRole("button",{name:"자체 취약점 등록"}));fireEvent.change(screen.getByLabelText("자체 등록 취약점 식별자"),{target:{value:"KODA-2026-002"}});fireEvent.change(screen.getByLabelText("제목"),{target:{value:"new advisory"}});fireEvent.change(screen.getByLabelText("PURL 1"),{target:{value:"pkg:npm/example"}});const versions=screen.getByLabelText("정확한 영향 버전 1");fireEvent.change(versions,{target:{value:"1.0.0,"}});expect(versions).toHaveValue("1.0.0,");fireEvent.change(versions,{target:{value:"1.0.0, 1.1.0"}});const aliases=screen.getByLabelText("별칭 (쉼표 구분)");fireEvent.change(aliases,{target:{value:"CVE-2026-10000,"}});expect(aliases).toHaveValue("CVE-2026-10000,");fireEvent.change(aliases,{target:{value:"CVE-2026-10000, GHSA-test"}});fireEvent.click(screen.getByRole("button",{name:"자체 등록 취약점 저장"}));await waitFor(()=>expect(api.createPrivateAdvisory).toHaveBeenCalledWith(expect.objectContaining({aliases:["CVE-2026-10000","GHSA-test"],affected:[expect.objectContaining({versions:["1.0.0","1.1.0"]})]})));});
it("locks existing identifiers and publishes against the observed revision",async()=>{render(<PrivateVulnerabilitiesPanel canManage/>);fireEvent.click(await screen.findByRole("button",{name:`${item.advisoryId} 편집`}));expect(screen.getByLabelText("자체 등록 취약점 식별자")).toBeDisabled();fireEvent.click(screen.getByRole("button",{name:"편집 취소"}));fireEvent.click(screen.getByRole("button",{name:`${item.advisoryId} 게시`}));await waitFor(()=>expect(api.updatePrivateAdvisory).toHaveBeenCalledWith(item,expect.objectContaining({state:"published"})));expect(await screen.findByText(/재분석 접수 2개/)).toBeInTheDocument();});
it("has no management actions without permission",async()=>{render(<PrivateVulnerabilitiesPanel canManage={false}/>);await screen.findByText(item.title);expect(screen.queryByRole("button",{name:"자체 취약점 등록"})).not.toBeInTheDocument();expect(screen.queryByRole("button",{name:`${item.advisoryId} 게시`})).not.toBeInTheDocument();});

it("keeps remaining package text aligned after removing the first affected row",async()=>{
  const twoPackages={...item,affected:[item.affected[0],{purl:"pkg:npm/second",versions:["3.0.0","3.1.0"],ranges:[],fixedVersions:["4.0.0"]}]};
  vi.mocked(api.fetchPrivateAdvisories).mockResolvedValue({items:[twoPackages],total:1,page:1,size:20});
  render(<PrivateVulnerabilitiesPanel canManage/>);fireEvent.click(await screen.findByRole("button",{name:`${item.advisoryId} 편집`}));
  fireEvent.click(screen.getByRole("button",{name:"패키지 1 제거"}));
  expect(screen.getByLabelText("PURL 1")).toHaveValue("pkg:npm/second");expect(screen.getByLabelText("정확한 영향 버전 1")).toHaveValue("3.0.0, 3.1.0");expect(screen.getByLabelText("수정 권장 버전 1")).toHaveValue("4.0.0");
  fireEvent.click(screen.getByRole("button",{name:"자체 등록 취약점 저장"}));await waitFor(()=>expect(api.updatePrivateAdvisory).toHaveBeenCalledWith(twoPackages,expect.objectContaining({affected:[twoPackages.affected[1]]})));
});

it("provides a named region without referring to the removed top-level tab", async () => {
  render(<PrivateVulnerabilitiesPanel canManage={false}/>);
  await screen.findByText(item.title);
  const region = screen.getByRole("region", {name: "자체 등록 취약점"});
  expect(region).toHaveAttribute("id", "settings-panel-private-vulnerabilities");
  expect(region).not.toHaveAttribute("aria-labelledby");
  expect(screen.queryByRole("tabpanel")).not.toBeInTheDocument();
});

import { useEffect, useState, type FormEvent } from "react";
import { createNativeProject, fetchProjectCatalog, fetchProjectRuns, previewMode, updateNativeProject } from "./api";
import type { CollectionLogic, NativeProject } from "./api";
import type { CatalogItem, SbomRun } from "./types";
import { formatSeoulDateTime } from "./format";
import { WorkflowPagination } from "./ReanalysisSchedule";
import { CollectionMetricsView } from "./CollectionMetrics";
import { FlowSelect } from "./ScrollingSelect";
import { ScrollingText } from "./ScrollingText";
import "./environment-administration.css";

const collectionModes:Record<CollectionLogic,string>={NONE:"일반 프로젝트",AGGREGATE_DIRECT_CHILDREN:"직접 자식 집계",AGGREGATE_DIRECT_CHILDREN_WITH_TAG:"태그가 일치하는 직접 자식",AGGREGATE_LATEST_VERSION_CHILDREN:"최신 버전 자식 집계",AGGREGATE_ALL_DESCENDANTS:"모든 하위 프로젝트 집계"};

const errorMessage = (value: unknown) => value instanceof Error ? value.message : "처리에 실패했습니다.";
const split = (value:string) => value.split(",").map(v => v.trim()).filter(Boolean);

const analysisStates:Record<string,string>={completed:"분석 완료",running:"분석 중",failed:"분석 실패",queued:"분석 대기"};
const runStates:Record<SbomRun["state"],string>={completed:"완료",processing:"처리 중",partial:"일부 실패",failed:"실패",queued:"대기",archived:"보관"};

function ProjectRuns({projectId,onOpenRun}:{projectId:string;onOpenRun?:(run:SbomRun)=>void}) {
  const [page,setPage]=useState(1),[reload,setReload]=useState(0);
  const [result,setResult]=useState<{items:SbomRun[];total:number}>({items:[],total:0});
  const [load,setLoad]=useState<"loading"|"ready"|"error">("loading"),[message,setMessage]=useState("");
  useEffect(()=>{let active=true;
    void fetchProjectRuns(projectId,page).then(value=>{if(active){setResult(value);setLoad("ready");}}).catch(error=>{if(active){setMessage(errorMessage(error));setLoad("error");}});
    return()=>{active=false;};
  },[projectId,page,reload]);
  return <section className="project-linked-runs" aria-label="연결된 SBOM 회차와 점검결과">
    <div className="project-linked-heading"><h4>연결된 SBOM 회차·점검결과</h4><button type="button" className="secondary compact" disabled={load==="loading"} onClick={()=>{setLoad("loading");setReload(value=>value+1);}}>회차 새로고침</button></div>
    {load==="loading" ? <p role="status">연결된 회차 조회 중</p> : load==="error" ? <p role="alert">연결된 회차를 조회하지 못했습니다. {message} 새로고침으로 다시 시도하세요.</p> : <>
      <p className="muted">직접 연결된 회차와 서비스·환경·릴리스가 유일하게 일치하는 회차입니다. 점검결과를 열면 분석 리비전과 상세 근거를 확인할 수 있습니다.</p>
      <div className="project-runs-scroll" role="region" aria-label="프로젝트 회차 목록" tabIndex={0}><table className="project-runs-table"><colgroup><col className="project-release-column"/><col className="project-scope-column"/><col className="project-state-column"/><col className="project-count-column"/><col className="project-count-column"/><col className="project-count-column"/><col className="project-date-column"/><col className="project-result-column"/></colgroup><thead><tr><th>회차 / 릴리스</th><th>서비스 / 환경</th><th>상태</th><th>구성요소</th><th>취약 구성요소</th><th>정책 위반</th><th>업로드 (서울)</th><th>점검결과</th></tr></thead><tbody>
        {result.items.map(run=><tr key={run.id}><td><ScrollingText>{`${run.roundNumber}차 / ${run.releaseVersion}`}</ScrollingText></td><td><ScrollingText>{`${run.service.name} / ${run.environment.name}`}</ScrollingText></td><td><span className={`state ${run.state}`}>{runStates[run.state]}</span>{run.analysisState&&run.analysisState!=="completed"&&<small className="workflow-id muted">{analysisStates[run.analysisState]}</small>}</td><td>{run.componentCount.toLocaleString()}</td><td>{run.analysisAvailable===false ? "미평가" : (run.vulnerableComponentCount?.toLocaleString() ?? "미평가")}</td><td>{run.analysisAvailable===false ? "미평가" : run.policyViolationCount.toLocaleString()}</td><td>{formatSeoulDateTime(run.createdAt)}</td><td><a className="project-result-link" href={`${window.location.pathname}?page=runs&runId=${encodeURIComponent(run.id)}`} onClick={event=>{if(onOpenRun&&!event.ctrlKey&&!event.metaKey&&!event.shiftKey&&!event.altKey&&event.button===0){event.preventDefault();onOpenRun(run);}}}>{run.analysisAvailable===false ? "회차 상세 보기" : "점검결과 보기"}</a></td></tr>)}
        {!result.items.length&&<tr><td colSpan={8}>연결된 SBOM 회차가 없습니다. 프로젝트 이름만으로 회차를 추정하지 않습니다.</td></tr>}
      </tbody></table></div>
      <WorkflowPagination page={page} total={result.total} pageSize={10} label="연결된 회차" onPage={value=>{setLoad("loading");setPage(value);}}/>
    </>}
  </section>;
}

function ProjectEditor({project,disabled,save,canViewRuns,onOpenRun}:{project:NativeProject;disabled:boolean;canViewRuns:boolean;onOpenRun?:(run:SbomRun)=>void;save:(project:NativeProject,body:Record<string,unknown>)=>Promise<void>}) {
  const [runsOpen,setRunsOpen]=useState(false);
  const [tags,setTags] = useState(project.tags.join(", "));
  const [parent,setParent] = useState(project.parentProjectId || "");
  const [latest,setLatest] = useState(project.isLatest);
  const [active,setActive] = useState(project.active);
  const [logic,setLogic] = useState<CollectionLogic>(project.collectionLogic || "NONE");
  const [tag,setTag] = useState(project.collectionTag || "");
  return <form className="table-frame workflow-form project-catalog-card" onSubmit={event => {event.preventDefault();void save(project,{tags:split(tags),parentProjectId:parent.trim() || null,isLatest:latest,active,collectionLogic:logic,collectionTag:logic==="AGGREGATE_DIRECT_CHILDREN_WITH_TAG" ? tag.trim() : null});}}>
    <div className="project-catalog-card-heading"><h3>{canViewRuns ? <button type="button" className="project-catalog-open" aria-expanded={runsOpen} aria-controls={`project-runs-${project.id}`} onClick={()=>setRunsOpen(value=>!value)}><ScrollingText className="project-title-text" focusable={false}>{`${project.name} · ${project.version || "버전 없음"}`}</ScrollingText><span aria-hidden="true">{runsOpen ? "▴" : "▾"}</span></button> : <ScrollingText>{`${project.name} · ${project.version || "버전 없음"}`}</ScrollingText>}</h3><span className="muted">{project.active ? "활성" : "비활성"}{project.isLatest ? " · 최신 버전" : ""}</span></div>
    <p className="mono muted"><ScrollingText>{`${project.sourceId} / ${project.sourceProjectId}`}</ScrollingText></p>
    {canViewRuns ? <div id={`project-runs-${project.id}`}>{runsOpen&&<ProjectRuns projectId={project.id} onOpenRun={onOpenRun}/>}</div> : <p className="muted">연결된 회차와 점검결과를 보려면 회차 조회 권한이 필요합니다.</p>}
    <fieldset disabled={disabled}><legend>프로젝트 범위 v{project.revision}</legend>
      <label>태그<input aria-label={`${project.id} 태그`} value={tags} onChange={e=>setTags(e.target.value)} placeholder="쉼표로 구분"/></label>
      <label>부모 원본 프로젝트 ID<input aria-label={`${project.id} 부모`} value={parent} onChange={e=>setParent(e.target.value)} placeholder="같은 원본의 프로젝트 ID, 비우면 최상위"/></label>
      <label className="checkbox-label"><input type="checkbox" checked={latest} onChange={e=>setLatest(e.target.checked)}/>최신 버전</label>
      <label className="checkbox-label"><input type="checkbox" checked={active} onChange={e=>setActive(e.target.checked)}/>활성 프로젝트</label>
      <label>Collection 집계 방식<FlowSelect aria-label={`${project.id} Collection 방식`} value={logic} onChange={e=>setLogic(e.target.value as CollectionLogic)}>{Object.entries(collectionModes).map(([value,label])=><option key={value} value={value}>{label}</option>)}</FlowSelect></label>
      {logic==="AGGREGATE_DIRECT_CHILDREN_WITH_TAG"&&<label>집계 태그<input required value={tag} onChange={e=>setTag(e.target.value)}/></label>}
      {!disabled && <button className="secondary" type="submit">프로젝트 범위 저장</button>}
    </fieldset><p>변경은 다음 분석에 적용됩니다. 과거 리비전의 범위·판정은 보존합니다.</p>
    {(project.collectionLogic && project.collectionLogic!=="NONE")&&<CollectionMetricsView projectId={project.id}/> }
  </form>;
}


export function ProjectCatalogPanel({canManage,canViewRuns=false,onOpenRun,services=[],environments=[]}:{canManage:boolean;canViewRuns?:boolean;onOpenRun?:(run:SbomRun)=>void;services?:CatalogItem[];environments?:CatalogItem[]}) {
  const [projects,setProjects] = useState<{items:NativeProject[];total:number}>({items:[],total:0});
  const [projectPage,setProjectPage] = useState(1),[reload,setReload] = useState(0);
  const [message,setMessage] = useState(""),[load,setLoad] = useState("loading"),[busy,setBusy] = useState(false);
  const editable = canManage && !previewMode;
  useEffect(()=>{if(previewMode)return;let active=true;
    void fetchProjectCatalog(projectPage).then(p=>{if(active){setProjects(p);setLoad("ready");}}).catch(error=>{if(active){setMessage(errorMessage(error));setLoad("error");}});
    return()=>{active=false;};
  },[projectPage,reload]);
  async function act(work:()=>Promise<unknown>) {setBusy(true);setMessage("");try{await work();setMessage("저장·접수를 완료했습니다. 새로고침으로 최신 상태를 확인하세요.");setReload(v=>v+1);}catch(error){setMessage(errorMessage(error));}finally{setBusy(false);}}
  async function createProject(event:FormEvent<HTMLFormElement>) {event.preventDefault();const values=new FormData(event.currentTarget);await act(()=>createNativeProject({sourceId:"native",sourceProjectId:String(values.get("identity")),serviceId:String(values.get("service")),environmentId:String(values.get("environment")),name:String(values.get("name")),version:String(values.get("version")),tags:split(String(values.get("tags")||"")),...(values.get("runId") ? {runId:String(values.get("runId"))} : {})}));}
  return <section className="settings-panel workflow-panel tracker-view tracker-data-panel project-catalog-panel" aria-label="프로젝트 계층"><div className="settings-panel-heading"><h2>프로젝트 계층·태그·최신 버전</h2><button className="secondary" disabled={busy||previewMode} onClick={()=>{setLoad("loading");setReload(v=>v+1);}}>프로젝트 새로고침</button></div>
    <div className="tracker-panel-body"><p>프로젝트 계층·태그·최신 버전 범위를 관리합니다. 프로젝트 이름을 누르면 연결된 SBOM 회차와 점검결과를 확인할 수 있습니다.</p>
    {message && <p role="status">{message}</p>}{previewMode ? <p>샘플 모드 · 실제 조회·저장 안 함</p> : load!=="ready" ? <p>{load==="error" ? "프로젝트 조회 실패. 새로고침으로 재시도하세요." : "프로젝트 조회 중"}</p> : <>
      <div className="policy-rules">{projects.items.map(project=><ProjectEditor key={`${project.id}-${project.revision}`} project={project} canViewRuns={canViewRuns&&!previewMode} onOpenRun={onOpenRun} disabled={!editable||busy} save={(p,body)=>act(()=>updateNativeProject(p,body))}/>)}</div>
      {!projects.items.length && <p>등록된 프로젝트가 없습니다.</p>}<WorkflowPagination page={projectPage} total={projects.total} pageSize={20} label="프로젝트 목록" onPage={setProjectPage}/>
    </>}
    {editable && <><details><summary>자체 프로젝트 등록</summary><form className="workflow-form" onSubmit={createProject}><fieldset disabled={busy}><legend>새 프로젝트</legend><label>식별자<input name="identity" required maxLength={128}/></label><label>이름<input name="name" required maxLength={255}/></label><label>버전<input name="version" maxLength={255}/></label><label>서비스<FlowSelect name="service" required>{services.map(s=><option key={s.id} value={s.id}>{s.name}</option>)}</FlowSelect></label><label>환경<FlowSelect name="environment" required>{environments.map(s=><option key={s.id} value={s.id}>{s.name}</option>)}</FlowSelect></label><label>태그<input name="tags"/></label><label>기존 회차 ID (선택)<input name="runId"/></label><button className="secondary">프로젝트 등록</button></fieldset></form></details></>}
    </div>
  </section>;
}

import { useEffect, useState, type FormEvent } from "react";
import { createNativeProject, createProjectSyncSource, fetchProjectCatalog, fetchProjectSyncEvents, fetchProjectSyncSources, previewMode, runProjectSync, updateNativeProject, updateProjectSyncSource } from "./api";
import type { CollectionLogic, NativeProject, ProjectSyncSource } from "./api";
import type { CatalogItem } from "./types";
import { WorkflowPagination } from "./ReanalysisSchedule";
import { formatSeoulDateTime } from "./format";
import { CollectionMetricsView } from "./CollectionMetrics";

const collectionModes:Record<CollectionLogic,string>={NONE:"일반 프로젝트",AGGREGATE_DIRECT_CHILDREN:"직접 자식 집계",AGGREGATE_DIRECT_CHILDREN_WITH_TAG:"태그가 일치하는 직접 자식",AGGREGATE_LATEST_VERSION_CHILDREN:"최신 버전 자식 집계",AGGREGATE_ALL_DESCENDANTS:"모든 하위 프로젝트 집계"};

const errorMessage = (value: unknown) => value instanceof Error ? value.message : "처리에 실패했습니다.";
const split = (value:string) => value.split(",").map(v => v.trim()).filter(Boolean);
const states:Record<string,string> = {idle:"대기",running:"동기화 중",retrying:"재시도 대기",failed:"실패",blocked:"검토 필요",completed:"완료"};

function ProjectEditor({project,disabled,save}:{project:NativeProject;disabled:boolean;save:(project:NativeProject,body:Record<string,unknown>)=>Promise<void>}) {
  const [tags,setTags] = useState(project.tags.join(", "));
  const [parent,setParent] = useState(project.parentProjectId || "");
  const [latest,setLatest] = useState(project.isLatest);
  const [active,setActive] = useState(project.active);
  const [logic,setLogic] = useState<CollectionLogic>(project.collectionLogic || "NONE");
  const [tag,setTag] = useState(project.collectionTag || "");
  return <form className="table-frame workflow-form" onSubmit={event => {event.preventDefault();void save(project,{tags:split(tags),parentProjectId:parent.trim() || null,isLatest:latest,active,collectionLogic:logic,collectionTag:logic==="AGGREGATE_DIRECT_CHILDREN_WITH_TAG" ? tag.trim() : null});}}>
    <h4>{project.name} · {project.version || "버전 없음"}</h4><p className="mono wrap">{project.sourceId} / {project.sourceProjectId}</p>
    <fieldset disabled={disabled}><legend>프로젝트 범위 v{project.revision}</legend>
      <label>태그<input aria-label={`${project.id} 태그`} value={tags} onChange={e=>setTags(e.target.value)} placeholder="쉼표로 구분"/></label>
      <label>부모 원본 프로젝트 ID<input aria-label={`${project.id} 부모`} value={parent} onChange={e=>setParent(e.target.value)} placeholder="같은 원본의 프로젝트 ID, 비우면 최상위"/></label>
      <label className="checkbox-label"><input type="checkbox" checked={latest} onChange={e=>setLatest(e.target.checked)}/>최신 버전</label>
      <label className="checkbox-label"><input type="checkbox" checked={active} onChange={e=>setActive(e.target.checked)}/>활성 프로젝트</label>
      <label>Collection 집계 방식<select aria-label={`${project.id} Collection 방식`} value={logic} onChange={e=>setLogic(e.target.value as CollectionLogic)}>{Object.entries(collectionModes).map(([value,label])=><option key={value} value={value}>{label}</option>)}</select></label>
      {logic==="AGGREGATE_DIRECT_CHILDREN_WITH_TAG"&&<label>집계 태그<input required value={tag} onChange={e=>setTag(e.target.value)}/></label>}
      {!disabled && <button className="secondary" type="submit">프로젝트 범위 저장</button>}
    </fieldset><p>변경은 다음 분석에 적용됩니다. 과거 리비전의 범위·판정은 보존합니다.</p>
    {(project.collectionLogic && project.collectionLogic!=="NONE")&&<CollectionMetricsView projectId={project.id}/> }
  </form>;
}

function SourceEditor({source,disabled,act,history}:{source:ProjectSyncSource;disabled:boolean;act:(work:()=>Promise<unknown>)=>Promise<void>;history:(id:string)=>void}) {
  const [interval,setInterval] = useState(source.intervalMinutes);
  const [key,setKey] = useState("");
  return <div className="table-frame workflow-form"><h4>{source.name}</h4><p className="mono wrap">{source.baseUrl}</p>
    <p>{states[source.state] || source.state} · {source.enabled ? "활성" : "중지"} · 시도 {source.attempts}회<br/>다음 실행: {formatSeoulDateTime(source.nextRunAt)}<br/>최근 성공: {formatSeoulDateTime(source.lastSuccessAt)}</p>
    {source.lastError && <p role="alert" className="drawer-error">{source.lastError}</p>}
    <fieldset disabled={disabled}><legend>자동 동기화 설정 v{source.version}</legend><label>주기 (분)<input type="number" min={5} max={10080} value={interval} onChange={e=>setInterval(Number(e.target.value))}/></label>
      <label>API 키 교체 (비우면 유지)<input type="password" autoComplete="off" value={key} onChange={e=>setKey(e.target.value)}/></label>
      {!disabled && <div className="button-row"><button className="secondary" disabled={source.state==="running"} onClick={()=>void act(async()=>{try{return await updateProjectSyncSource(source,{intervalMinutes:interval,...(key ? {apiKey:key} : {})});}finally{setKey("");}})}>동기화 설정 저장</button>
      <button className="secondary" disabled={source.state==="running"} onClick={()=>void act(()=>updateProjectSyncSource(source,{enabled:!source.enabled}))}>{source.enabled ? "자동 동기화 중지" : "자동 동기화 활성화"}</button>
      <button className="secondary" disabled={!source.enabled || source.state==="running"} onClick={()=>void act(()=>runProjectSync(source.id))}>지금 동기화·재시도</button></div>}
    </fieldset><button className="secondary" onClick={()=>history(source.id)}>동기화 이력 보기</button>
  </div>;
}

export function ProjectCatalogPanel({canManage,services=[],environments=[]}:{canManage:boolean;services?:CatalogItem[];environments?:CatalogItem[]}) {
  const [projects,setProjects] = useState<{items:NativeProject[];total:number}>({items:[],total:0});
  const [sources,setSources] = useState<{items:ProjectSyncSource[];total:number}>({items:[],total:0});
  const [projectPage,setProjectPage] = useState(1),[sourcePage,setSourcePage] = useState(1),[reload,setReload] = useState(0);
  const [message,setMessage] = useState(""),[load,setLoad] = useState("loading"),[busy,setBusy] = useState(false);
  const [sourceKey,setSourceKey] = useState(""),[events,setEvents] = useState<Awaited<ReturnType<typeof fetchProjectSyncEvents>> | null>(null);
  const editable = canManage && !previewMode;
  useEffect(()=>{if(previewMode)return;let active=true;
    void Promise.all([fetchProjectCatalog(projectPage),fetchProjectSyncSources(sourcePage)]).then(([p,s])=>{if(active){setProjects(p);setSources(s);setLoad("ready");}}).catch(error=>{if(active){setMessage(errorMessage(error));setLoad("error");}});
    return()=>{active=false;};
  },[projectPage,sourcePage,reload]);
  async function act(work:()=>Promise<unknown>) {setBusy(true);setMessage("");try{await work();setMessage("저장·접수를 완료했습니다. 새로고침으로 최신 상태를 확인하세요.");setReload(v=>v+1);}catch(error){setMessage(errorMessage(error));}finally{setBusy(false);}}
  async function createSource(event:FormEvent<HTMLFormElement>) {event.preventDefault();const form=event.currentTarget,values=new FormData(form);await act(async()=>{try{const baseUrl=String(values.get("url"));const parsed=new URL(baseUrl);if(!["http:","https:"].includes(parsed.protocol)||parsed.username||parsed.password)throw new Error("원본 주소 형식을 확인하세요.");return await createProjectSyncSource({name:String(values.get("name")),baseUrl,allowedOrigins:[parsed.origin],apiKey:sourceKey,projectUuids:split(String(values.get("projects")||"")),intervalMinutes:Number(values.get("interval")),enabled:values.get("enabled")==="on"});}finally{setSourceKey("");}});}
  async function createProject(event:FormEvent<HTMLFormElement>) {event.preventDefault();const values=new FormData(event.currentTarget);await act(()=>createNativeProject({sourceId:"native",sourceProjectId:String(values.get("identity")),serviceId:String(values.get("service")),environmentId:String(values.get("environment")),name:String(values.get("name")),version:String(values.get("version")),tags:split(String(values.get("tags")||"")),...(values.get("runId") ? {runId:String(values.get("runId"))} : {})}));}
  function history(id:string) {setEvents(null);void fetchProjectSyncEvents(id).then(setEvents).catch(error=>setMessage(errorMessage(error)));}
  return <section className="settings-panel workflow-panel" aria-label="프로젝트 계층·자동 동기화"><div className="settings-panel-heading"><h2>프로젝트 계층·태그·최신 버전</h2><button className="secondary" disabled={busy||previewMode} onClick={()=>{setLoad("loading");setReload(v=>v+1);}}>프로젝트·동기화 새로고침</button></div>
    <p>원본 서버를 종료한 뒤에도 KODA에서 계층·태그·최신 버전 범위를 관리합니다. 원본을 계속 사용할 때만 자동 동기화를 활성화하세요. 통신 실패는 최대 5회 재시도하며 변환 불가·로컬 정책 충돌은 검토를 위해 중단합니다.</p>
    {message && <p role="status">{message}</p>}{previewMode ? <p>샘플 모드 · 실제 조회·저장 안 함</p> : load!=="ready" ? <p>{load==="error" ? "프로젝트·동기화 조회 실패. 새로고침으로 재시도하세요." : "프로젝트·동기화 조회 중"}</p> : <>
      <div className="policy-rules">{projects.items.map(project=><ProjectEditor key={`${project.id}-${project.revision}`} project={project} disabled={!editable||busy} save={(p,body)=>act(()=>updateNativeProject(p,body))}/>)}</div>
      {!projects.items.length && <p>등록된 프로젝트가 없습니다.</p>}<WorkflowPagination page={projectPage} total={projects.total} pageSize={20} label="프로젝트 목록" onPage={setProjectPage}/>
      <h3>원본 주기 동기화·재시도</h3><p>원본 키는 서버에서 암호화하며 응답·브라우저 저장소에 반환하지 않습니다. 원본은 읽기만 합니다.</p>
      {sources.items.map(source=><SourceEditor key={`${source.id}-${source.version}`} source={source} disabled={!editable||busy} act={act} history={history}/>)}
      {!sources.items.length && <p>자동 동기화 원본이 없습니다.</p>}<WorkflowPagination page={sourcePage} total={sources.total} pageSize={20} label="동기화 원본" onPage={setSourcePage}/>
      {events && <details open><summary>동기화 이력 · 최근 {events.items.length}건 / 전체 {events.total}건</summary><pre className="migration-report">{JSON.stringify(events.items,null,2)}</pre></details>}
    </>}
    {editable && <><details><summary>자체 프로젝트 등록</summary><form className="workflow-form" onSubmit={createProject}><fieldset disabled={busy}><legend>새 프로젝트</legend><label>식별자<input name="identity" required maxLength={128}/></label><label>이름<input name="name" required maxLength={255}/></label><label>버전<input name="version" maxLength={255}/></label><label>서비스<select name="service" required>{services.map(s=><option key={s.id} value={s.id}>{s.name}</option>)}</select></label><label>환경<select name="environment" required>{environments.map(s=><option key={s.id} value={s.id}>{s.name}</option>)}</select></label><label>태그<input name="tags"/></label><label>기존 회차 ID (선택)<input name="runId"/></label><button className="secondary">프로젝트 등록</button></fieldset></form></details>
      <details><summary>자동 동기화 원본 등록</summary><form className="workflow-form" onSubmit={createSource}><fieldset disabled={busy}><legend>읽기 전용 원본 연결</legend><label>연결 이름<input name="name" required/></label><label>원본 주소<input name="url" type="url" required/></label><label>원본 API 키<input type="password" autoComplete="off" required value={sourceKey} onChange={e=>setSourceKey(e.target.value)}/></label><label>프로젝트 UUID (쉼표 구분, 비우면 전체)<input name="projects"/></label><label>주기 (분)<input name="interval" type="number" min={5} max={10080} defaultValue={1440} required/></label><label className="checkbox-label"><input name="enabled" type="checkbox"/>등록 후 자동 동기화 활성화</label><button className="secondary">동기화 원본 등록</button></fieldset></form></details></>}
  </section>;
}

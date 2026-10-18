import { useEffect, useRef, useState, type FormEvent } from "react";
import { createPrivateAdvisory, fetchPrivateAdvisories, fetchPrivateAdvisoryHistory, previewMode, updatePrivateAdvisory } from "./api";
import type { PrivateAdvisory, PrivateAdvisoryInput, PrivateAffected } from "./api";
import { WorkflowPagination } from "./ReanalysisSchedule";
import { formatSeoulDateTime } from "./format";

const split = (value:string) => value.split(/[,\n]/).map(item=>item.trim()).filter(Boolean);
const messageOf = (error:unknown) => error instanceof Error ? error.message : "사내 취약점 처리에 실패했습니다.";
const stateLabels = {draft:"초안",published:"게시됨",withdrawn:"철회됨"};
const emptyAffected = ():PrivateAffected => ({purl:"",versions:[],ranges:[],fixedVersions:[]});
const emptyAdvisory = ():PrivateAdvisoryInput => ({advisoryId:"",title:"",description:"",severity:"High",cvssScore:null,cwes:[],aliases:[],references:[],state:"draft",affected:[emptyAffected()]});

function ListInput({label,values,onChange,multiline=false}:{label:string;values:(string|number)[];onChange:(values:string[])=>void;multiline?:boolean}) {
  const [text,setText]=useState(values.join(multiline ? "\n" : ", "));
  const change=(value:string)=>{setText(value);onChange(split(value));};
  return <label>{label}{multiline ? <textarea value={text} onChange={e=>change(e.target.value)}/> : <input value={text} onChange={e=>change(e.target.value)}/>}</label>;
}

function AdvisoryForm({record,disabled,onSave,onCancel}:{record:PrivateAdvisory|null;disabled:boolean;onSave:(body:PrivateAdvisoryInput)=>Promise<void>;onCancel:()=>void}) {
  const [draft,setDraft] = useState<PrivateAdvisoryInput>(()=>record ? {advisoryId:record.advisoryId,title:record.title,description:record.description,severity:record.severity,cvssScore:record.cvssScore,cwes:record.cwes,aliases:record.aliases,references:record.references,state:record.state,affected:record.affected} : emptyAdvisory());
  const nextRowKey = useRef(draft.affected.length);
  const [rowKeys,setRowKeys] = useState(()=>draft.affected.map((_,index)=>index));
  function set<K extends keyof PrivateAdvisoryInput>(key:K,value:PrivateAdvisoryInput[K]) {setDraft(current=>({...current,[key]:value}));}
  function affected(index:number,patch:Partial<PrivateAffected>) {setDraft(current=>({...current,affected:current.affected.map((item,i)=>i===index ? {...item,...patch} : item)}));}
  function range(index:number,patch:Partial<PrivateAffected["ranges"][number]>) {const item=draft.affected[index];affected(index,{ranges:[{scheme:item.ranges[0]?.scheme || "semver",introduced:item.ranges[0]?.introduced || null,fixed:item.ranges[0]?.fixed || null,lastAffected:item.ranges[0]?.lastAffected || null,...patch},...item.ranges.slice(1)]});}
  function submit(event:FormEvent) {event.preventDefault();void onSave(draft);}
  return <form className="workflow-form table-frame private-advisory-form" aria-label="사내 취약점 편집" onSubmit={submit}><h3>{record ? `${record.advisoryId} · 리비전 ${record.revision} 편집` : "새 사내 취약점"}</h3><fieldset disabled={disabled}><legend>취약점 정보</legend>
    <label>사내 취약점 식별자<input required disabled={Boolean(record)} maxLength={128} value={draft.advisoryId} onChange={e=>set("advisoryId",e.target.value)} placeholder="KODA-2026-001 또는 CVE ID"/></label>
    <label>제목<input required maxLength={500} value={draft.title} onChange={e=>set("title",e.target.value)}/></label>
    <label>설명<textarea rows={3} value={draft.description} onChange={e=>set("description",e.target.value)}/></label>
    <label>심각도<select value={draft.severity} onChange={e=>set("severity",e.target.value as PrivateAdvisoryInput["severity"])}>{["Critical","High","Medium","Low","Unknown"].map(value=><option key={value}>{value}</option>)}</select></label>
    <label>CVSS 점수 (선택)<input type="number" min={0} max={10} step={0.1} value={draft.cvssScore ?? ""} onChange={e=>set("cvssScore",e.target.value==="" ? null : Number(e.target.value))}/></label>
    <ListInput label="CWE 번호 (쉼표 구분)" values={draft.cwes} onChange={values=>set("cwes",values.map(value=>Number(value.replace(/^CWE-/i,""))))}/>
    <ListInput label="별칭 (쉼표 구분)" values={draft.aliases} onChange={values=>set("aliases",values)}/>
    <ListInput label="참고 URL (한 줄에 하나)" values={draft.references} onChange={values=>set("references",values)} multiline/>
    <label>게시 상태<select value={draft.state} onChange={e=>set("state",e.target.value as PrivateAdvisoryInput["state"])}>{Object.entries(stateLabels).map(([value,label])=><option key={value} value={value}>{label}</option>)}</select></label>
    <p>초안은 분석에 적용되지 않습니다. 게시·게시 내용 변경·철회 시 해당 패키지를 포함하는 회차의 재분석을 접수합니다. 과거 분석 리비전은 보존됩니다.</p>
    <h4>영향 패키지</h4><p>버전을 제외한 PURL과 정확한 버전 목록 또는 범위를 입력하세요. 범위의 시작은 포함, 수정 버전은 제외, 마지막 영향 버전은 포함합니다. SemVer 범위는 x.y.z 정식 버전 형식입니다.</p>
    {draft.affected.map((item,index)=><fieldset key={rowKeys[index]}><legend>영향 패키지 {index+1}</legend>
      <label>PURL {index+1}<input required value={item.purl} onChange={e=>affected(index,{purl:e.target.value})} placeholder="pkg:maven/org.example/library"/></label>
      <ListInput label={`정확한 영향 버전 ${index+1}`} values={item.versions} onChange={values=>affected(index,{versions:values})}/>
      <label>범위 사용 {index+1}<input type="checkbox" checked={item.ranges.length>0} onChange={e=>affected(index,{ranges:e.target.checked ? [{scheme:"semver",introduced:null,fixed:null,lastAffected:null}] : []})}/></label>
      {item.ranges.length>0 && <><label>버전 비교 방식 {index+1}<select value={item.ranges[0].scheme} onChange={e=>range(index,{scheme:e.target.value as "maven"|"semver"})}><option value="semver">SemVer</option><option value="maven">Maven</option></select></label><label>영향 시작 버전 {index+1}<input value={item.ranges[0].introduced || ""} onChange={e=>range(index,{introduced:e.target.value || null})}/></label><label>범위 수정 버전 {index+1}<input value={item.ranges[0].fixed || ""} onChange={e=>range(index,{fixed:e.target.value || null})}/></label><label>마지막 영향 버전 {index+1}<input value={item.ranges[0].lastAffected || ""} onChange={e=>range(index,{lastAffected:e.target.value || null})}/></label>{item.ranges.length>1 && <p>추가 범위 {item.ranges.length-1}개는 저장 시 보존됩니다.</p>}</>}
      <ListInput label={`수정 권장 버전 ${index+1}`} values={item.fixedVersions} onChange={values=>affected(index,{fixedVersions:values})}/>
      {draft.affected.length>1 && <button type="button" className="secondary" onClick={()=>{set("affected",draft.affected.filter((_,i)=>i!==index));setRowKeys(keys=>keys.filter((_,i)=>i!==index));}}>패키지 {index+1} 제거</button>}
    </fieldset>)}
    <button type="button" className="secondary" onClick={()=>{set("affected",[...draft.affected,emptyAffected()]);const key=nextRowKey.current++;setRowKeys(keys=>[...keys,key]);}}>영향 패키지 추가</button>
    <div className="button-row"><button className="primary" type="submit">사내 취약점 저장</button><button className="secondary" type="button" onClick={onCancel}>편집 취소</button></div>
  </fieldset></form>;
}

export function PrivateVulnerabilitiesPanel({canManage}:{canManage:boolean}) {
  const [result,setResult]=useState<{items:PrivateAdvisory[];total:number}>({items:[],total:0});
  const [page,setPage]=useState(1),[reload,setReload]=useState(0),[busy,setBusy]=useState(false);
  const [load,setLoad]=useState("loading"),[message,setMessage]=useState("");
  const [editor,setEditor]=useState<{record:PrivateAdvisory|null}|null>(null),[history,setHistory]=useState<unknown>(null);
  const editable=canManage&&!previewMode;
  useEffect(()=>{if(previewMode)return;let active=true;void fetchPrivateAdvisories(page).then(value=>{if(active){setResult(value);setLoad("ready");}}).catch(error=>{if(active){setMessage(messageOf(error));setLoad("error");}});return()=>{active=false;};},[page,reload]);
  function refresh() {setLoad("loading");setReload(value=>value+1);}
  async function save(body:PrivateAdvisoryInput) {if(!editable)return;setBusy(true);setMessage("");try{const record=editor?.record;const value=record ? await updatePrivateAdvisory(record,body) : await createPrivateAdvisory(body);setMessage(`${value.advisoryId} ${stateLabels[value.state]} · 리비전 ${value.revision} 저장. 재분석 접수 ${value.affectedRunsQueued ?? 0}개.`);setEditor(null);refresh();}catch(error){setMessage(messageOf(error));}finally{setBusy(false);}}
  async function changeState(record:PrivateAdvisory,state:PrivateAdvisoryInput["state"]) {setBusy(true);setMessage("");try{const {advisoryId,title,description,severity,cvssScore,cwes,aliases,references,affected}=record;const value=await updatePrivateAdvisory(record,{advisoryId,title,description,severity,cvssScore,cwes,aliases,references,affected,state});setMessage(`${value.advisoryId} ${stateLabels[value.state]} · 재분석 접수 ${value.affectedRunsQueued ?? 0}개.`);refresh();}catch(error){setMessage(messageOf(error));}finally{setBusy(false);}}
  async function showHistory(id:string) {setBusy(true);setHistory(null);try{setHistory(await fetchPrivateAdvisoryHistory(id));}catch(error){setMessage(messageOf(error));}finally{setBusy(false);}}
  return <section className="settings-panel workflow-panel" aria-label="사내 취약점 DB" id="settings-panel-private-vulnerabilities" role="tabpanel" aria-labelledby="settings-tab-private-vulnerabilities"><div className="settings-panel-heading"><h2>사내 취약점 DB</h2><div className="button-row"><button className="secondary" disabled={busy||previewMode} onClick={refresh}>사내 DB 새로고침</button>{editable&&<button className="primary" disabled={busy} onClick={()=>{setEditor({record:null});setMessage("");}}>사내 취약점 등록</button>}</div></div>
    <p>Grype DB 분석에 조직의 비공개 취약점 정보를 함께 적용합니다. 게시된 항목의 패키지·버전이 일치하면 내부 식별자도 분석 결과·정책·VEX 검토에 표시됩니다.</p>
    {message&&<p role="status">{message}</p>}{previewMode ? <p>샘플 모드 · 실제 사내 DB 조회·저장 안 함</p> : load!=="ready" ? <p>{load==="error" ? "사내 취약점을 조회하지 못했습니다. 새로고침으로 재시도하세요." : "사내 취약점 조회 중"}</p> : <><div className="table-scroll"><table><thead><tr><th>식별자 / 제목</th><th>상태 / 심각도</th><th>영향 패키지</th><th>리비전 / 수정 (서울)</th><th>작업</th></tr></thead><tbody>{result.items.map(item=><tr key={item.id}><td className="wrap"><strong>{item.advisoryId}</strong><br/>{item.title}</td><td>{stateLabels[item.state]} / {item.severity}<br/>CVSS {item.cvssScore ?? "미지정"}</td><td className="wrap">{item.affected.map((value,index)=><div key={index}>{value.purl}<small className="workflow-id">정확한 버전 {value.versions.join(", ") || "없음"} · 범위 {value.ranges.length}개 · 수정 {value.fixedVersions.join(", ") || "미지정"}</small></div>)}</td><td>v{item.revision}<br/>{formatSeoulDateTime(item.updatedAt)}</td><td><div className="button-row">{editable&&<><button className="secondary compact" disabled={busy} onClick={()=>setEditor({record:item})} aria-label={`${item.advisoryId} 편집`}>편집</button>{item.state!=="published"&&<button className="secondary compact" disabled={busy} onClick={()=>void changeState(item,"published")} aria-label={`${item.advisoryId} 게시`}>게시</button>}{item.state==="published"&&<button className="secondary compact" disabled={busy} onClick={()=>void changeState(item,"withdrawn")} aria-label={`${item.advisoryId} 철회`}>철회</button>}</>}<button className="secondary compact" disabled={busy} onClick={()=>void showHistory(item.id)} aria-label={`${item.advisoryId} 이력`}>이력</button></div></td></tr>)}{!result.items.length&&<tr><td colSpan={5}>등록된 사내 취약점이 없습니다.</td></tr>}</tbody></table></div><WorkflowPagination page={page} total={result.total} pageSize={20} label="사내 취약점" onPage={value=>{setPage(value);setLoad("loading");}}/></>}
    {editable&&editor&&<AdvisoryForm key={editor.record ? `${editor.record.id}-${editor.record.revision}` : "new"} record={editor.record} disabled={busy} onSave={save} onCancel={()=>setEditor(null)}/>}
    {history!==null&&<details open><summary>사내 취약점 변경 이력</summary><pre className="migration-report">{JSON.stringify(history,null,2)}</pre></details>}
  </section>;
}

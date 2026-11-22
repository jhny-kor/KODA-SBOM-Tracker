import { DetailPagination } from "./DetailPagination";
import { ResizableTable } from "./ResizableTable";
import { useEffect, useState } from "react";
import { fetchReanalysisCycles, fetchReanalysisSchedule, previewMode, queueReanalysisCycle, updateReanalysisSchedule } from "./api";
import { formatSeoulDateTime } from "./format";
import type { CatalogItem, ReanalysisCycle, ReanalysisSchedule } from "./types";

export function ScopeSelect({ label, items, value, onChange, disabled }: { label: string; items: CatalogItem[]; value: string[]; onChange: (ids: string[]) => void; disabled?: boolean }) {
  const options: CatalogItem[] = [...items, ...value.filter((id) => !items.some((item) => item.id === id)).map((id) => ({ id, name: id, slug: id }))];
  return <label>{label}<select multiple aria-label={label} value={value} disabled={disabled} onChange={(event) => onChange(Array.from(event.target.selectedOptions, (option) => option.value))}>{options.map((item) => <option key={item.id} value={item.id}>{item.name}{item.active === false ? " (비활성)" : ""}</option>)}</select><small>선택하지 않으면 전체. Ctrl/⌘ 키로 복수 선택·해제합니다.</small></label>;
}
const errorText = (error: unknown) => error instanceof Error ? error.message : "요청을 처리하지 못했습니다.";
export function ReanalysisSchedulePanel({ canManage, services = [], environments = [] }: { canManage: boolean; services?: CatalogItem[]; environments?: CatalogItem[] }) {
  const [schedule, setSchedule] = useState<ReanalysisSchedule | null>(null);
  const [cycles, setCycles] = useState<{items: ReanalysisCycle[]; total: number}>({items: [], total: 0});
  const [cycleLoad, setCycleLoad] = useState<"loading" | "ready" | "error">(previewMode ? "ready" : "loading");
  const [page, setPage] = useState(1);
  const [reload, setReload] = useState(0);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const editable = canManage && !previewMode;
  useEffect(() => {
    if (previewMode) return;
    let active = true;
    void fetchReanalysisSchedule().then((value) => { if (active) setSchedule(value); }).catch((error: unknown) => { if (active) setMessage(errorText(error)); });
    return () => { active = false; };
  }, [reload]);
  useEffect(() => {
    if (previewMode) return;
    let active = true;
    setCycleLoad("loading");
    void fetchReanalysisCycles(page).then((value) => { if (active) { setCycles(value); setCycleLoad("ready"); } }).catch((error: unknown) => { if (active) { setMessage(errorText(error)); setCycleLoad("error"); } });
    return () => { active = false; };
  }, [page, reload]);
  function change(patch: Partial<ReanalysisSchedule>) { setSchedule((value) => value && ({...value, ...patch})); }
  async function act(queue: boolean) {
    if (!editable || !schedule) return;
    setBusy(true); setMessage("");
    try {
      if (queue) { const cycle = await queueReanalysisCycle(); setMessage(`재분석 사이클 ${cycle.id}을 접수했습니다. 완료 상태와 실패 건수는 실행 이력에서 확인하세요.`); }
      else { setSchedule(await updateReanalysisSchedule(schedule)); setMessage("재분석 일정을 저장했습니다."); }
      setReload((value) => value + 1);
    } catch (error) { setMessage(errorText(error)); } finally { setBusy(false); }
  }
  return <section className="settings-panel workflow-panel tracker-view" role="tabpanel" id="settings-panel-reanalysis" aria-labelledby="settings-tab-reanalysis"><div className="settings-panel-heading"><div><h2>전체 분석 스케쥴</h2><p>보관하지 않은 기존 SBOM을 현재 Grype DB와 KODA 정책으로 다시 분석합니다. 원본 회차는 유지하고 새 분석 리비전을 추가합니다.</p></div><button className="secondary" onClick={() => setReload((value) => value + 1)} disabled={busy || previewMode}>상태 새로고침</button></div>
    {previewMode && <p className="preview-note">샘플 모드에서는 서버 일정과 실행 이력을 조회하거나 저장하지 않습니다.</p>}{message && <p className="form-message" role="status">{message}</p>}
    {schedule && <><form onSubmit={(event) => { event.preventDefault(); void act(false); }}><fieldset disabled={!editable || busy} className="workflow-form"><legend>자동 실행 설정 · v{schedule.version}</legend><label className="checkbox-label"><input type="checkbox" checked={schedule.enabled} onChange={(event) => change({enabled:event.target.checked})} />자동 재분석 사용</label><label>실행 간격 (분)<input aria-label="재분석 간격" type="number" min={5} max={10080} required value={schedule.intervalMinutes} onChange={(event) => change({intervalMinutes:Number(event.target.value)})} /></label><label className="checkbox-label"><input type="checkbox" checked={schedule.onDataUpdate} onChange={(event) => change({onDataUpdate:event.target.checked})} />취약점 데이터 활성화 시에도 실행</label><label className="checkbox-label"><input type="checkbox" checked={schedule.latestOnly} onChange={(event) => change({latestOnly:event.target.checked})} />각 릴리스의 최신 회차만 분석</label><ScopeSelect label="재분석 서비스 범위" items={services} value={schedule.serviceIds} onChange={(serviceIds) => change({serviceIds})} /><ScopeSelect label="재분석 환경 범위" items={environments} value={schedule.environmentIds} onChange={(environmentIds) => change({environmentIds})} />{canManage && <button className="primary" type="submit">재분석 일정 저장</button>}</fieldset></form><p>대상: {schedule.latestOnly ? "릴리스별 최신 회차" : "저장된 전체 회차"} · 다음 실행 (서울): {schedule.nextRunAt ? formatSeoulDateTime(schedule.nextRunAt) : "예약 없음"} · 최근 실행: {schedule.lastRunAt ? formatSeoulDateTime(schedule.lastRunAt) : "없음"}</p>{schedule.activeCycle && <p role="status">진행 중: {schedule.activeCycle.id} · 대기 {schedule.activeCycle.pendingCount} · 접수 {schedule.activeCycle.enqueuedCount} · 실패 {schedule.activeCycle.failedCount}</p>}{canManage && <button className="secondary" disabled={!editable || busy || Boolean(schedule.activeCycle)} onClick={() => void act(true)}>현재 저장된 범위 지금 재분석</button>}<p className="policy-metrics-note">수동 실행은 저장된 범위를 사용합니다. 이미 분석 중인 회차는 중복 접수하지 않고 같은 사이클에서 기다린 뒤 다시 접수합니다.</p></>}
    <h3>재분석 실행 이력</h3><div className="table-scroll" role="region" aria-label="재분석 실행 이력 가로 스크롤" tabIndex={0}><ResizableTable><thead><tr><th>접수 (서울)</th><th>이유 / 상태</th><th>전체</th><th>대기</th><th>접수</th><th>완료</th><th>실패</th><th>건너뜀</th></tr></thead><tbody>{cycleLoad === "ready" && cycles.items.map((cycle) => <tr key={cycle.id}><td>{formatSeoulDateTime(cycle.createdAt)}</td><td>{cycle.reason} / {cycle.state}<small className="workflow-id">{cycle.id}</small></td><td>{cycle.totalCount}</td><td>{cycle.pendingCount}</td><td>{cycle.enqueuedCount}</td><td>{cycle.completedCount}</td><td>{cycle.failedCount}</td><td>{cycle.skippedCount}</td></tr>)}{cycleLoad !== "ready" ? <tr><td colSpan={8}>{cycleLoad === "error" ? "실행 이력을 조회하지 못했습니다. 상태 새로고침으로 재시도하세요." : "실행 이력을 불러오는 중입니다."}</td></tr> : !cycles.items.length && <tr><td colSpan={8}>실행 이력이 없습니다.</td></tr>}</tbody></ResizableTable></div><DetailPagination page={page} total={cycles.total} pageSize={10} label="재분석 이력" onPage={setPage} /></section>;
}

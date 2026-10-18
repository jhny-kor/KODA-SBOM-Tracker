import { useEffect, useState } from "react";
import { applyMigration, fetchMetadataStatus, fetchMigrations, fetchRunMetadata, importMetadata, importVulnerabilityIntelligence, previewMode, refreshRunMetadata, stageMigration, stageRemoteMigration } from "./api";
import type { MetadataStatus, MigrationRecord, PackageMetadataRow, RunMetadataItem } from "./api";
import { WorkflowPagination } from "./ReanalysisSchedule";
import { formatSeoulDateTime } from "./format";

const messageOf = (error: unknown) => error instanceof Error ? error.message : "요청 처리에 실패했습니다.";
type LoadState = "loading" | "ready" | "error";
const metadataLabels: Record<string, string> = { fresh: "유효한 관측 캐시", stale: "유효기간 만료 · 과거 관측", pending: "수집 대기", error: "수집 실패", unsupported: "미지원 생태계", missing: "수집 전", invalid: "잘못된 패키지 식별자" };
const countLabels: Record<string, string> = { queued: "대기", running: "수집 중", completed: "수집 완료", failed: "실패", unsupported: "미지원", projects: "원본 프로젝트", policies: "원본 정책", convertedPolicies: "변환 정책", findings: "원본 발견", analyses: "원본 분석" };
const publicationLabel = (basis?:string) => basis === "artifact_last_modified" ? "저장소 파일 시각 (최초 출시일 미확정)" : basis === "go_module_revision_time" ? "소스 리비전 생성 시각" : basis?.includes("maven") ? "공식 저장소 색인 시각" : "저장소 공개 시각";
const migrationLabels = { staged: "적용 대기", blocked: "적용 차단", applied: "적용 완료" };
function MetadataEvidence({ metadata }: { metadata: PackageMetadataRow }) {
  return <><p>{metadata.sourceKind === "offline_import" ? "오프라인 반입 자료" : metadata.sourceKind === "public_registry" ? "공식 저장소 관측" : "출처 확인 필요"}</p><p>관측 (서울): {formatSeoulDateTime(metadata.fetchedAt)}<br />유효기한: {formatSeoulDateTime(metadata.expiresAt)}</p>{metadata.error && <p className="drawer-error">{metadata.error}</p>}<details><summary>메타데이터 근거</summary><p>최신 버전 선택: {metadata.latestSelection || "확인 안 됨"}{metadata.latestIsPrerelease ? " · 사전 출시 버전" : ""}</p>{metadata.registryLatestVersion && <p>저장소 latest 태그: {metadata.registryLatestVersion}{metadata.registryLatestIsPrerelease ? " · 사전 출시 버전" : ""}</p>}<p>현재 버전 시각 기준: {metadata.currentVersionPublishedAtBasis || metadata.publicationBasis || "확인 안 됨"}<br />최신 버전 시각 기준: {metadata.latestPublishedAtBasis || metadata.publicationBasis || "확인 안 됨"}<br />버전 거리 기준: {metadata.versionDistanceBasis || "확인 안 됨"}</p><p>필드 상태: {Object.entries(metadata.fieldStatus || {}).map(([name,state]) => `${name}: ${state}`).join(" · ") || "확인 안 됨"}</p>{metadata.sourceUrls?.map((source) => <p className="mono wrap" key={source}>{source}</p>)}{metadata.warnings?.map((warning,index) => <p key={index}>{warning}</p>)}</details></>;
}
export function PackageMetadataPanel({ canManage, runId }: { canManage: boolean; runId?: string }) {
  const [status, setStatus] = useState<MetadataStatus | null>(null);
  const [statusLoad, setStatusLoad] = useState<LoadState>("loading");
  const [result, setResult] = useState<{items: RunMetadataItem[];total:number}>({items:[],total:0});
  const [rowLoad, setRowLoad] = useState<LoadState>("loading");
  const [page, setPage] = useState(1), [exportPage, setExportPage] = useState(1), [reload, setReload] = useState(0);
  const [busy, setBusy] = useState(false), [message, setMessage] = useState("");
  const editable = canManage && !previewMode;
  useEffect(() => {
    if (previewMode) return;
    let active = true;
    void fetchMetadataStatus().then((value) => { if (active) { setStatus(value); setStatusLoad("ready"); } }).catch((error: unknown) => { if (active) { setStatusLoad("error"); setMessage(messageOf(error)); } });
    return () => { active = false; };
  }, [reload]);
  useEffect(() => {
    if (previewMode || !runId) return;
    let active = true;
    void fetchRunMetadata(runId,page).then((value) => { if (active) { setResult(value); setRowLoad("ready"); } }).catch((error: unknown) => { if (active) { setRowLoad("error"); setMessage(messageOf(error)); } });
    return () => { active = false; };
  }, [runId,page,reload]);
  function refresh() { setStatusLoad("loading"); setRowLoad("loading"); setReload((value) => value + 1); }
  async function act(file?: File, intelligence = false) {
    if (!editable) return;
    setBusy(true); setMessage("");
    try {
      if (file) {
        if (file.size > 4 * 1024 * 1024) throw new Error("메타데이터 가져오기 파일은 최대 4MiB입니다.");
        const value = await (intelligence ? importVulnerabilityIntelligence : importMetadata)(JSON.parse(await file.text()));
        setMessage(`${intelligence ? "EPSS" : "패키지 메타데이터"} 반입 ${value.imported}건 · 더 최신 캐시가 있어 건너뜀 ${value.skipped}건. 관측 시각과 출처는 반입 자료 기준입니다.`);
      } else if (runId) {
        const value = await refreshRunMetadata(runId);
        setMessage(`수집 접수 ${value.queued}건 · 캐시 ${value.cached}건 · 미지원 ${value.unsupported}건 · 식별자 오류 ${value.invalid ?? 0}건 · 후속 처리 ${value.deferred ?? 0}건. 수집 완료 후 새 분석에서 정책에 반영됩니다.`);
      }
      refresh();
    } catch (error) { setMessage(messageOf(error)); } finally { setBusy(false); }
  }
  return <section className="settings-panel workflow-panel" aria-label="패키지 메타데이터" id={runId ? undefined : "settings-panel-metadata"} role={runId ? undefined : "tabpanel"} aria-labelledby={runId ? undefined : "settings-tab-metadata"}>
    <div className="settings-panel-heading"><div><h2>패키지 최신 버전·출시일</h2><p>별도 수집기가 공식 저장소에서 관측한 캐시입니다. 최신 버전·출시일은 취약점 공개일이나 SBOM 생성일과 다릅니다. 원본 SBOM과 과거 분석은 바꾸지 않습니다.</p></div><button className="secondary" disabled={busy || previewMode} onClick={refresh}>수집 상태 새로고침</button></div>
    {message && <p role="status" className="form-message">{message}</p>}{previewMode ? <p className="preview-note">샘플 모드에서는 실제 캐시를 조회하거나 외부 저장소 수집·반입을 실행하지 않습니다.</p> : statusLoad === "error" ? <p>수집 상태를 조회하지 못했습니다. 새로고침으로 다시 확인하세요.</p> : statusLoad === "loading" ? <p>수집 상태 확인 중</p> : status && <><p>자동 수집 {status.enabled ? "활성" : "비활성"} · 캐시 유효기간 {status.ttlSeconds / 3600}시간 · 지원: {status.supportedEcosystems.join(", ")}</p><p>{Object.entries(status.counts).map(([name,count]) => `${countLabels[name] || name} ${count}건`).join(" · ")}</p></>}
    <p>출시 후 경과일은 현재 버전의 저장소 출시 시각으로 계산합니다. Go는 리비전 생성 시각, Maven은 공식 색인 시각을 구분해 표시합니다. 릴리스 개수 거리는 해당 생태계가 제공하는 정식 버전 목록의 개수이며 버전 문자열의 숫자 차이가 아닙니다. 저장소 파일 수정 시각만 있는 경우 최초 출시일로 확정하지 않습니다. 단위별 버전 거리는 처음 달라진 epoch·major·minor·patch의 절대 차이이며 이후 단위 -1은 미산출입니다. 확인 불가·만료 자료는 CEL 조건에 최신 관측값으로 제공하지 않습니다.</p>
    {runId && <><div className="table-scroll"><table className="metadata-table"><thead><tr><th>패키지 / 현재 버전</th><th>관측 상태</th><th>최신 버전</th><th>현재 버전 시각 (서울)</th><th>최신 버전 시각 (서울)</th><th>출시 후 경과일 / 버전 거리</th><th>관측 시각·출처 / 오류</th></tr></thead><tbody>
      {!previewMode && rowLoad === "ready" && result.items.map(({component,metadata},index) => <tr key={component.identityKey || `${component.purl}-${index}`}><td className="wrap">{component.name} / {component.version || "확인 안 됨"}<small className="workflow-id">{component.purl || "PURL 없음"}</small></td><td>{metadataLabels[metadata.status] || metadata.status}{metadata.status === "stale" && <p>과거 관측값이며 현재 최신 여부를 보증하지 않습니다.</p>}</td><td>{metadata.latestVersion || "확인 안 됨"}</td><td>{metadata.currentVersionPublishedAt ? <>{formatSeoulDateTime(metadata.currentVersionPublishedAt)}<small className="workflow-id">{publicationLabel(metadata.currentVersionPublishedAtBasis)}</small></> : "확인 안 됨"}</td><td>{metadata.latestPublishedAt ? <>{formatSeoulDateTime(metadata.latestPublishedAt)}<small className="workflow-id">{publicationLabel(metadata.latestPublishedAtBasis)}</small></> : "확인 안 됨"}</td><td>{typeof metadata.ageDays === "number" ? `${metadata.currentVersionPublishedAtBasis === "artifact_last_modified" ? "파일 시각 경과 " : metadata.currentVersionPublishedAtBasis === "go_module_revision_time" ? "리비전 시각 경과 " : ""}${metadata.ageDays}일` : "경과일 확인 안 됨"}<br />{typeof metadata.versionDistance === "number" ? `${metadata.versionDistance}개 버전` : "릴리스 개수 미제공"}{metadata.versionDistanceParts && <p>단위 거리: {Object.entries(metadata.versionDistanceParts).map(([key,value])=>`${key} ${value}`).join(" / ")}</p>}</td><td className="wrap"><MetadataEvidence metadata={metadata} /></td></tr>)}
      {previewMode ? <tr><td colSpan={7}>샘플 모드 · 실제 조회 안 함</td></tr> : rowLoad !== "ready" ? <tr><td colSpan={7}>{rowLoad === "error" ? "메타데이터 조회에 실패했습니다. 새로고침으로 재시도하세요." : "메타데이터를 불러오는 중입니다."}</td></tr> : !result.items.length && <tr><td colSpan={7}>이 회차에 메타데이터를 조회할 구성요소가 없습니다.</td></tr>}
    </tbody></table></div><WorkflowPagination page={page} total={result.total} label="패키지 메타데이터" onPage={(value) => { setRowLoad("loading"); setPage(value); }} />{canManage && <button className="secondary" disabled={!editable || busy} onClick={() => void act()}>이 회차 메타데이터 수집 접수</button>}</>}
    {!runId && canManage && <div className="workflow-form"><div><label>캐시 내보내기 페이지<input aria-label="캐시 내보내기 페이지" type="number" min={1} step={1} value={exportPage} disabled={!editable || busy} onChange={(event) => setExportPage(Math.max(1,Math.floor(Number(event.target.value) || 1)))} /></label>{editable && <a className="secondary" href={`/api/v1/package-metadata/export?page=${exportPage}&size=1000`}>캐시 {exportPage}페이지 내려받기 (최대 1,000개)</a>}<p>캐시는 페이지별로 내려받습니다. 파일의 total·page를 확인하고 필요한 모든 페이지를 각각 반입하세요.</p></div><label>패키지 캐시 가져오기<input aria-label="패키지 캐시 가져오기" type="file" accept=".json,application/json" disabled={!editable || busy} onChange={(event) => { const file = event.target.files?.[0]; if (file) void act(file); event.target.value = ""; }} /></label></div>}
    {!runId && canManage && <details><summary>EPSS 오프라인 데이터 반입</summary><p>관측한 CVE의 EPSS 점수는 별도 수집기가 공식 공급원에서 수집합니다. 24시간 캐시와 원본 기준일을 함께 검사하며, 오래되거나 없는 점수는 0점으로 대체하지 않습니다. CWE는 Grype·반입한 NVD·원본 증거에서 읽습니다.</p>{editable && <a className="secondary" href={`/api/v1/vulnerability-intelligence/export?page=${exportPage}&size=1000`}>EPSS {exportPage}페이지 내려받기 (최대 1,000개)</a>}<label>EPSS 캐시 가져오기<input type="file" accept=".json,application/json" disabled={!editable||busy} onChange={event=>{const file=event.target.files?.[0];if(file)void act(file,true);event.target.value="";}}/></label></details>}
  </section>;
}

export function LegacyMigrationPanel({ canApply = false }: { canApply?: boolean }) {
  const [history, setHistory] = useState<{items:MigrationRecord[];total:number}>({items:[],total:0});
  const [loadState, setLoadState] = useState<LoadState>("loading");
  const [record, setRecord] = useState<MigrationRecord | null>(null);
  const [page, setPage] = useState(1), [reload, setReload] = useState(0);
  const [url, setUrl] = useState(""), [apiKey, setApiKey] = useState("");
  const [trust, setTrust] = useState(false), [busy, setBusy] = useState(false), [message, setMessage] = useState("");
  useEffect(() => {
    if (previewMode) return;
    let active = true;
    void fetchMigrations(page).then((value) => { if (active) { setHistory(value); setLoadState("ready"); } }).catch((error: unknown) => { if (active) { setLoadState("error"); setMessage(messageOf(error)); } });
    return () => { active = false; };
  }, [page,reload]);
  function reloadHistory() { setLoadState("loading"); setReload((value) => value + 1); }
  async function stage(file?: File) {
    if (previewMode) return;
    setBusy(true); setMessage(""); setTrust(false);
    try {
      if (file && file.size > 64 * 1024 * 1024) throw new Error("이관 파일은 최대 64MiB입니다.");
      const value = file ? await stageMigration(JSON.parse(await file.text())) : await stageRemoteMigration(url,apiKey);
      setRecord(value); setPage(1); reloadHistory();
      setMessage(value.state === "applied" ? "이미 적용된 원본 번들입니다. 기존 적용 결과를 표시합니다." : value.state === "blocked" ? "변환 검사에서 적용 차단 사유가 발견되었습니다. 원본과 차단 근거를 확인하세요." : "원본 수집과 변환 검사를 완료했습니다. 적용 범위와 근거를 검토하세요.");
    } catch (error) { setMessage(messageOf(error)); } finally { setApiKey(""); setBusy(false); }
  }
  async function apply() {
    if (!record || !canApply || previewMode || record.state !== "staged" || !record.report.canApply) return;
    setBusy(true); setMessage("");
    try {
      const value = await applyMigration(record,record.report.currentPolicyVersion,trust);
      setRecord(value); reloadHistory();
      if (value.state !== "applied") throw new Error("서버가 적용 완료 상태를 반환하지 않았습니다. 검사 결과를 다시 확인하세요.");
      setMessage("이관 적용을 완료했습니다. 아래 실제 생성 결과와 보존된 원본을 확인하세요. 현재 Grype DB 검증은 새 분석이 필요합니다.");
    } catch (error) { setMessage(messageOf(error)); } finally { setBusy(false); }
  }
  return <section className="settings-panel workflow-panel" role="tabpanel" id="settings-panel-migration" aria-labelledby="settings-tab-migration"><div className="settings-panel-heading"><h2>기존 시스템 데이터·정책 이관</h2><button className="secondary" disabled={busy || previewMode} onClick={reloadHistory}>이관 이력 새로고침</button></div><p>원본 수집 → 변환 검사 → 관리자 적용 순서입니다. 변환할 수 없는 조건은 적용을 차단합니다. 원본 ID로 중복 생성을 방지하며, 원본 분석은 과거 증거로 보존합니다.</p>{previewMode && <p className="preview-note">샘플 모드에서는 실제 이관·원본 서버 조회를 실행하지 않습니다.</p>}{message && <p role="status" className="form-message">{message}</p>}
    <fieldset className="workflow-form" disabled={busy || previewMode}><legend>원본 서버 수집 또는 번들 가져오기 (최대 64MiB)</legend><label>원본 서버 주소<input aria-label="이관 원본 주소" type="url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://legacy.internal" /></label><label>원본 관리자 API 키<input aria-label="이관 원본 API 키" type="password" autoComplete="off" value={apiKey} onChange={(event) => setApiKey(event.target.value)} /></label><p>API 키는 이 요청에서만 사용하며 브라우저 저장소에 보관하지 않습니다. 성공·실패 후 입력값을 지웁니다.</p><button type="button" className="secondary" disabled={!url.trim() || !apiKey.trim()} onClick={() => void stage()}>원본 수집·변환 검사</button><label>또는 내보내기 번들 가져오기<input aria-label="이관 번들 파일" type="file" accept=".json,application/json" onChange={(event) => { const file = event.target.files?.[0]; if (file) void stage(file); event.target.value = ""; }} /></label></fieldset>
    {record && <><h3>검사 결과 · {migrationLabels[record.state]}</h3><p>이관 ID <span className="mono wrap">{record.id}</span> · 원본 {record.sourceId || "확인 안 됨"}</p><p>검사 당시 KODA 정책 v{record.report.currentPolicyVersion} · {Object.entries(record.report.counts || {}).map(([name,count]) => `${countLabels[name] || name} ${count}건`).join(" · ")}</p><p>적용 가능: {record.report.canApply ? "예" : "아니오"}</p>{record.report.blockers?.map((item,index) => <p role="alert" className="drawer-error" key={index}>{item.reason}</p>)}{record.report.warnings?.map((item,index) => <p key={index}>{item.reason}</p>)}<details><summary>원본 범위·정책 변환 근거 보기</summary><pre className="migration-report">{JSON.stringify(record.report,null,2)}</pre></details>
      {record.state === "applied" && record.result && <div className="table-frame workflow-review"><h3>실제 적용 결과</h3><p>회차 {record.result.runIds?.length ?? 0}개 · 분석 리비전 {record.result.analysisRevisionsCreated ?? 0}개 · 검토 요청 {record.result.reviewsCreated ?? 0}개 · 정책 v{record.result.policyVersion ?? "확인 안 됨"}</p><p>원본 검토: {record.result.trustSourceReviews ? "관리자가 원본 결정을 신뢰해 승인 상태로 이관" : "미승인 검토로 이관 · 별도 승인 필요"}</p><p>원본 분석은 현재 Grype DB로 검증한 KODA 분석이 아닙니다. 새 분석 리비전 또는 재분석 사이클을 실행해 현재 기준으로 검증하세요.</p>{record.appliedAt && <p>적용 (서울): {formatSeoulDateTime(record.appliedAt)} · {record.result.actor}</p>}</div>}
      {record.state !== "applied" && <><p>기본값은 원본 검토를 미승인 요청으로 가져옵니다. 원본 결정을 신뢰해 승인 상태로 가져오려면 관리자가 아래 항목을 명시적으로 선택해야 합니다.</p><label className="checkbox-label"><input aria-label="원본 검토 신뢰 승인" type="checkbox" disabled={busy || previewMode || !canApply || !record.report.canApply} checked={trust} onChange={(event) => setTrust(event.target.checked)} />원본의 검토 결정을 신뢰해 승인 상태로 이관 (관리자 책임·감사 기록)</label>{canApply ? <button type="button" className="primary" disabled={busy || previewMode || !record.report.canApply || record.state !== "staged"} onClick={() => void apply()}>검사된 이관 적용</button> : <p>검사된 이관 적용은 이관 권한이 있는 관리자만 실행할 수 있습니다.</p>}<p>정책이 변경되어 적용이 거절되면 같은 원본 번들을 다시 검사하고 변경된 변환 근거를 검토하세요.</p></>}
      {!previewMode && <a className="secondary" href={`/api/v1/legacy-migrations/${encodeURIComponent(record.id)}/bundle`}>보존된 원본 번들 내려받기</a>}
    </>}
    <h3>이관 이력</h3><div className="table-scroll"><table><thead><tr><th>검사 (서울)</th><th>원본 / 이관 ID</th><th>상태</th><th>작업</th></tr></thead><tbody>{!previewMode && loadState === "ready" && history.items.map((item) => <tr key={item.id}><td>{formatSeoulDateTime(item.createdAt)}</td><td className="wrap">{item.sourceId || "-"}<small className="workflow-id">{item.id}</small></td><td>{migrationLabels[item.state]}</td><td><button className="secondary compact" type="button" disabled={busy} aria-label={`이관 ${item.id} 검사 결과 보기`} onClick={() => { setRecord(item); setTrust(false); setMessage(""); }}>검사 결과 보기</button></td></tr>)}{previewMode ? <tr><td colSpan={4}>샘플 모드 · 실제 조회 안 함</td></tr> : loadState !== "ready" ? <tr><td colSpan={4}>{loadState === "error" ? "이관 이력 조회에 실패했습니다. 새로고침으로 재시도하세요." : "이관 이력을 불러오는 중입니다."}</td></tr> : !history.items.length && <tr><td colSpan={4}>이관 이력이 없습니다.</td></tr>}</tbody></table></div><WorkflowPagination page={page} total={history.total} pageSize={20} label="이관 이력" onPage={(value) => { setLoadState("loading"); setPage(value); }} />
  </section>;
}

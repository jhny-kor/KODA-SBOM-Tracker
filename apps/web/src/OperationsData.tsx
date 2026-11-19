import { ResizableTable } from "./ResizableTable";
import { useEffect, useState } from "react";
import { fetchMetadataStatus, fetchRunMetadata, previewMode, refreshRunMetadata } from "./api";
import type { MetadataStatus, PackageMetadataRow, RunMetadataItem } from "./api";
import { WorkflowPagination } from "./ReanalysisSchedule";
import { formatSeoulDateTime } from "./format";
import { ScrollingText } from "./ScrollingText";

const messageOf = (error: unknown) => error instanceof Error ? error.message : "요청 처리에 실패했습니다.";
type LoadState = "loading" | "ready" | "error";
const metadataLabels: Record<string, string> = { fresh: "유효한 관측 캐시", stale: "유효기간 만료 · 과거 관측", pending: "수집 대기", error: "수집 실패", unsupported: "미지원 생태계", missing: "수집 전", invalid: "잘못된 패키지 식별자" };
const countLabels: Record<string, string> = { queued: "대기", running: "수집 중", completed: "수집 완료", failed: "실패", unsupported: "미지원", projects: "원본 프로젝트", policies: "원본 정책", convertedPolicies: "변환 정책", findings: "원본 발견", analyses: "원본 분석" };
const publicationLabel = (basis?:string) => basis === "artifact_last_modified" ? "저장소 파일 시각 (최초 출시일 미확정)" : basis === "go_module_revision_time" ? "소스 리비전 생성 시각" : basis?.includes("maven") ? "공식 저장소 색인 시각" : "저장소 공개 시각";
function MetadataEvidence({ metadata }: { metadata: PackageMetadataRow }) {
  return <><p>{metadata.sourceKind === "offline_import" ? "오프라인 반입 자료" : metadata.sourceKind === "public_registry" ? "공식 저장소 관측" : "출처 확인 필요"}</p><p>관측 : {formatSeoulDateTime(metadata.fetchedAt)}<br />유효기한: {formatSeoulDateTime(metadata.expiresAt)}</p>{metadata.error && <p className="drawer-error">{metadata.error}</p>}<details><summary>메타데이터 근거</summary><p>최신 버전 선택: {metadata.latestSelection || "확인 안 됨"}{metadata.latestIsPrerelease ? " · 사전 출시 버전" : ""}</p>{metadata.registryLatestVersion && <p>저장소 latest 태그: {metadata.registryLatestVersion}{metadata.registryLatestIsPrerelease ? " · 사전 출시 버전" : ""}</p>}<p>현재 버전 시각 기준: {metadata.currentVersionPublishedAtBasis || metadata.publicationBasis || "확인 안 됨"}<br />최신 버전 시각 기준: {metadata.latestPublishedAtBasis || metadata.publicationBasis || "확인 안 됨"}<br />버전 거리 기준: {metadata.versionDistanceBasis || "확인 안 됨"}</p><p>필드 상태: {Object.entries(metadata.fieldStatus || {}).map(([name,state]) => `${name}: ${state}`).join(" · ") || "확인 안 됨"}</p>{metadata.sourceUrls?.map((source) => <p className="mono wrap" key={source}>{source}</p>)}{metadata.warnings?.map((warning,index) => <p key={index}>{warning}</p>)}</details></>;
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
  async function collectRunMetadata() {
    if (!editable || !runId) return;
    setBusy(true); setMessage("");
    try {
      const value = await refreshRunMetadata(runId);
      setMessage(`수집 접수 ${value.queued}건 · 캐시 ${value.cached}건 · 미지원 ${value.unsupported}건 · 식별자 오류 ${value.invalid ?? 0}건 · 후속 처리 ${value.deferred ?? 0}건. 수집 완료 후 새 분석에서 정책에 반영됩니다.`);
      refresh();
    } catch (error) { setMessage(messageOf(error)); } finally { setBusy(false); }
  }
  return <section className="settings-panel workflow-panel tracker-view" aria-label="패키지 메타데이터" id={runId ? undefined : "settings-panel-metadata"} role="region">
    <div className="settings-panel-heading"><div><h2>패키지 최신 버전·출시일</h2><p>별도 수집기가 공식 저장소에서 관측한 캐시입니다. 최신 버전·출시일은 취약점 공개일이나 SBOM 생성일과 다릅니다. 원본 SBOM과 과거 분석은 바꾸지 않습니다.</p></div><button className="secondary" disabled={busy || previewMode} onClick={refresh}>수집 상태 새로고침</button></div>
    {message && <p role="status" className="form-message">{message}</p>}{previewMode ? <p className="preview-note">샘플 모드에서는 실제 캐시를 조회하거나 외부 저장소 수집·반입을 실행하지 않습니다.</p> : statusLoad === "error" ? <p>수집 상태를 조회하지 못했습니다. 새로고침으로 다시 확인하세요.</p> : statusLoad === "loading" ? <p>수집 상태 확인 중</p> : status && <><p>자동 수집 {status.enabled ? "활성" : "비활성"} · 캐시 유효기간 {status.ttlSeconds / 3600}시간 · 지원: {status.supportedEcosystems.join(", ")}</p><p>{Object.entries(status.counts).map(([name,count]) => `${countLabels[name] || name} ${count}건`).join(" · ")}</p></>}
    <p>출시 후 경과일은 현재 버전의 저장소 출시 시각으로 계산합니다. Go는 리비전 생성 시각, Maven은 공식 색인 시각을 구분해 표시합니다. 릴리스 개수 거리는 해당 생태계가 제공하는 정식 버전 목록의 개수이며 버전 문자열의 숫자 차이가 아닙니다. 저장소 파일 수정 시각만 있는 경우 최초 출시일로 확정하지 않습니다. 단위별 버전 거리는 처음 달라진 epoch·major·minor·patch의 절대 차이이며 이후 단위 -1은 미산출입니다. 확인 불가·만료 자료는 CEL 조건에 최신 관측값으로 제공하지 않습니다.</p>
    {runId && <><div className="table-scroll"><ResizableTable className="metadata-table package-metadata-flow-table"><thead><tr><th>패키지 / 현재 버전</th><th>관측 상태</th><th>최신 버전</th><th>현재 버전 시각</th><th>최신 버전 시각</th><th>출시 후 경과일 / 버전 거리</th><th>관측 시각·출처 / 오류</th></tr></thead><tbody>
      {!previewMode && rowLoad === "ready" && result.items.map(({component,metadata},index) => <tr key={component.identityKey || `${component.purl}-${index}`}><td><ScrollingText>{`${component.name} / ${component.version || "확인 안 됨"}`}</ScrollingText><small className="workflow-id"><ScrollingText>{component.purl || "PURL 없음"}</ScrollingText></small></td><td>{metadataLabels[metadata.status] || metadata.status}{metadata.status === "stale" && <p>과거 관측값이며 현재 최신 여부를 보증하지 않습니다.</p>}</td><td><ScrollingText>{metadata.latestVersion || "확인 안 됨"}</ScrollingText></td><td>{metadata.currentVersionPublishedAt ? <>{formatSeoulDateTime(metadata.currentVersionPublishedAt)}<small className="workflow-id">{publicationLabel(metadata.currentVersionPublishedAtBasis)}</small></> : "확인 안 됨"}</td><td>{metadata.latestPublishedAt ? <>{formatSeoulDateTime(metadata.latestPublishedAt)}<small className="workflow-id">{publicationLabel(metadata.latestPublishedAtBasis)}</small></> : "확인 안 됨"}</td><td>{typeof metadata.ageDays === "number" ? `${metadata.currentVersionPublishedAtBasis === "artifact_last_modified" ? "파일 시각 경과 " : metadata.currentVersionPublishedAtBasis === "go_module_revision_time" ? "리비전 시각 경과 " : ""}${metadata.ageDays}일` : "경과일 확인 안 됨"}<br />{typeof metadata.versionDistance === "number" ? `${metadata.versionDistance}개 버전` : "릴리스 개수 미제공"}{metadata.versionDistanceParts && <p>단위 거리: {Object.entries(metadata.versionDistanceParts).map(([key,value])=>`${key} ${value}`).join(" / ")}</p>}</td><td className="wrap"><MetadataEvidence metadata={metadata} /></td></tr>)}
      {previewMode ? <tr><td colSpan={7}>샘플 모드 · 실제 조회 안 함</td></tr> : rowLoad !== "ready" ? <tr><td colSpan={7}>{rowLoad === "error" ? "메타데이터 조회에 실패했습니다. 새로고침으로 재시도하세요." : "메타데이터를 불러오는 중입니다."}</td></tr> : !result.items.length && <tr><td colSpan={7}>이 회차에 메타데이터를 조회할 구성요소가 없습니다.</td></tr>}
    </tbody></ResizableTable></div><WorkflowPagination page={page} total={result.total} label="패키지 메타데이터" onPage={(value) => { setRowLoad("loading"); setPage(value); }} />{canManage && <button className="secondary" disabled={!editable || busy} onClick={() => void collectRunMetadata()}>이 회차 메타데이터 수집 접수</button>}</>}
    <p>자료 반입은 설정 → 취약점 데이터 → 공개 참조 자료에서 서명된 통합 압축파일로 진행합니다. 이 영역은 저장소 관측 캐시이며, 통합 반입한 참조 자료의 현황과 구분됩니다.</p>
    {!runId && canManage && <div className="workflow-form metadata-export-form">
      <label>캐시 내보내기 페이지<input aria-label="캐시 내보내기 페이지" type="number" min={1} step={1} value={exportPage} disabled={!editable || busy} onChange={(event) => setExportPage(Math.max(1,Math.floor(Number(event.target.value) || 1)))} /></label>
      {editable && <a className="secondary" href={`/api/v1/package-metadata/export?page=${exportPage}&size=1000`}>캐시 {exportPage}페이지 내려받기 (최대 1,000개)</a>}
      <p>저장된 캐시는 페이지별로 내려받아 확인할 수 있습니다. 관측 시각과 유효기간은 원본 기록을 따릅니다.</p>
    </div>}
    {!runId && canManage && <details><summary>EPSS 관측 캐시 내보내기</summary><p>저장된 EPSS 관측값을 확인하기 위한 내보내기입니다. 새 자료 반입은 서명된 통합 압축파일을 사용합니다.</p>{editable && <a className="secondary" href={`/api/v1/vulnerability-intelligence/export?page=${exportPage}&size=1000`}>EPSS {exportPage}페이지 내려받기 (최대 1,000개)</a>}</details>}
  </section>;
}

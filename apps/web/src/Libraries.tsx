import { ResizableTable } from "./ResizableTable";
import { useDeferredValue, useEffect, useState } from "react";
import { demoMode, standaloneMode } from "./api";
import { formatSeoulDateTime } from "./format";
import { Icon } from "./icons";
import { FlowSelect } from "./ScrollingSelect";
import { ScrollingText } from "./ScrollingText";
import { fetchLibraries, fetchLibrary, type LibraryDetail, type LibraryPage } from "./library-api";
import "./libraries.css";
const eventLabels: Record<string, string> = { first_seen: "최초 관측", version_changed: "버전 변경", removed: "제거 관측", reappeared: "재등장", observed: "재확인" };
const severityLabels: Record<string, string> = { critical: "치명", high: "높음", medium: "중간", low: "낮음", unknown: "미확인", info: "정보" };
const pageSizes = [10, 25, 50, 100];
const empty: LibraryPage = { items: [], total: 0, page: 1, size: pageSizes[0], basis: "", filters: { environments: [], ecosystems: [] } };
const errorMessage = (error: unknown) => error instanceof Error ? error.message : "라이브러리를 조회하지 못했습니다.";
function Pagination({ page, total, size, onPage, onPageSize, label }: {
    page: number;
    total: number;
    size: number;
    onPage: (page: number) => void;
    onPageSize?: (size: number) => void;
    label: string;
}) {
    const pages = Math.max(1, Math.ceil(total / size));
    return <div className="library-pagination">
      <span>전체 {total.toLocaleString()}건 · {page}/{pages}페이지</span>
      <div>
        {onPageSize && <select aria-label={`${label} 페이지당 행 수`} value={size}
          onChange={event => onPageSize(Number(event.target.value))}>
          {pageSizes.map(value => <option key={value} value={value}>{value}개씩 보기</option>)}
        </select>}
        <button className="secondary" disabled={page <= 1} aria-label={`${label} 이전 페이지`} onClick={() => onPage(page - 1)}>이전</button>
        <button className="secondary" disabled={page >= pages} aria-label={`${label} 다음 페이지`} onClick={() => onPage(page + 1)}>다음</button>
      </div>
    </div>;
}
export default function LibrariesPage({ onOpenRun, initialQuery = "" }: {
    onOpenRun?: (runId: string) => void;
    initialQuery?: string;
}) {
    const [query, setQuery] = useState(initialQuery), [environment, setEnvironment] = useState(""), [ecosystem, setEcosystem] = useState(""), [version, setVersion] = useState("");
    const [pageSize, setPageSize] = useState(pageSizes[0]);
    const [page, setPage] = useState(1), [result, setResult] = useState<LibraryPage>(empty), [selected, setSelected] = useState("");
    const [detail, setDetail] = useState<LibraryDetail | null>(null), [tab, setTab] = useState("inventory"), [historyPage, setHistoryPage] = useState(1);
    const [listLoad, setListLoad] = useState({ key: "", error: "" });
    const [detailLoad, setDetailLoad] = useState({ key: "", error: "" });
    const [sourceQuery, setSourceQuery] = useState(initialQuery);
    if (sourceQuery !== initialQuery) {
        setSourceQuery(initialQuery);
        setQuery(initialQuery);
        setPage(1);
    }
    const deferredQuery = useDeferredValue(query.trim()), deferredVersion = useDeferredValue(version.trim());
    const listKey = JSON.stringify([deferredQuery, deferredVersion, environment, ecosystem, page, pageSize]);
    const detailKey = JSON.stringify([selected, environment, historyPage]);
    const listState = listLoad.key !== listKey ? "loading" : listLoad.error ? "error" : "ready";
    const detailState = !selected ? "idle" : detailLoad.key !== detailKey ? "loading" : detailLoad.error ? "error" : "ready";
    const listError = listLoad.error, detailError = detailLoad.error;
    useEffect(() => {
        let active = true;
        void fetchLibraries({ q: deferredQuery, environmentId: environment, ecosystem, version: deferredVersion, page, size: pageSize }).then(value => {
            if (!active)
                return;
            setResult(value);
            setListLoad({ key: listKey, error: "" });
            setSelected(current => value.items.some(item => item.key === current) ? current : value.items[0]?.key || "");
            setHistoryPage(1);
            setTab("inventory");
        }).catch(error => { if (active) {
            setListLoad({ key: listKey, error: errorMessage(error) });
            setSelected("");
        } });
        return () => { active = false; };
    }, [deferredQuery, deferredVersion, environment, ecosystem, page, pageSize, listKey]);
    useEffect(() => {
        if (!selected)
            return;
        let active = true;
        void fetchLibrary(selected, environment, historyPage).then(value => {
            if (active) {
                setDetail(value);
                setDetailLoad({ key: detailKey, error: "" });
            }
        }).catch(error => { if (active) {
            setDetailLoad({ key: detailKey, error: errorMessage(error) });
        } });
        return () => { active = false; };
    }, [selected, environment, historyPage, detailKey]);
    function selectLibrary(key: string) { setSelected(key); setHistoryPage(1); setTab("inventory"); }
    function openRun(runId: string) { if (onOpenRun)
        onOpenRun(runId);
    else
        window.location.assign(`/?page=runs&runId=${encodeURIComponent(runId)}`); }
    return <section className="page libraries-page">
    <div className="page-heading"><div><h1>라이브러리</h1><p>서비스·환경·릴리스별 사용 현황과 개별 라이브러리의 변경 이력을 확인합니다.</p></div>{demoMode && <span className="library-sample">샘플 모드 · 가상 데이터</span>}</div>
    <form className="library-filters" onSubmit={event => event.preventDefault()}>
      <label className="library-query"><span>라이브러리 검색</span><div><Icon name="search"/><input aria-label="라이브러리 검색" placeholder="라이브러리명 또는 PURL 검색" value={query} onChange={event => { setQuery(event.target.value); setPage(1); }}/></div></label>
      <label>환경<FlowSelect value={environment} aria-label="라이브러리 환경" onChange={event => { setEnvironment(event.target.value); setPage(1); }}><option value="">전체</option>{result.filters.environments.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</FlowSelect></label>
      <label>생태계<FlowSelect value={ecosystem} aria-label="라이브러리 생태계" onChange={event => { setEcosystem(event.target.value); setPage(1); }}><option value="">전체</option>{result.filters.ecosystems.map(item => <option key={item} value={item}>{item === "unidentified" ? "식별 확인 필요" : item}</option>)}</FlowSelect></label>
      <label>라이브러리 버전<input aria-label="라이브러리 버전" placeholder="정확한 버전" value={version} onChange={event => { setVersion(event.target.value); setPage(1); }}/></label>
      <button type="button" className="secondary" onClick={() => { setQuery(""); setEnvironment(""); setEcosystem(""); setVersion(""); setPage(1); }}>초기화</button>
    </form>
    <p className="library-notice"><Icon name="guide"/>최신 완료 SBOM 관측 기준입니다. 실제 서버의 현재 배포 상태를 의미하지 않으며, 보관 회차는 과거 이력에만 포함합니다.</p>
    {standaloneMode && <p className="preview-note">로컬 단독 미리보기에서는 서버에 보관된 전체 라이브러리 이력을 조회할 수 없습니다.</p>}
    <div className="library-layout">
      <div className="library-catalog"><div className="table-frame table-scroll"><ResizableTable aria-label="라이브러리 목록"><thead><tr><th>라이브러리</th><th>최신 관측 버전</th><th>서비스</th><th>최근 관측</th></tr></thead><tbody>
        {listState === "ready" && result.items.map(item => <tr key={item.key} className={selected === item.key ? "selected" : ""} onClick={() => selectLibrary(item.key)}><td><button type="button" className="library-name" aria-pressed={selected === item.key}><ScrollingText focusable={false}>{item.name}</ScrollingText></button><small><ScrollingText>{item.ecosystem}</ScrollingText></small></td><td><ScrollingText>{item.currentVersions.length ? item.currentVersions.map(value => value || "버전 미기재").join(" · ") : "현재 관측 없음"}</ScrollingText></td><td>{item.currentServiceCount}개<small>과거 포함 {item.serviceCount}개</small></td><td>{formatSeoulDateTime(item.lastObservedAt).slice(0, 10)}</td></tr>)}
        {listState !== "ready" ? <tr><td colSpan={4} role={listState === "error" ? "alert" : "status"}>{listState === "error" ? listError : "라이브러리를 불러오는 중입니다…"}</td></tr> : !result.items.length && <tr><td colSpan={4}>조건에 맞는 라이브러리가 없습니다.</td></tr>}
      </tbody></ResizableTable></div><Pagination label="라이브러리 목록" page={page} total={result.total} size={pageSize} onPage={setPage} onPageSize={size => { setPageSize(size); setPage(1); }}/></div>
      <div className="library-detail" aria-label="라이브러리 상세" aria-busy={detailState === "loading"}>
        {detailState === "loading" ? <p role="status">상세 관측 이력을 불러오는 중입니다…</p> : detailState === "error" ? <p role="alert">{detailError}</p> : selected && detail ? <>
          <h2><ScrollingText>{detail.name}</ScrollingText></h2><p className="library-coordinate"><ScrollingText>{detail.coordinate}</ScrollingText></p>
          <div className="tabs" role="tablist" aria-label="라이브러리 상세 탭">{[["inventory", "보유 환경·릴리스"], ["history", "변경 이력"], ["vulnerabilities", "연관 취약점"]].map(([id, label]) => <button type="button" role="tab" id={`library-tab-${id}`} aria-controls={`library-panel-${id}`} aria-selected={tab === id} key={id} className={tab === id ? "active" : ""} onClick={() => setTab(id)}>{label}</button>)}</div>
          <div id={`library-panel-${tab}`} role="tabpanel" aria-labelledby={`library-tab-${tab}`}>
          {tab === "inventory" && <><h3>서비스·환경별 최신 관측</h3><div className="table-scroll"><ResizableTable aria-label="라이브러리 보유 환경"><thead><tr><th>서비스 / 환경</th><th>서비스 릴리스</th><th>라이브러리 버전</th><th>근거</th></tr></thead><tbody>{detail.observations.map((item, index) => <tr key={`${item.runId}-${item.bomRef}-${index}`}><td><ScrollingText>{item.service.name}</ScrollingText><small><ScrollingText>{item.environment.name}</ScrollingText></small></td><td><ScrollingText>{item.releaseVersion}</ScrollingText></td><td><ScrollingText>{item.libraryVersion || "미기재"}</ScrollingText>{item.identityStatus !== "identified" && <small>식별 근거 확인 필요</small>}</td><td><button type="button" className="library-link" onClick={() => openRun(item.runId)}>SBOM {item.roundNumber}차</button><small>{formatSeoulDateTime(item.at)}</small></td></tr>)}{!detail.observations.length && <tr><td colSpan={4}>최신 완료 SBOM에서 관측되지 않았습니다. 과거 이력은 변경 이력에서 확인하세요.</td></tr>}</tbody></ResizableTable></div><p className="library-footnote">라이브러리 버전과 서비스 릴리스를 구분합니다. 과거 관측 구성요소 {detail.observationsTotal.toLocaleString()}개</p></>}
          {tab === "history" && <><ol className="library-timeline">{detail.history.items.map((item, index) => <li key={`${item.runId}-${item.kind}-${index}`}><div className="library-event-time">{formatSeoulDateTime(item.at)}</div><div><span className={`library-event-label ${item.kind}`}>{eventLabels[item.kind] || item.kind}</span><strong><ScrollingText>{item.kind === "version_changed" ? `${item.previousVersions.map(value => value || "버전 미기재").join(" · ")} → ${item.versions.map(value => value || "버전 미기재").join(" · ")}` : item.versions.map(value => value || "버전 미기재").join(" · ") || "구성요소 부재 확인"}</ScrollingText></strong><p><ScrollingText>{`${item.service.name} · ${item.environment.name}`}</ScrollingText><ScrollingText>{`서비스 릴리스 ${item.releaseVersion} · SBOM ${item.roundNumber}차`}</ScrollingText></p>{!item.reliable && <p>보관 또는 미완료 회차의 과거 관측입니다.</p>}<button type="button" className="library-link" onClick={() => openRun(item.runId)}>근거 SBOM 보기</button>{item.previousRunId && <a className="library-link" href={`/?page=compare&baseRunId=${encodeURIComponent(item.previousRunId)}&targetRunId=${encodeURIComponent(item.runId)}`}>회차 비교</a>}</div></li>)}</ol>{!detail.history.total && <p>보관된 변경 이력이 없습니다.</p>}<Pagination label="라이브러리 변경 이력" page={historyPage} total={detail.history.total} size={20} onPage={setHistoryPage}/><p className="library-footnote">미수집 기간의 변경은 알 수 없습니다. 제거는 전체 구성요소가 완전하다고 명시된 완료 SBOM에서만 표시합니다.</p></>}
          {tab === "vulnerabilities" && <><h3>저장된 분석에서 발견된 취약점</h3><div className="table-scroll"><ResizableTable aria-label="라이브러리 연관 취약점"><thead><tr><th>CVE / 취약점 ID</th><th>심각도</th><th>관측 근거</th></tr></thead><tbody>{detail.vulnerabilities.map((item, index) => <tr key={`${item.analysisId}-${item.id}-${index}`}><td><ScrollingText>{item.id}</ScrollingText><small>{item.dataAsOf}</small></td><td>{severityLabels[item.severity.toLowerCase()] || item.severity}</td><td>{item.evaluationState === "reanalysis_required" ? "과거 분석 · 재분석 필요" : item.current ? "최신 관측" : "과거 관측"}{item.matchBasis !== "purl" && <small>이름 일치 · 식별 검토 필요</small>}<button type="button" className="library-link" onClick={() => openRun(item.runId)}>분석 근거 보기</button></td></tr>)}{!detail.vulnerabilities.length && <tr><td colSpan={3}>연결된 저장 분석 결과가 없습니다. 취약점이 없음을 뜻하지 않습니다.</td></tr>}</tbody></ResizableTable></div>{detail.vulnerabilitiesTruncated && <p className="library-footnote" role="note">연관 취약점은 최근 관측 회차 최대 {detail.vulnerabilityCoverage?.runLimit ?? 1000}개, 발견 근거 최대 {detail.vulnerabilityCoverage?.recordLimit ?? 200}건으로 조회 범위를 제한했습니다. 전체 이력이 아니며, 이전 회차의 분석 근거는 해당 SBOM에서 확인하세요.</p>}</>}
          </div>
        </> : <p className="library-empty">목록에서 라이브러리를 선택하세요.</p>}
      </div>
    </div>
  </section>;
}

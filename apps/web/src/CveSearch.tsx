import { useEffect, useState, type FormEvent } from "react";
import { previewMode } from "./api";
import { fetchCveCatalog, fetchCveDetail, EMPTY_CVE_QUERY, type CveCatalogDetail, type CveCatalogPage, type CveProduct } from "./cve-search-api";
import { formatSeoulDateTime } from "./format";
import { Icon } from "./icons";
import { ScrollingText } from "./ScrollingText";
import "./cve-search.css";

const statusName = (status: string) => ({ affected: "영향 있음", unaffected: "영향 없음", unknown: "확인 필요", environment: "환경 선행조건" })[status] || status;
const date = (value: string | null) => value ? formatSeoulDateTime(value).slice(0, 10) : "미제공";
function ProductRows({ products }: { products: CveProduct[] }) {
  return <div className="table-scroll"><table className="cve-products"><thead><tr><th>공급자·소프트웨어</th><th>공지 버전·범위</th><th>상태·적용 조건</th></tr></thead><tbody>{products.map((product, index) => <tr key={`${product.source}-${product.vendor}-${product.product}-${index}`}><td><strong><ScrollingText>{product.product}</ScrollingText></strong><small><ScrollingText>{product.vendor}</ScrollingText></small></td><td>{product.ranges.length ? product.ranges.map((range, position) => <span className="cve-product-range" key={position}><ScrollingText>{range.label}</ScrollingText><small><ScrollingText>{`${statusName(range.status)} · ${range.versionType}`}</ScrollingText></small></span>) : "버전 정보 미제공"}</td><td>{product.condition}{product.sourceIdentifier && <small><ScrollingText>{`제공 출처: ${product.sourceIdentifier}`}</ScrollingText></small>}{product.defaultStatus && <small>기본 상태: {statusName(product.defaultStatus)}</small>}</td></tr>)}{!products.length && <tr><td colSpan={3}>보존된 제품·버전 정보가 없습니다. 설명만으로 영향 범위를 추정하지 않습니다.</td></tr>}</tbody></table></div>;
}

export default function CveSearchPanel({ onOpenRun }: { onOpenRun?: (runId: string) => void }) {
  const [draft, setDraft] = useState({ ...EMPTY_CVE_QUERY });
  const [query, setQuery] = useState({ ...EMPTY_CVE_QUERY });
  const [page, setPage] = useState(1);
  const [reload, setReload] = useState(0);
  const [listState, setListState] = useState<{ key: string; data: CveCatalogPage | null; error: string }>({ key: "", data: null, error: "" });
  const [selected, setSelected] = useState("");
  const [detailState, setDetailState] = useState<{ key: string; data: CveCatalogDetail | null; error: string }>({ key: "", data: null, error: "" });
  const [productSource, setProductSource] = useState<"cna" | "nvd">("cna");
  const queryKey = JSON.stringify([query, page, reload]);
  const loading = listState.key !== queryKey;
  const result = loading ? null : listState.data;
  const error = loading ? "" : listState.error;
  const bundleVersion = result?.bundleVersion || "";
  const detailKey = JSON.stringify([selected, bundleVersion, reload]);
  const detailLoading = Boolean(selected && detailState.key !== detailKey);
  const detail = detailState.key === detailKey ? detailState.data : null;
  const detailError = detailState.key === detailKey ? detailState.error : "";

  useEffect(() => {
    let active = true;
    void fetchCveCatalog(query, page).then(value => {
      if (!active) return;
      setListState({ key: queryKey, data: value, error: "" }); setSelected(value.items[0]?.id || "");
    }).catch(reason => { if (active) { setListState({ key: queryKey, data: null, error: reason instanceof Error ? reason.message : "CVE 자료를 조회하지 못했습니다." }); setSelected(""); } });
    return () => { active = false; };
  }, [query, page, reload, queryKey]);
  useEffect(() => {
    let active = true;
    if (!selected || !bundleVersion) return;
    void fetchCveDetail(selected).then(value => {
      if (!active) return;
      if (value.bundleVersion !== bundleVersion) { setDetailState({ key: detailKey, data: null, error: "활성 취약점 자료가 변경되었습니다. 다시 검색하여 같은 자료 버전으로 확인하세요." }); return; }
      setDetailState({ key: detailKey, data: value, error: "" }); setProductSource(value.products.some(product => product.source === "cna") ? "cna" : "nvd");
    }).catch(reason => { if (active) setDetailState({ key: detailKey, data: null, error: reason instanceof Error ? reason.message : "CVE 상세 조회에 실패했습니다." }); });
    return () => { active = false; };
  }, [selected, bundleVersion, reload, detailKey]);

  function submit(event: FormEvent) {
    event.preventDefault(); setPage(1);
    setQuery(Object.fromEntries(Object.entries(draft).map(([key, value]) => [key, value.trim()])) as typeof draft);
  }
  const pages = Math.max(1, Math.ceil((result?.total || 0) / (result?.size || 20)));
  return <section className="cve-search-panel" aria-label="CVE 검색">
    <div className="cve-section-heading"><div><h2>CVE 검색</h2><p>공지된 소프트웨어·영향 버전과 우리 SBOM의 발견 근거를 함께 확인합니다.</p></div>{previewMode && <span className="cve-demo-label">샘플 · 모든 데이터는 가상 예시</span>}</div>
    <form className="cve-search-form" onSubmit={submit}>
      <label>CVE 번호·설명<input aria-label="CVE 번호·설명" value={draft.q} maxLength={256} placeholder="CVE-2026-…" onChange={event => setDraft(value => ({ ...value, q: event.target.value }))}/></label>
      <label>공급자<input aria-label="CVE 공급자" value={draft.vendor} maxLength={256} placeholder="공급자명" onChange={event => setDraft(value => ({ ...value, vendor: event.target.value }))}/></label>
      <label>소프트웨어명<input aria-label="CVE 소프트웨어명" value={draft.product} maxLength={256} placeholder="예: sample-json" onChange={event => setDraft(value => ({ ...value, product: event.target.value }))}/></label>
      <label>버전<input aria-label="CVE 검색 버전" value={draft.version} maxLength={128} placeholder="예: 1.4.0" onChange={event => setDraft(value => ({ ...value, version: event.target.value }))}/></label>
      <button className="primary" type="submit"><Icon name="search"/>검색</button>
      <button className="secondary" type="button" onClick={() => { setDraft({ ...EMPTY_CVE_QUERY }); setQuery({ ...EMPTY_CVE_QUERY }); setPage(1); }}>초기화</button>
    </form>
    {result && <p className="cve-source-note"><ScrollingText>{`${result.source} · 기준일 ${result.dataAsOf} · 자료 버전 ${result.bundleVersion}`}</ScrollingText></p>}
    {loading && <p role="status" className="cve-notice">활성 반입 자료에서 CVE를 검색하고 있습니다…</p>}
    {error && <div role="alert" className="cve-error"><strong>CVE 자료 조회 불가</strong><p>{error}</p><p>조회 실패·자료 미반입은 취약점 0건을 뜻하지 않습니다.</p><button type="button" className="secondary" onClick={() => setReload(value => value + 1)}>다시 조회</button></div>}
    {result && !loading && <>
      <h3 className="cve-results-title">검색 결과 ({result.total.toLocaleString()}건)</h3>
      <div className="table-frame"><div className="table-scroll"><table className="cve-catalog-results"><thead><tr><th>CVE</th><th>소프트웨어</th><th>공지 버전·범위</th><th>CVSS</th><th>수정일</th></tr></thead><tbody>{result.items.map(item => { const products = item.matchedProducts ?? item.products; return <tr key={item.id} className={selected === item.id ? "selected" : ""}><td><button type="button" className="cve-text-link" aria-expanded={selected === item.id} onClick={() => setSelected(item.id)}><ScrollingText focusable={false}>{item.id}</ScrollingText></button>{item.versionMatch === "unknown" && <small className="cve-review">버전·환경 조건 확인 필요</small>}{item.versionMatch === "match" && <small>입력 버전 조건 일치 · 실제 영향은 분석 근거 확인</small>}</td><td><ScrollingText>{[...new Set(products.filter(product => product.source === "cna" || product.ranges.some(range => range.status === "affected")).map(product => product.product))].slice(0, 3).join(", ") || "제품 정보 미제공"}</ScrollingText></td><td><ScrollingText>{products.map(product => `${product.product}: ${product.ranges.map(range => range.label).join(", ") || "버전 미제공"}`).join(" / ") || "원문 조건 확인 필요"}</ScrollingText></td><td>{item.cvss ?? "미제공"}</td><td>{date(item.lastModified)}</td></tr>; })}{!result.items.length && <tr><td colSpan={5}>검색 조건에 맞는 CVE가 없습니다. 검색 범위는 활성 반입 자료로 한정됩니다.</td></tr>}</tbody></table></div><div className="table-footer"><span>{page} / {pages} 페이지</span><div><button aria-label="CVE 이전 페이지" type="button" disabled={page <= 1} onClick={() => setPage(value => value - 1)}>‹</button><button aria-label="CVE 다음 페이지" type="button" disabled={page >= pages} onClick={() => setPage(value => value + 1)}>›</button></div></div></div>
      <p className="cve-source-note">{result.versionSearchNote}</p>
    </>}
    {selected && !loading && !error && <section className="cve-detail" aria-label="선택한 CVE 상세">
      <div className="cve-section-heading"><h3><ScrollingText>{`${selected} 상세`}</ScrollingText></h3><button type="button" className="secondary" onClick={() => setSelected("")}>상세 닫기</button></div>
      {detailLoading && <p role="status">CVE 상세를 불러오고 있습니다…</p>}
      {detailError && <p role="alert" className="cve-error">{detailError}</p>}
      {detail && <>
        <p className="cve-description">{detail.description || "설명 미제공"}</p>
        <dl className="cve-metadata"><div><dt>공개일</dt><dd>{date(detail.published)}</dd></div><div><dt>수정일</dt><dd>{date(detail.lastModified)}</dd></div><div><dt>CVSS</dt><dd>{detail.cvss ?? "미제공"}</dd></div><div><dt>상태</dt><dd><ScrollingText>{detail.status}</ScrollingText></dd></div></dl>
        <div className="cve-source-tabs" role="tablist" aria-label="CVE 제품 정보 출처"><button type="button" role="tab" aria-selected={productSource === "cna"} onClick={() => setProductSource("cna")}>발행기관 공지</button><button type="button" role="tab" aria-selected={productSource === "nvd"} onClick={() => setProductSource("nvd")}>NVD 분석 조건</button></div>
        <div role="tabpanel" aria-label={productSource === "cna" ? "발행기관 공지" : "NVD 분석 조건"}><ProductRows products={detail.products.filter(product => product.source === productSource)}/></div>
        <p className="cve-notice">{detail.applicabilityNote}</p>
        <div className="cve-section-heading"><h3>우리 SBOM에서 발견된 버전</h3><span className="cve-source-note">{detail.observations.scope || "보관된 SBOM 기준"}</span></div>
        {!detail.observations.available ? <p>{detail.observations.reason}</p> : <div className="table-scroll"><table className="cve-observations"><thead><tr><th>서비스</th><th>환경</th><th>릴리스</th><th>발견 버전</th><th>관측 시각·분석 상태</th><th>근거</th></tr></thead><tbody>{detail.observations.items.map((item, index) => <tr key={`${item.runId}-${item.component}-${index}`}><td><ScrollingText>{item.service}</ScrollingText><small><ScrollingText>{item.component}</ScrollingText></small></td><td><ScrollingText>{item.environment}</ScrollingText></td><td><ScrollingText>{item.release}</ScrollingText></td><td><ScrollingText>{item.version || "미제공"}</ScrollingText></td><td>{formatSeoulDateTime(item.observedAt)}<small>{item.analysisState === "completed" ? "저장 분석 완료" : "분석 미완료 · 확인 필요"} · 자료 기준일 {item.dataAsOf}</small></td><td>{onOpenRun ? <button type="button" className="cve-text-link" onClick={() => onOpenRun(item.runId)}>SBOM 회차 보기</button> : <ScrollingText>{item.runId}</ScrollingText>}</td></tr>)}{!detail.observations.items.length && <tr><td colSpan={6}>조회 범위의 저장 분석 결과에서 발견 근거가 없습니다. 미발견만으로 안전을 뜻하지 않습니다.</td></tr>}</tbody></table></div>}
        {detail.observations.truncated && <p className="cve-review">전체 근거 중 최대 200건, 최신 회차 1,000개 범위를 표시합니다.</p>}
        <details className="cve-original"><summary>적용 조건·발행기관 원문 데이터 보기</summary><pre>{JSON.stringify({ affected: detail.affected, configurations: detail.configurations, weaknesses: detail.weaknesses }, null, 2)}</pre></details>
        {!!detail.references.length && <details><summary>참고 링크 ({detail.references.length})</summary><ul>{detail.references.map(url => <li key={url}><a href={url} target="_blank" rel="noopener noreferrer"><ScrollingText focusable={false}>{url}</ScrollingText></a></li>)}</ul></details>}
      </>}
    </section>}
  </section>;
}

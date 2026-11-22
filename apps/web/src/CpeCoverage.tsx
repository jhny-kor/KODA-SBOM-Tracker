import { DetailPagination } from "./DetailPagination";
import { RunDetailCard } from "./RunDetailCard";
import { useDetailPage } from "./useDetailPage";
import type { AnalysisRevisionSummary, CoverageReasonCount, SbomRunDetail } from "./types";
import "./quality.css";

const statusLabels: Record<string, string> = {
  completed: "제공 CPE 조건 평가 완료", incomplete: "평가 범위 불완전",
  unavailable: "적용 자료 이용 불가", not_evaluated: "미평가",
};
const reasons: Record<string, string> = {
  "No concrete CPE 2.3 identities supplied; no package-name inference performed": "구체적인 CPE 2.3 제품 식별자가 제공되지 않아 평가하지 않았습니다. 제품 이름으로 CPE를 추정하지 않습니다.",
  "No indexed applicability conditions for supplied products; absence is not proof of safety": "제공한 제품에 대한 적용 조건이 반입 자료에서 확인되지 않았습니다. 이 결과로 안전 여부를 확정할 수 없습니다.",
};
const collectionScopes: Record<string, string> = {
  filesystem: "파일시스템",
  "image-archive": "컨테이너 이미지",
  "aix-evidence": "IBM AIX 수집 증적",
};
const collectionStatuses: Record<string, string> = {
  completed: "지정 범위 수집 완료", partial: "부분 수집",
};
const collectionReasons: Record<string, string> = {
  static_js_identity_unconfirmed: "JavaScript 구성요소 이름 또는 버전 미확인",
  static_js_probe_truncated: "JavaScript 검사 크기 한도 초과",
  static_js_archive_depth_limit: "아카이브 중첩 깊이 한도 초과",
  static_js_archive_limit: "아카이브 크기 또는 항목 한도 초과",
  static_js_nested_archive_limit: "중첩 아카이브 검사 한도 초과",
  static_js_scan_limit: "JavaScript 검사량 한도 초과",
  static_js_read_failed: "JavaScript 파일 읽기 실패",
  filesystem_permission_denied: "파일시스템 읽기 권한 부족",
  filesystem_incomplete: "파일시스템 일부 수집 누락",
  file_limit_exceeded: "수집 파일 수 한도 초과",
  package_catalog_incomplete: "패키지 목록 일부 수집 누락",
  product_not_supported: "제품 식별 미지원",
  product_evidence_incomplete: "제품 식별 근거 부족",
  host_context_permission_denied: "호스트 상태 조회 권한 부족",
  host_context_incomplete: "호스트 상태 일부 미확인",
  livepatch_evidence_incomplete: "라이브패치 적용 근거 일부 미확인",
  no_identified_components: "식별한 구성요소 없음",
  aix_capture_failed: "AIX 증적 수집 실패",
  aix_evidence_unreadable: "AIX 증적 읽기 실패",
  oracle_inventory_unverified: "Oracle Home 설치 목록 미확인",
  oracle_ru_conflict: "Oracle 업데이트 버전 근거 불일치",
  oracle_ru_unknown: "Oracle 업데이트 버전 미확인",
  oracle_listener_unverified: "Oracle Listener 실행 파일 미확인",
  oracle_listener_version_unknown: "Oracle Listener 버전 미확인",
  oracle_sqlpatch_not_provided: "Oracle SQL 패치 이력 미제공",
  oracle_sqlpatch_partial: "Oracle SQL 패치 이력 일부 미확인",
};
const componentReasons: Record<string, string> = {
  missing_cpe: "CPE 없음",
  oracle_listener_version_unconfirmed: "Oracle Home의 Listener 버전 미확인",
  invalid_cpe: "CPE 형식 오류",
  nonconcrete_version: "CPE에 구체적인 버전 없음",
  nvd_unavailable: "반입한 NVD 적용 자료 이용 불가",
  no_indexed_product: "반입한 자료에 제품 적용 조건 없음",
  unresolved_applicability: "적용 조건 판정에 필요한 근거 부족",
  coverage_limit: "구성요소별 적용 조건 검사 한도 초과",
};
const count = (value: unknown, unit = "") => typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value.toLocaleString() + unit : "확인 불가";

function CoverageReasons({ items, labels, title }: { items: CoverageReasonCount[]; labels: Record<string, string>; title: string }) {
  const { start, end, pagination } = useDetailPage(items.length);
  if (!items.length) return null;
  return <details>
    <summary>{title}</summary>
    <ul className="paths">{items.slice(start, end).map(({ code, count: total }) => <li key={code}>
      {Object.hasOwn(labels, code) ? labels[code] : code} · {count(total, "건")}
    </li>)}</ul>
    {items.length > 10 && <DetailPagination label={title} {...pagination} />}
  </details>;
}

type CollectionEvidence = Pick<SbomRunDetail, "collectionCoverage" | "collectionCoverageState">;

function CollectionCoverage({ collectionCoverage: coverage, collectionCoverageState }: CollectionEvidence) {
  return <section className="coverage-stage" aria-label="SBOM 수집 범위">
    <h4>SBOM 수집 범위</h4>
    {collectionCoverageState === "invalid" ? <p>첨부된 수집 범위 정보에 오류가 있어 확인할 수 없습니다.</p> : !coverage ? <p>이 SBOM에 수집 범위 정보가 없습니다.</p> : <>
      <p>{collectionScopes[coverage.sourceType] || "수집 대상 확인 불가"} · {collectionStatuses[coverage.status] || "수집 상태 확인 불가"}</p>
      <div className="table-scroll" role="region" aria-label="SBOM 수집 현황 가로 스크롤" tabIndex={0}><table className="cpe-coverage-table" aria-label="SBOM 수집 현황"><tbody>
        <tr><th scope="row">수집된 구성요소</th><td>{count(coverage.componentCount, "개")}</td><th scope="row">제외한 디렉터리</th><td>{count(coverage.excludedDirectoryCount, "개")}</td></tr>
        {coverage.excludedPatternCount !== undefined && <tr><th scope="row">설정한 제외 패턴</th><td colSpan={3}>{count(coverage.excludedPatternCount, "개")}</td></tr>}
      </tbody></table></div>
      <CoverageReasons items={coverage.issueCounts} labels={collectionReasons} title="수집 중 확인이 필요한 사유" />
      {!!coverage.omittedIssueCount && <p>수집 보고 한도로 인해 사유 집계에 {count(coverage.omittedIssueCount, "건")}이 생략됐습니다.</p>}
    </>}
  </section>;
}

export function CpeCoverage({ analysis, loading = false, collectionCoverage, collectionCoverageState }: CollectionEvidence & { analysis?: AnalysisRevisionSummary; loading?: boolean }) {
  const summary = analysis?.dataSources?.cpeApplicability;
  const unresolved = summary?.unresolved?.slice(0, 100) ?? [];
  const unresolvedPage = useDetailPage(unresolved.length);
  const components = summary?.componentCoverage;
  const revisionCoverage = analysis?.dataSources?.collectionCoverage;
  const revisionCoverageState = analysis?.dataSources?.collectionCoverageState;
  const status = typeof summary?.status === "string" ? summary.status : "unknown";
  const reason = typeof summary?.reason === "string" ? summary.reason : "";
  const countsIncomplete = [summary?.invalidCpes, summary?.unmatchedProducts, summary?.unknownCves].some(value => typeof value !== "number" || !Number.isSafeInteger(value) || value !== 0);
  const scopeIncomplete = status !== "completed" || countsIncomplete || Boolean(components && (components.inconclusive !== 0 || components.notEvaluated !== 0));

  return <RunDetailCard className="workflow-panel cpe-coverage tracker-view" title="오프라인 CPE 평가 범위">
    {loading ? <p>최신 분석의 CPE 평가 범위를 불러오는 중입니다.</p> : <>
      <CollectionCoverage collectionCoverage={revisionCoverage ?? collectionCoverage} collectionCoverageState={revisionCoverageState ?? collectionCoverageState} />
      {!analysis ? <p>분석 리비전이 없습니다. CPE 평가 여부를 확인할 수 없습니다.</p> : <>
      <p>최신 분석 r{analysis.sequence} · {analysis.state === "completed" ? "분석 완료" : `분석 ${analysis.state}`} · CPE {statusLabels[status] || "상태 확인 필요"}</p>
      {analysis.state !== "completed" && <p>최신 분석이 완료되지 않았습니다. 아래 값은 현재 확보된 근거이며 최종 점검 결과로 확정할 수 없습니다.</p>}
      {!summary ? <p>이 분석에는 CPE 평가 근거가 없습니다. 구버전 분석 또는 미평가 상태이므로 CPE 취약점 없음으로 간주할 수 없습니다.</p> : <>
        {components ? <section className="coverage-stage" aria-label="NVD 구성요소 대조 결과">
          <h4>NVD 구성요소 대조 결과</h4>
          <p>반입한 NVD 적용 조건과 CPE를 대조한 구성요소 수입니다. Grype의 PURL 등 다른 식별자 매칭은 별도입니다.</p>
          <div className="table-scroll" role="region" aria-label="NVD 구성요소 대조 현황 가로 스크롤" tabIndex={0}><table className="cpe-coverage-table" aria-label="NVD 구성요소 대조 현황"><tbody>
            <tr><th scope="row">평가한 구성요소</th><td>{count(components.evaluated, "개")}</td><th scope="row">판정 보류 구성요소</th><td>{count(components.inconclusive, "개")}</td></tr>
            <tr><th scope="row">미평가 구성요소</th><td colSpan={3}>{count(components.notEvaluated, "개")}</td></tr>
          </tbody></table></div>
          <CoverageReasons items={components.reasons} labels={componentReasons} title="미평가·판정 보류 사유" />
        </section> : <p>구성요소별 NVD 대조 집계가 저장되지 않았습니다.</p>}
        <div className="table-scroll" role="region" aria-label="CPE 평가 현황 가로 스크롤" tabIndex={0}><table className="cpe-coverage-table" aria-label="CPE 평가 항목별 현황"><tbody>
          <tr><th scope="row">입력 CPE</th><td>{count(summary.inputCpes, "개")}</td><th scope="row">유효하지 않은 CPE</th><td>{count(summary.invalidCpes, "개")}</td></tr>
          <tr><th scope="row">적용 조건이 없는 제품</th><td>{count(summary.unmatchedProducts, "개")}</td><th scope="row">평가한 CVE</th><td>{count(summary.evaluatedCves, "개")}</td></tr>
          <tr><th scope="row">조건 판정 불가 CVE</th><td>{count(summary.unknownCves, "개")}</td><th scope="row">적용 조건 형식·복잡도 확인 필요 CVE</th><td>{count(summary.indexIncompleteCves, "개")}</td></tr>
          <tr><th scope="row">영향 확인 CVE</th><td>{count(summary.affectedCves, "개")}</td><th scope="row">추가 발견 / 기존 발견 보강</th><td>{count(summary.addedFindings)} / {count(summary.matchedExisting)}건</td></tr>
          <tr className="cpe-coverage-wide"><th scope="row">적용 조건 없는 과거 NVD 레코드</th><td colSpan={3}>{count(summary.legacyDetailsOnly, "개")}</td></tr>
          <tr className="cpe-coverage-wide"><th scope="row">인벤토리 전체성</th><td colSpan={3}>{summary.inventoryComplete === true ? "완전한 인벤토리로 평가됨" : "확인되지 않음 · 누락 환경 조건은 판정 불가로 처리"}</td></tr>
        </tbody></table></div>
        {reason && <p>평가 사유: {reasons[reason] || reason}</p>}
        {unresolved.length > 0 && <details><summary>미판정 근거 보기 (최대 100개)</summary><ul className="paths">{unresolved.slice(unresolvedPage.start, unresolvedPage.end).map((item, index) => <li key={`${item.id}-${unresolvedPage.start + index}`}>{item.id}{item.oracleHomeId && <> · <code>{item.oracleHomeId}</code></>}: {item.reason}</li>)}</ul>
          <DetailPagination label="CPE 미판정 근거" {...unresolvedPage.pagination} />
        </details>}
        {scopeIncomplete && <p>식별자 또는 적용 자료가 부족하거나 조건을 확정하지 못했습니다. 미평가·미판정 항목을 취약점 없음으로 집계해서는 안 됩니다.</p>}
        <p>제공한 CPE와 반입한 NVD 적용 조건을 기준으로 평가합니다. 발견 0건은 전체 제품·환경의 안전을 보장하지 않습니다.</p>
      </>}
      </>}
    </>}
  </RunDetailCard>;
}

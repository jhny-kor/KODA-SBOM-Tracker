export function DetailPagination({
  total, page, pageSize, onPage, onPageSize, label, busy = false, level = "detail",
}: {
  total: number;
  page: number;
  pageSize: number;
  onPage: (page: number) => void;
  onPageSize?: (size: number) => void;
  label?: string;
  busy?: boolean;
  level?: "list" | "detail";
}) {
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  const currentPage = Math.min(page, pageCount);
  const prefix = label ? `${label} ` : level === "list" ? "" : "상세 ";
  const showPageNumbers = level === "list";
  const firstVisiblePage = Math.min(Math.max(1, currentPage - 2), Math.max(1, pageCount - 4));
  return <div className={showPageNumbers ? "detail-pagination list-pagination" : "detail-pagination"}>
    <span>전체 {total.toLocaleString()}건 · {currentPage}/{pageCount}페이지</span>
    <div>
      {onPageSize && <select aria-label={`${prefix}페이지당 행 수`} value={pageSize} onChange={event => onPageSize(Number(event.target.value))}>
        <option value={10}>10개씩 보기</option>
        <option value={25}>25개씩 보기</option>
        <option value={50}>50개씩 보기</option>
        <option value={100}>100개씩 보기</option>
      </select>}
      {showPageNumbers && <button type="button" aria-label={`${prefix}첫 페이지`} disabled={busy || currentPage <= 1} onClick={() => onPage(1)}>|‹</button>}
      <button type="button" aria-label={`${prefix}이전 페이지`} disabled={busy || currentPage <= 1} onClick={() => onPage(currentPage - 1)}>‹</button>
      {showPageNumbers && Array.from({ length: Math.min(5, pageCount) }, (_, index) => {
        const target = firstVisiblePage + index;
        return <button type="button" key={target} aria-label={`${prefix}${target}페이지`} aria-current={currentPage === target ? "page" : undefined}
          disabled={busy} onClick={() => onPage(target)}>{target}</button>;
      })}
      <button type="button" aria-label={`${prefix}다음 페이지`} disabled={busy || currentPage >= pageCount} onClick={() => onPage(currentPage + 1)}>›</button>
      {showPageNumbers && <button type="button" aria-label={`${prefix}마지막 페이지`} disabled={busy || currentPage >= pageCount} onClick={() => onPage(pageCount)}>›|</button>}
    </div>
  </div>;
}

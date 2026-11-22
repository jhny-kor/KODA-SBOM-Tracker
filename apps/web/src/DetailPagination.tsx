export function DetailPagination({
  total, page, pageSize, onPage, onPageSize, label, busy = false,
}: {
  total: number;
  page: number;
  pageSize: number;
  onPage: (page: number) => void;
  onPageSize: (size: number) => void;
  label?: string;
  busy?: boolean;
}) {
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  const currentPage = Math.min(page, pageCount);
  return <div className="detail-pagination">
    <span>전체 {total.toLocaleString()}건 · {currentPage}/{pageCount}페이지</span>
    <div>
      <select aria-label={`${label || "상세"} 페이지당 행 수`} value={pageSize} onChange={event => onPageSize(Number(event.target.value))}>
        <option value={10}>10개씩 보기</option>
        <option value={25}>25개씩 보기</option>
        <option value={50}>50개씩 보기</option>
        <option value={100}>100개씩 보기</option>
      </select>
      <button type="button" aria-label={`${label || "상세"} 이전 페이지`} disabled={busy || currentPage <= 1} onClick={() => onPage(currentPage - 1)}>‹</button>
      <button type="button" aria-label={`${label || "상세"} 다음 페이지`} disabled={busy || currentPage >= pageCount} onClick={() => onPage(currentPage + 1)}>›</button>
    </div>
  </div>;
}

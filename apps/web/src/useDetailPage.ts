import { useState } from "react";

export function useDetailPage(total: number) {
  const [pageSize, setPageSize] = useState(10);
  const [requestedPage, setPage] = useState(1);
  const page = Math.min(requestedPage, Math.max(1, Math.ceil(total / pageSize)));
  const start = (page - 1) * pageSize;

  return {
    start,
    end: start + pageSize,
    pagination: {
      total, page, pageSize, onPage: setPage,
      onPageSize(size: number) { setPageSize(size); setPage(1); },
    },
  };
}

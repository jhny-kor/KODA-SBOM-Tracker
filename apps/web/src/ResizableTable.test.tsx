import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { ResizableTable } from "./ResizableTable";

afterEach(cleanup);

it("resizes adjacent columns from an interior handle without changing their combined width", () => {
  render(<ResizableTable><thead><tr><th>First</th><><th>Second</th><th>Last</th></></tr></thead>
    <tbody><tr><td>A</td><td>B</td><td>C</td></tr></tbody>
  </ResizableTable>);
  const columns = screen.getAllByRole("columnheader") as HTMLTableCellElement[];
  columns.forEach(column => vi.spyOn(column, "getBoundingClientRect").mockReturnValue({
    width: 100,
  } as DOMRect));
  const handles = screen.getAllByRole("button", { name: /너비 조절/ });
  expect(handles).toHaveLength(2);
  expect(handles.map(handle => handle.textContent)).toEqual(["|", "|"]);

  fireEvent.keyDown(handles[1], { key: "ArrowRight" });
  expect(Number.parseFloat(columns[0].style.width)).toBeCloseTo(100 / 3);
  expect(Number.parseFloat(columns[1].style.width)).toBeCloseTo(112 / 3);
  expect(Number.parseFloat(columns[2].style.width)).toBeCloseTo(88 / 3);
});

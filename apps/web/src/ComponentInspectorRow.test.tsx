import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { useState } from "react";
import { afterEach, expect, it, vi } from "vitest";
import { request } from "./api";
import ComponentInspectorRow from "./ComponentInspectorRow";
import { correctRunComponent } from "./environment-admin-api";
import type { ComponentSnapshot } from "./types";

vi.mock("./api", () => ({ request: vi.fn() }));
vi.mock("./environment-admin-api", () => ({ correctRunComponent: vi.fn() }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });

const component: ComponentSnapshot = {
  id: "component-id", identityKey: "component-key", name: '"Example JDK"', version: '"1.8.0_201"',
};

function Inspector() {
  const [item, setItem] = useState(component);
  const [editing, setEditing] = useState("");
  return <table><tbody><ComponentInspectorRow
    runId="run-id" component={item} identifier="Java" canEdit editing={Boolean(editing)}
    showCpeCandidates onEdit={setEditing}
    onSaved={(_, saved) => { setItem(current => ({ ...current, ...saved })); setEditing(""); }}
  /></tbody></table>;
}

it("edits both table cells and saves using the button in the original name cell", async () => {
  vi.mocked(correctRunComponent).mockResolvedValue({ name: "Example JDK", version: "1.8.0_201", correctionRevision: 1 });
  render(<Inspector />);
  const edit = screen.getByRole("button", { name: /이름·버전 수정/ });
  const nameCell = edit.closest("td")!;
  fireEvent.click(edit);
  expect(correctRunComponent).not.toHaveBeenCalled();
  const name = screen.getByRole("textbox", { name: "구성요소 이름" });
  const version = screen.getByRole("textbox", { name: "구성요소 버전" });
  const save = screen.getByRole("button", { name: "저장" });
  expect(name.closest("td")).toBe(nameCell);
  expect(version.closest("td")).toBe(nameCell.nextElementSibling);
  expect(save.closest("td")).toBe(nameCell);
  expect(name).toHaveValue('"Example JDK"');
  fireEvent.change(name, { target: { value: "Example JDK" } });
  fireEvent.change(version, { target: { value: "1.8.0_201" } });
  fireEvent.click(save);
  await waitFor(() => expect(correctRunComponent).toHaveBeenCalledWith("run-id", "component-id", {
    name: "Example JDK", version: "1.8.0_201", expectedRevision: 0,
  }));
  expect(await screen.findByText("Example JDK")).toBeVisible();
  expect(screen.queryByRole("textbox", { name: "구성요소 버전" })).not.toBeInTheDocument();
});

it("shows fetched CPE evidence inside the last cell of the same component row", async () => {
  vi.mocked(request).mockResolvedValue({ dataAsOf: "2026-11-07", candidates: [{
    id: "c0", vendor: "oracle", product: "jdk", match: "exact", cveCount: 12,
    cpe: "cpe:2.3:a:oracle:jdk:*:*:*:*:*:*:*:*", confidence: "medium", reason: "검토용 예시",
  }] });
  render(<Inspector />);
  const open = screen.getByRole("button", { name: /CPE 식별 후보 조회/ });
  fireEvent.click(open);
  const candidate = await screen.findByText("cpe:2.3:a:oracle:jdk:*:*:*:*:*:*:*:*");
  expect(candidate.closest("td")).toBe(open.closest("tr")?.lastElementChild);
  expect(screen.getAllByRole("row")).toHaveLength(1);
  expect(screen.getByText(/이름 정확 일치 · 관련 CVE 12건 · AI 신뢰도 보통/)).toBeVisible();
});



it("confirms deletion next to Cancel and restores the removed row on request", async () => {
  vi.mocked(correctRunComponent)
    .mockResolvedValueOnce({ name: component.name, version: component.version!, correctionRevision: 1, removed: true })
    .mockResolvedValueOnce({ name: component.name, version: component.version!, correctionRevision: 2, removed: false });
  render(<Inspector />);
  fireEvent.click(screen.getByRole("button", { name: /이름·버전 수정/ }));
  const cancel = screen.getByRole("button", { name: "취소" });
  const remove = screen.getByRole("button", { name: "삭제" });
  expect(cancel.nextElementSibling).toBe(remove);
  expect(remove).toHaveClass("danger");

  fireEvent.click(remove);
  expect(screen.getByRole("status")).toHaveTextContent("검사기에서 삭제할까요?");
  fireEvent.click(cancel);
  expect(screen.queryByRole("button", { name: "삭제 확인" })).not.toBeInTheDocument();
  expect(correctRunComponent).not.toHaveBeenCalled();

  fireEvent.click(remove);
  fireEvent.click(screen.getByRole("button", { name: "삭제 확인" }));
  const restore = await screen.findByRole("button", { name: /복원/ });
  expect(correctRunComponent).toHaveBeenNthCalledWith(1, "run-id", "component-id", { removed: true, expectedRevision: 0 });
  expect(screen.queryByRole("button", { name: /후보 조회/ })).not.toBeInTheDocument();
  fireEvent.click(restore);
  await screen.findByRole("button", { name: /이름·버전 수정/ });
  expect(correctRunComponent).toHaveBeenNthCalledWith(2, "run-id", "component-id", { removed: false, expectedRevision: 1 });
});

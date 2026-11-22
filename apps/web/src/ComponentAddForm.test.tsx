import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import ComponentAddForm from "./ComponentAddForm";
import { addRunComponent } from "./environment-admin-api";

vi.mock("./environment-admin-api", () => ({ addRunComponent: vi.fn() }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });

it("requires both fields, saves their text and retains the draft on failure", async () => {
  const onSaved = vi.fn();
  vi.mocked(addRunComponent).mockRejectedValueOnce(new Error("같은 이름과 버전의 수동 추가 항목이 있습니다"))
    .mockResolvedValueOnce({ id: "manual:1", name: "Example", version: "02.01" });
  render(<ComponentAddForm id="add-component" runId="run" onCancel={vi.fn()} onSaved={onSaved} />);

  const name = screen.getByRole("textbox", { name: "이름" });
  const version = screen.getByRole("textbox", { name: "버전" });
  const save = screen.getByRole("button", { name: "저장" });
  expect(name).toHaveFocus();
  fireEvent.change(name, { target: { value: " Example " } });
  expect(save).toBeDisabled();
  fireEvent.change(version, { target: { value: "02.01" } });
  fireEvent.click(save);
  expect(await screen.findByRole("alert")).toHaveTextContent("같은 이름과 버전");
  expect(version).toHaveValue("02.01");
  expect(onSaved).not.toHaveBeenCalled();

  fireEvent.click(save);
  await vi.waitFor(() => expect(onSaved).toHaveBeenCalledOnce());
  expect(addRunComponent).toHaveBeenLastCalledWith("run", { name: "Example", version: "02.01" });
});

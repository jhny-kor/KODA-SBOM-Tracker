import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ChangeEvent } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FlowSelect, ScrollingSelect } from "./ScrollingSelect";

const disconnect = vi.fn();
beforeEach(() => {
  disconnect.mockClear();
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect = disconnect; });
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe("FlowSelect native semantics", () => {
  it("preserves its accessible label, name, validation, change event and disabled submission behavior", async () => {
    const changed = vi.fn((event: ChangeEvent<HTMLSelectElement>) => event.currentTarget.value);
    const options = <><option value="">선택</option><option value="production">운영 환경의 전체 이름</option></>;
    const view = render(<form data-testid="form"><label htmlFor="environment">환경</label><FlowSelect id="environment" name="environment" required defaultValue="" onChange={changed}>{options}</FlowSelect></form>);
    const select = screen.getByRole("combobox", { name: "환경" }) as HTMLSelectElement;
    const form = screen.getByTestId("form") as HTMLFormElement;
    expect(select).toBeRequired();
    expect(select.validity.valueMissing).toBe(true);
    fireEvent.change(select, { target: { value: "production" } });
    await waitFor(() => expect(select).toHaveAttribute("title", "운영 환경의 전체 이름"));
    expect(changed).toHaveBeenCalledOnce();
    expect(changed).toHaveReturnedWith("production");
    expect(select.validity.valid).toBe(true);
    expect(new FormData(form).get("environment")).toBe("production");
    expect(view.container.querySelector(".flow-select-viewport")).toHaveAttribute("aria-hidden", "true");
    expect(view.container.querySelector(".scrolling-text")).not.toHaveAttribute("tabindex");

    view.rerender(<form data-testid="form"><label htmlFor="environment">환경</label><FlowSelect id="environment" name="environment" required disabled defaultValue="" onChange={changed}>{options}</FlowSelect></form>);
    expect(select).toBeDisabled();
    expect(new FormData(form).get("environment")).toBeNull();
    await act(async () => {});
  });

  it("keeps an uncontrolled default, changed value and form reset synchronized with its visible text", async () => {
    render(<form data-testid="form"><FlowSelect aria-label="환경" name="environment" defaultValue="a"><option value="a">기본 개발 환경</option><option value="b">선택한 운영 환경</option></FlowSelect></form>);
    const select = screen.getByRole("combobox", { name: "환경" });
    const form = screen.getByTestId("form") as HTMLFormElement;
    await waitFor(() => expect(select).toHaveAttribute("title", "기본 개발 환경"));
    expect(new FormData(form).get("environment")).toBe("a");
    fireEvent.change(select, { target: { value: "b" } });
    await waitFor(() => expect(select).toHaveAttribute("title", "선택한 운영 환경"));
    expect(new FormData(form).get("environment")).toBe("b");

    await act(async () => form.reset());
    await waitFor(() => expect(select).toHaveAttribute("title", "기본 개발 환경"));
    expect(select).toHaveValue("a");
    expect(new FormData(form).get("environment")).toBe("a");
  });

  it("restores the displayed selection when a controlled owner rejects a native change", async () => {
    const changed = vi.fn((event: ChangeEvent<HTMLSelectElement>) => event.currentTarget.value);
    render(<FlowSelect aria-label="고정된 환경" value="a" onChange={changed}><option value="a">승인된 환경</option><option value="b">다른 환경</option></FlowSelect>);
    const select = screen.getByRole("combobox", { name: "고정된 환경" });
    await waitFor(() => expect(select).toHaveAttribute("title", "승인된 환경"));
    await act(async () => { fireEvent.change(select, { target: { value: "b" } }); });
    expect(changed).toHaveReturnedWith("b");
    expect(select).toHaveValue("a");
    expect(select).toHaveAttribute("title", "승인된 환경");
  });

  it("uses native option labels and updates its display when option attributes or children change", async () => {
    const view = render(<FlowSelect aria-label="환경" defaultValue="a"><option value="a" label="환경 별칭">내부 원본 이름</option></FlowSelect>);
    const select = screen.getByRole("combobox", { name: "환경" }) as HTMLSelectElement;
    await waitFor(() => expect(select).toHaveAttribute("title", "환경 별칭"));
    await act(async () => { select.options[0].label = "변경된 환경 별칭"; });
    await waitFor(() => expect(select).toHaveAttribute("title", "변경된 환경 별칭"));

    view.rerender(<FlowSelect aria-label="환경" defaultValue="a"><option value="a">새로 불러온 환경 이름</option></FlowSelect>);
    await waitFor(() => expect(select).toHaveAttribute("title", "새로 불러온 환경 이름"));
    expect(select).toHaveValue("a");
  });
});

it("preserves the comparison adapter's accessible native select, explicit selected text and string change callback", async () => {
  const change = vi.fn();
  const view = render(<ScrollingSelect value="a" text="긴 회차 이름" label="기준 회차" onChange={change}><option value="a">회차 A</option><option value="b">회차 B</option></ScrollingSelect>);
  const select = screen.getByRole("combobox", { name: "기준 회차" });
  await act(async () => {});
  expect(select).toHaveValue("a");
  expect(select).toHaveAttribute("title", "긴 회차 이름");
  await act(async () => { fireEvent.change(select, { target: { value: "b" } }); });
  expect(change).toHaveBeenCalledWith("b");
  expect(select).toHaveAttribute("title", "긴 회차 이름");
  view.unmount();
  expect(disconnect).toHaveBeenCalledOnce();
});

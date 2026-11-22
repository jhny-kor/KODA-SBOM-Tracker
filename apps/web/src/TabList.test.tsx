import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { afterEach, expect, it } from "vitest";
import { TabList } from "./TabList";

const items = [
  { id: "first", label: "첫 탭" },
  { id: "middle", label: "둘째 탭" },
  { id: "last", label: "마지막 탭" },
] as const;

function Example() {
  const [value, setValue] = useState<(typeof items)[number]["id"]>("middle");
  return <>
    <TabList label="테스트 탭" idPrefix="example" value={value} items={items} onChange={setValue} />
    <div role="tabpanel" id={`example-panel-${value}`} aria-labelledby={`example-tab-${value}`} />
  </>;
}

afterEach(cleanup);

it("moves focus and the active panel with arrows, Home and End", () => {
  render(<Example />);
  const first = screen.getByRole("tab", { name: "첫 탭" });
  const middle = screen.getByRole("tab", { name: "둘째 탭" });
  const last = screen.getByRole("tab", { name: "마지막 탭" });
  const expectSelection = (tab: HTMLElement) => {
    expect(screen.getByRole("tab", { selected: true })).toBe(tab);
    expect(tab).toHaveAttribute("tabindex", "0");
    expect(document.querySelectorAll('[role="tab"][tabindex="0"]')).toHaveLength(1);
    expect(screen.getByRole("tabpanel")).toHaveAttribute("aria-labelledby", tab.id);
    expect(tab).toHaveAttribute("aria-controls", screen.getByRole("tabpanel").id);
  };

  expectSelection(middle);
  middle.focus();
  fireEvent.keyDown(middle, { key: "ArrowRight" });
  expectSelection(last);
  expect(last).toHaveFocus();

  fireEvent.keyDown(last, { key: "ArrowRight" });
  expectSelection(first);
  expect(first).toHaveFocus();

  fireEvent.keyDown(first, { key: "ArrowLeft" });
  expectSelection(last);
  expect(last).toHaveFocus();

  fireEvent.keyDown(last, { key: "Home" });
  expectSelection(first);
  expect(first).toHaveFocus();

  fireEvent.keyDown(first, { key: "End" });
  expectSelection(last);
  expect(last).toHaveFocus();

  fireEvent.click(middle);
  expectSelection(middle);
});

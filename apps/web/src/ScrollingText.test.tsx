import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ScrollingText } from "./ScrollingText";

let viewportWidth = 160;
let contentWidth = 120;
const observers: TestResizeObserver[] = [];

class TestResizeObserver {
  observe = vi.fn();
  unobserve = vi.fn();
  disconnect = vi.fn();
  constructor(readonly callback: ResizeObserverCallback) { observers.push(this); }
  notify() { this.callback([], this); }
}

beforeEach(() => {
  viewportWidth = 160;
  contentWidth = 120;
  observers.length = 0;
  vi.stubGlobal("ResizeObserver", TestResizeObserver);
  vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockImplementation(function (this: HTMLElement) {
    return this.classList.contains("scrolling-text") ? viewportWidth : 0;
  });
  vi.spyOn(HTMLElement.prototype, "scrollWidth", "get").mockImplementation(function (this: HTMLElement) {
    return this.classList.contains("scrolling-text-content") ? contentWidth : 0;
  });
});

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

async function notifyResize() {
  await act(async () => { observers.forEach(observer => observer.notify()); });
}

describe("overflowing text", () => {
  it("offers a focus stop only while the complete value exceeds its group", async () => {
    render(<ScrollingText data-testid="value">라이브러리 전체 이름</ScrollingText>);
    const value = screen.getByTestId("value");
    await act(async () => {});
    expect(value).toHaveAttribute("data-overflow", "false");
    expect(value).not.toHaveAttribute("tabindex");
    expect(value).toHaveAttribute("title", "라이브러리 전체 이름");

    contentWidth = 480;
    await notifyResize();
    expect(value).toHaveAttribute("data-overflow", "true");
    expect(value).toHaveAttribute("tabindex", "0");
    act(() => value.focus());
    expect(value).toHaveFocus();
    expect(value).toHaveTextContent("라이브러리 전체 이름");

    viewportWidth = 600;
    await notifyResize();
    expect(value).toHaveAttribute("data-overflow", "false");
    expect(value).not.toHaveAttribute("tabindex");
  });

  it("remeasures changed text and replaces the moving content so its motion restarts", async () => {
    contentWidth = 420;
    const view = render(<ScrollingText data-testid="value">이전의 긴 라이브러리 이름</ScrollingText>);
    const oldContent = screen.getByText("이전의 긴 라이브러리 이름");
    await waitFor(() => expect(screen.getByTestId("value")).toHaveAttribute("data-overflow", "true"));

    contentWidth = 90;
    view.rerender(<ScrollingText data-testid="value">짧은 이름</ScrollingText>);
    await waitFor(() => expect(screen.getByTestId("value")).toHaveAttribute("data-overflow", "false"));
    expect(oldContent).not.toBeInTheDocument();
    expect(screen.getByText("짧은 이름")).not.toBe(oldContent);
    expect(screen.getByTestId("value")).toHaveAttribute("title", "짧은 이름");
    expect(observers[0].disconnect).toHaveBeenCalledOnce();
  });

  it("keeps nested controls as the only focus target when focusable is false", async () => {
    contentWidth = 420;
    render(<button><ScrollingText data-testid="value" focusable={false}>긴 환경 이름 전체 보기</ScrollingText></button>);
    const value = screen.getByTestId("value");
    await waitFor(() => expect(value).toHaveAttribute("data-overflow", "true"));
    expect(value).not.toHaveAttribute("tabindex");
    const button = screen.getByRole("button", { name: "긴 환경 이름 전체 보기" });
    act(() => button.focus());
    expect(button).toHaveFocus();
  });

  it("responds to window resizing without ResizeObserver and removes its listener on unmount", async () => {
    vi.stubGlobal("ResizeObserver", undefined);
    const addListener = vi.spyOn(window, "addEventListener");
    const removeListener = vi.spyOn(window, "removeEventListener");
    contentWidth = 420;
    const view = render(<ScrollingText data-testid="value">관측 API가 없는 환경의 긴 이름</ScrollingText>);
    const value = screen.getByTestId("value");
    await waitFor(() => expect(value).toHaveAttribute("data-overflow", "true"));
    const resizeListener = addListener.mock.calls.find(([name]) => name === "resize")?.[1];
    expect(resizeListener).toBeTypeOf("function");

    viewportWidth = 600;
    fireEvent(window, new Event("resize"));
    expect(value).toHaveAttribute("data-overflow", "false");
    view.unmount();
    expect(removeListener).toHaveBeenCalledWith("resize", resizeListener);
  });
});

import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import App from "./App";
import { fetchActiveCveBaseline, fetchRuns } from "./api";
import { demoRuns } from "./demo";

vi.mock("./api", async (importOriginal) => ({
  ...await importOriginal<typeof import("./api")>(),
  demoMode: false,
  previewMode: false,
  standaloneMode: false,
  resumeSession: vi.fn().mockResolvedValue({
    user: { id: "reader", username: "reader", role: "viewer", active: true, permissions: ["runs.view"] },
  }),
  fetchActiveCveBaseline: vi.fn(),
  fetchRuns: vi.fn(),
}));

beforeEach(() => {
  window.history.replaceState(null, "", "/?page=runs");
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} });
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.history.replaceState(null, "", "/");
});

it.each([
  ["2026-11-07", "2026-11-07"],
  [null, "확인 필요"],
])("uses the active NVD date (%s) while keeping the historical run date", async (date, headerDate) => {
  const run = { ...demoRuns[0], cveDataAsOf: "2026-08-24" };
  vi.mocked(fetchRuns).mockResolvedValue({ items: [run], page: 1, size: 10, total: 1 });
  vi.mocked(fetchActiveCveBaseline).mockResolvedValue({ cveDataAsOf: date });

  render(<App />);

  expect(await screen.findByText(`활성 CVE 기준일: ${headerDate}`)).toBeInTheDocument();
  const table = await screen.findByRole("table");
  expect(await within(table).findByRole("cell", { name: "2026-08-24" })).toBeInTheDocument();
});

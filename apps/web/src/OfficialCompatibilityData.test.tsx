import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { request } from "./api";
import OfficialCompatibilityData from "./OfficialCompatibilityData";

vi.mock("./api", () => ({ request: vi.fn() }));
const apiRequest = vi.mocked(request);
afterEach(() => { cleanup(); apiRequest.mockReset(); });

it("uploads one archive and exposes verified file provenance beside the pinned institution", async () => {
  const authority = { id: "pypi", ecosystem: "python", organization: "Python Software Foundation", name: "PyPI", url: "https://pypi.org/" };
  const file = { kind: "wheel", path: "python/demo.whl", url: "https://files.pythonhosted.org/demo.whl", sha256: "b".repeat(64), size: 28 };
  const bundle = { id: "bundle", sha256: "a".repeat(64), collectedAt: "2026-11-08T10:00:00Z", importedAt: "2026-11-08T10:15:00Z",
    items: [{ ecosystem: "python", package: "demo", version: "1.0", authority, files: [file], evidence: { requiresPython: ">=3.9" } }] };
  apiRequest.mockResolvedValueOnce({ bundles: [], authorities: [authority] }).mockResolvedValueOnce(bundle);

  render(<OfficialCompatibilityData canManage />);
  const input = screen.getByLabelText("호환성 자료 압축파일");
  await screen.findByText("반입된 호환성 자료가 없습니다.");
  fireEvent.change(input, { target: { files: [new File(["archive"], "compatibility.tar.gz")] } });
  const submit = screen.getByRole("button", { name: "반입하고 검증" });
  expect(submit).toBeEnabled();
  fireEvent.submit(submit.closest("form")!);

  const detail = await screen.findByRole("region", { name: "반입한 호환성 자료" });
  expect(within(detail).getByText(authority.organization)).toBeInTheDocument();
  expect(within(detail).getByText("Python 요구 버전 >=3.9")).toBeInTheDocument();
  const source = within(detail).getByText("원본과 검증 해시 1개").closest("details")!;
  source.open = true;
  expect(within(detail).getByRole("link", { name: file.url })).toHaveAttribute("href", file.url);
  expect(within(detail).getByText(file.sha256)).toBeInTheDocument();
  const [endpoint, options] = apiRequest.mock.calls[1];
  expect(endpoint).toBe("/api/v1/compatibility-data/import");
  expect(options?.method).toBe("POST");
  expect(((options?.body as FormData).get("file") as File).name).toBe("compatibility.tar.gz");
  expect(screen.getByRole("button", { name: "반입하고 검증" })).toBeDisabled();
});

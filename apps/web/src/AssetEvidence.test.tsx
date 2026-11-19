import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { AssetEvidence } from "./AssetEvidence";
afterEach(cleanup);
it("shows running and stored firmware", () => {
  render(<AssetEvidence component={{ identityKey: "nic", name: "NIC", componentType: "firmware", version: "1.0", properties: [
    { name: "koda:asset:model", value: "Model A" },
    { name: "koda:asset:evidence:running.fw", value: "1.0" },
    { name: "koda:asset:evidence:stored.fw", value: "2.0" },
    { name: "koda:asset:evidence:applicationState", value: "Staged" },
  ] }} />);
  expect(screen.getByText("Model A")).toBeInTheDocument();
  expect(screen.getByText("stored.fw").nextSibling).toHaveTextContent("2.0");
  expect(screen.getByText("보고된 적용 상태").nextSibling).toHaveTextContent("Staged");
});
it("marks missing observations", () => {
  render(<AssetEvidence component={{ identityKey: "a", name: "Device", componentType: "device" }} />);
  expect(screen.getByText("미확인")).toBeInTheDocument();
  expect(screen.getByText("상세 수집 근거가 제공되지 않았습니다.")).toBeInTheDocument();
});
it("limits the panel to device types", () => {
  const { container } = render(<AssetEvidence component={{ identityKey: "lib", name: "Library", componentType: "library" }} />);
  expect(container).toBeEmptyDOMElement();
});

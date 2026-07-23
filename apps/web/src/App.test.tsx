import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import App from "./App";

afterEach(cleanup);

describe("KODA SBOM Tracker", () => {
  it("renders dense run history and opens comparison", () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: "SBOM 회차" })).toBeInTheDocument();
    expect(screen.getAllByText("결제 API").length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("button", { name: "회차 비교" }));
    expect(screen.getByRole("heading", { name: "회차 비교" })).toBeInTheDocument();
    expect(screen.getByText("구성요소 추가")).toBeInTheDocument();
  });

  it("opens upload dialog", () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: /SBOM 업로드/ }));
    expect(screen.getByRole("dialog", { name: "SBOM 업로드" })).toBeInTheDocument();
  });
});

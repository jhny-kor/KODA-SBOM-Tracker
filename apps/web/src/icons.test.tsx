import { render, cleanup } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { Icon } from "./icons";

afterEach(cleanup);

it("renders the revised icons and reuses the existing KODA logo", () => {
  const names = ["compare", "vulnerability", "lock", "koda", "settings", "reset", "integration", "external"];
  const { container } = render(<>{names.map((name) => <Icon key={name} name={name} />)}</>);
  const icons = container.querySelectorAll("svg");
  expect(icons).toHaveLength(names.length);
  icons.forEach((icon) => {
    expect(icon.getAttribute("viewBox")).toBe("0 0 24 24");
    expect(icon.getAttribute("aria-hidden")).toBe("true");
    expect(icon.children.length).toBeGreaterThan(0);
  });
  expect(icons[3].querySelector("image")?.getAttribute("href")).toBe("/KODA.ico");
  const center = icons[4].querySelector("circle");
  expect([center?.getAttribute("cx"), center?.getAttribute("cy")]).toEqual(["12", "12"]);
  expect(icons[6].innerHTML).not.toBe(icons[7].innerHTML);
});

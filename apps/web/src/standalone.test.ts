import { afterEach, describe, expect, it } from "vitest";
import { getStandaloneRun, getStandaloneRuns, importStandaloneSbom, parseStandaloneSbom, resetStandaloneStore } from "./standalone";

afterEach(() => resetStandaloneStore());

describe("standalone CycloneDX preview", () => {
  it("parses JSON components and embedded vulnerabilities", async () => {
    const detail = await parseStandaloneSbom(JSON.stringify({
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      metadata: { timestamp: "2026-08-05T01:02:03Z" },
      components: [{
        type: "library",
        group: "org.example",
        name: "demo-lib",
        version: "1.2.3",
        purl: "pkg:maven/org.example/demo-lib@1.2.3",
        licenses: [{ license: { id: "Apache-2.0" } }],
      }],
      vulnerabilities: [{
        id: "CVE-2026-0001",
        ratings: [{ severity: "high" }],
        affects: [{ ref: "pkg:maven/org.example/demo-lib@1.2.3" }],
        kev: true,
      }],
    }), "demo.cdx.json", "1.2.3");

    expect(detail.service.name).toBe("로컬 미리보기");
    expect(detail.componentCount).toBe(1);
    expect(detail.vulnerabilityCount).toBe(1);
    expect(detail.dataAsOf).toBe("2026-08-05");
    expect(detail.components[0].purl).toContain("demo-lib@1.2.3");
    expect(detail.analyses[0].findings?.[0]).toMatchObject({ canonicalId: "CVE-2026-0001", severity: "high", kev: true });
  });

  it("parses XML and stores an uploaded preview run in memory", async () => {
    const xml = `<?xml version="1.0"?>
      <bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1.5">
        <metadata><timestamp>2026-08-04T12:00:00Z</timestamp></metadata>
        <components><component type="library" bom-ref="pkg:npm/demo@2.0.0">
          <name>demo</name><version>2.0.0</version><purl>pkg:npm/demo@2.0.0</purl>
        </component></components>
        <vulnerabilities><vulnerability id="CVE-2026-0002">
          <ratings><rating><severity>medium</severity></rating></ratings>
          <affects><target ref="pkg:npm/demo@2.0.0" /></affects>
        </vulnerability></vulnerabilities>
      </bom>`;
    const file = new File([xml], "demo.cdx.xml", { type: "application/xml" });
    Object.defineProperty(file, "text", { value: async () => xml });
    const result = await importStandaloneSbom(file, "2.0.0");

    expect(getStandaloneRuns()).toHaveLength(1);
    expect(getStandaloneRun(result.runId)).toMatchObject({ filename: "demo.cdx.xml", releaseVersion: "2.0.0", specVersion: "1.5" });
    expect(getStandaloneRun(result.runId)?.analyses[0].findings?.[0]).toMatchObject({ canonicalId: "CVE-2026-0002", component: "pkg:npm/demo@2.0.0", severity: "medium" });
  });

  it("rejects standalone uploads larger than 100 MiB", async () => {
    const file = new File(["{}"], "large.cdx.json", { type: "application/json" });
    Object.defineProperty(file, "size", { value: 100 * 1024 * 1024 + 1 });
    await expect(importStandaloneSbom(file)).rejects.toThrow("100 MiB 이하");
  });
});

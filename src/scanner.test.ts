import { describe, expect, test } from "bun:test";
import { scanDirectory } from "./scanner";
import { rules } from "./rules/index";

describe("scanDirectory", () => {
  test("finds vulnerabilities in the bundled examples", async () => {
    const result = await scanDirectory("examples", rules);
    expect(result.scannedFiles).toBeGreaterThan(0);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.summary.critical + result.summary.high).toBeGreaterThan(0);
  });
});

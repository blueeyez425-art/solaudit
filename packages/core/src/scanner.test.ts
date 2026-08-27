import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { scanDirectory, scanContent, scanFiles } from "./scanner";
import { rules } from "./rules/index";

const EXAMPLES_DIR = join(import.meta.dir, "../../../examples");

describe("scanDirectory", () => {
  test("finds vulnerabilities in the bundled examples", async () => {
    const result = await scanDirectory(EXAMPLES_DIR, rules);
    expect(result.scannedFiles).toBeGreaterThan(0);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.summary.critical + result.summary.high).toBeGreaterThan(0);
  });
});

describe("scanContent", () => {
  test("scans in-memory source with no filesystem access", () => {
    const src = `let x = ctx.accounts.vault.to_account_info();\ntoken::transfer(cpi_ctx, amount)?;`;
    const findings = scanContent(src, "virtual/lib.rs", rules);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].filePath).toBe("virtual/lib.rs");
  });

  test("returns no findings for clean source", () => {
    const src = `require!(ctx.accounts.authority.is_signer, ErrorCode::Unauthorized);\ntoken::transfer(cpi_ctx, amount)?;`;
    const findings = scanContent(src, "virtual/clean.rs", rules);
    expect(findings.length).toBe(0);
  });
});

describe("scanFiles", () => {
  test("aggregates findings and scannedFiles count across multiple in-memory files", () => {
    const result = scanFiles(
      [
        {
          path: "a.rs",
          content: `let x = ctx.accounts.vault.to_account_info();\ntoken::transfer(cpi_ctx, amount)?;`,
        },
        { path: "b.rs", content: `let pda = Pubkey::create_program_address(seeds, program_id)?;` },
        { path: "c.rs", content: `// nothing suspicious here` },
      ],
      rules
    );
    expect(result.scannedFiles).toBe(3);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.some((f) => f.filePath === "a.rs")).toBe(true);
    expect(result.findings.some((f) => f.filePath === "b.rs")).toBe(true);
    expect(result.findings.some((f) => f.filePath === "c.rs")).toBe(false);
  });

  test("returns empty result for empty file list", () => {
    const result = scanFiles([], rules);
    expect(result.scannedFiles).toBe(0);
    expect(result.findings.length).toBe(0);
  });
});

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import type { Finding, Rule, ScanResult } from "./types";

/** Run every rule against a single file's contents. */
export function scanFile(filePath: string, rules: Rule[]): Finding[] {
  const content = readFileSync(filePath, "utf8");
  const findings: Finding[] = [];

  for (const rule of rules) {
    try {
      const ruleFindings = rule.check(content, filePath);
      findings.push(...ruleFindings);
    } catch (err) {
      // A single misbehaving rule should never crash the whole scan.
      console.error(`[solaudit] rule ${rule.id} threw on ${filePath}: ${(err as Error).message}`);
    }
  }

  return findings.sort((a, b) => a.line - b.line);
}

function walk(dirPath: string, files: string[] = []): string[] {
  const entries = readdirSync(dirPath);

  for (const entry of entries) {
    if (entry === "node_modules" || entry === "target" || entry === ".git") continue;

    const fullPath = join(dirPath, entry);
    const stat = statSync(fullPath);

    if (stat.isDirectory()) {
      walk(fullPath, files);
    } else if (stat.isFile() && fullPath.endsWith(".rs")) {
      files.push(fullPath);
    }
  }

  return files;
}

function emptySummary() {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

function tallySummary(findings: Finding[]): ScanResult["summary"] {
  const summary = emptySummary();

  for (const finding of findings) {
    switch (finding.severity) {
      case "CRITICAL":
        summary.critical++;
        break;
      case "HIGH":
        summary.high++;
        break;
      case "MEDIUM":
        summary.medium++;
        break;
      case "LOW":
        summary.low++;
        break;
      case "INFO":
        summary.info++;
        break;
    }
  }

  return summary;
}

/** Recursively scan a directory (or a single file) for .rs files and aggregate findings. */
export async function scanDirectory(targetPath: string, rules: Rule[]): Promise<ScanResult> {
  const stat = statSync(targetPath);
  const rsFiles = stat.isDirectory() ? walk(targetPath) : targetPath.endsWith(".rs") ? [targetPath] : [];

  const allFindings: Finding[] = [];

  for (const file of rsFiles) {
    allFindings.push(...scanFile(file, rules));
  }

  const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  allFindings.sort((a, b) => {
    const sev = severityOrder[a.severity] - severityOrder[b.severity];
    if (sev !== 0) return sev;
    if (a.filePath !== b.filePath) return a.filePath.localeCompare(b.filePath);
    return a.line - b.line;
  });

  return {
    scannedFiles: rsFiles.length,
    findings: allFindings,
    summary: tallySummary(allFindings),
  };
}

/**
 * Baseline harness: runs SolAudit's deterministic rule engine against every
 * labeled sample in benchmark/samples/ and scores it against benchmark/labels.json.
 *
 * This measures what the *current, deterministic* SolAudit already catches on
 * its own, with no AI involved. It's the control group the AI-assisted eval
 * harness (run_llm_eval.ts) is compared against.
 *
 * Usage:
 *   bun benchmark/harness/run_baseline.ts
 */
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { scanContent } from "../../packages/core/src/scanner";
import { rules } from "../../packages/core/src/rules/index";

const __dirname = dirname(fileURLToPath(import.meta.url));
const BENCH_DIR = join(__dirname, "..");
const SAMPLES_DIR = join(BENCH_DIR, "samples");
const LABELS_PATH = join(BENCH_DIR, "labels.json");

interface LabelEntry {
  file: string;
  expectedRuleIds: string[];
  isKnownGap: boolean;
  vulnClass: string;
  notes: string;
}

interface SampleResult {
  file: string;
  expectedRuleIds: string[];
  foundRuleIds: string[];
  truePositives: string[];
  falsePositives: string[];
  falseNegatives: string[];
  isKnownGap: boolean;
  vulnClass: string;
}

function main() {
  const labelsRaw = JSON.parse(readFileSync(LABELS_PATH, "utf8")) as {
    samples: LabelEntry[];
  };

  const sampleFiles = new Set(readdirSync(SAMPLES_DIR));
  const results: SampleResult[] = [];

  for (const label of labelsRaw.samples) {
    if (!sampleFiles.has(label.file)) {
      console.error(`[benchmark] WARNING: labels.json references missing file ${label.file}`);
      continue;
    }

    const content = readFileSync(join(SAMPLES_DIR, label.file), "utf8");
    const findings = scanContent(content, label.file, rules);
    const foundRuleIds = [...new Set(findings.map((f) => f.ruleId))];

    const expectedSet = new Set(label.expectedRuleIds);
    const foundSet = new Set(foundRuleIds);

    results.push({
      file: label.file,
      expectedRuleIds: label.expectedRuleIds,
      foundRuleIds,
      truePositives: [...expectedSet].filter((id) => foundSet.has(id)),
      falsePositives: [...foundSet].filter((id) => !expectedSet.has(id)),
      falseNegatives: [...expectedSet].filter((id) => !foundSet.has(id)),
      isKnownGap: label.isKnownGap,
      vulnClass: label.vulnClass,
    });
  }

  let tp = 0;
  let fp = 0;
  let fn_ = 0;
  for (const r of results) {
    tp += r.truePositives.length;
    fp += r.falsePositives.length;
    fn_ += r.falseNegatives.length;
  }

  const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
  const recall = tp + fn_ === 0 ? 1 : tp / (tp + fn_);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);

  const knownGaps = results.filter((r) => r.isKnownGap);
  const gapsCorrectlyFlaggedZero = knownGaps.filter((r) => r.foundRuleIds.length === 0).length;

  console.log("=== SolAudit Deterministic Rule Engine — Benchmark Baseline ===\n");
  for (const r of results) {
    const status = r.falseNegatives.length === 0 && r.falsePositives.length === 0 ? "PASS" : "MISS";
    const gapTag = r.isKnownGap ? " [KNOWN GAP - not expected to be caught by rules]" : "";
    console.log(
      `[${status}] ${r.file}${gapTag}\n` +
        `        expected: ${r.expectedRuleIds.join(", ") || "(none)"}\n` +
        `        found:    ${r.foundRuleIds.join(", ") || "(none)"}`
    );
  }

  console.log("\n--- Aggregate (rule-engine detection quality) ---");
  console.log(`True positives:  ${tp}`);
  console.log(`False positives: ${fp}`);
  console.log(`False negatives: ${fn_}`);
  console.log(`Precision:       ${(precision * 100).toFixed(1)}%`);
  console.log(`Recall:          ${(recall * 100).toFixed(1)}%`);
  console.log(`F1:              ${(f1 * 100).toFixed(1)}%`);
  console.log(
    `\nKnown coverage gaps: ${knownGaps.length} sample(s) contain a real vulnerability class the ` +
      `deterministic ruleset cannot detect by design (${gapsCorrectlyFlaggedZero}/${knownGaps.length} ` +
      `correctly produced zero rule-based findings, as expected — this is the exact gap an ` +
      `AI-assisted review mode is meant to help close).`
  );

  const outPath = join(BENCH_DIR, "results_baseline.json");
  writeFileSync(
    outPath,
    JSON.stringify(
      {
        generatedAt: new Date().toISOString(),
        aggregate: { truePositives: tp, falsePositives: fp, falseNegatives: fn_, precision, recall, f1 },
        knownGaps: { total: knownGaps.length, correctlyEmpty: gapsCorrectlyFlaggedZero },
        samples: results,
      },
      null,
      2
    )
  );
  console.log(`\nFull results written to ${outPath}`);
}

main();

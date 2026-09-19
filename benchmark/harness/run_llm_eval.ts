/**
 * AI-assisted review evaluation harness.
 *
 * Sends every labeled sample in benchmark/samples/ to a chat-completion model
 * (any OpenAI-compatible endpoint) and asks it to report vulnerabilities as
 * structured JSON. Results are scored against benchmark/labels.json on two
 * axes:
 *
 *   1. Known-rule categories (SOL-001..SOL-008): does the model roughly agree
 *      with the deterministic engine? (sanity check / precision-recall vs.
 *      the same ground truth used for the baseline.)
 *   2. Known gaps (isKnownGap: true): vulnerability classes the deterministic
 *      engine cannot detect by design. This is the number that actually
 *      matters for justifying an AI-assisted review mode — it measures how
 *      many of those the model catches that the rule engine structurally
 *      cannot.
 *
 * This harness is model-agnostic by design: point it at any OpenAI-compatible
 * /chat/completions endpoint via LLM_BASE_URL / LLM_MODEL / LLM_API_KEY env
 * vars. It has been run against a free-tier OpenAI-compatible model to prove
 * the harness itself works end-to-end; swapping in an OpenAI model (once
 * grant credits are available) requires no code changes, only different env
 * vars.
 *
 * SECURITY NOTE: reads the API key only from the LLM_API_KEY environment
 * variable. Never hardcode, log, or write the key to any file.
 *
 * Usage:
 *   LLM_BASE_URL=https://api.openai.com/v1 \
 *   LLM_MODEL=gpt-4o-mini \
 *   LLM_API_KEY=sk-... \
 *   bun benchmark/harness/run_llm_eval.ts
 */
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const BENCH_DIR = join(__dirname, "..");
const SAMPLES_DIR = join(BENCH_DIR, "samples");
const LABELS_PATH = join(BENCH_DIR, "labels.json");

const LLM_BASE_URL = process.env.LLM_BASE_URL;
const LLM_MODEL = process.env.LLM_MODEL;
const LLM_API_KEY = process.env.LLM_API_KEY;

if (!LLM_BASE_URL || !LLM_MODEL || !LLM_API_KEY) {
  console.error(
    "Missing required env vars. Set LLM_BASE_URL, LLM_MODEL, and LLM_API_KEY " +
      "(e.g. LLM_BASE_URL=https://api.openai.com/v1 LLM_MODEL=gpt-4o-mini LLM_API_KEY=sk-...)."
  );
  process.exit(1);
}

interface LabelEntry {
  file: string;
  expectedRuleIds: string[];
  isKnownGap: boolean;
  vulnClass: string;
  notes: string;
}

interface ModelFinding {
  vulnClass: string;
  severity: string;
  line?: number;
  description: string;
}

const KNOWN_VULN_CLASSES = [
  "missing-signer-check",
  "unchecked-account-deserialization",
  "arbitrary-cpi",
  "missing-bump-canonicalization",
  "integer-overflow",
  "type-cosplay",
  "insecure-account-initialization",
  "missing-owner-check",
  "closed-account-revival",
  "duplicate-mutable-accounts",
  "missing-rent-exemption-check",
];

const SYSTEM_PROMPT = `You are a Solana/Anchor smart contract security auditor. Given a single Rust source file, identify security vulnerabilities. Respond with ONLY a JSON array (no markdown fences, no prose) of objects shaped like:
[{"vulnClass": "<short-kebab-case-category>", "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO", "line": <number or null>, "description": "<one sentence>"}]
Known category names to reuse when applicable (use your own kebab-case name if a finding doesn't fit any of these): ${KNOWN_VULN_CLASSES.join(", ")}.
If you find no issues, respond with an empty array: []`;

async function reviewSample(content: string): Promise<ModelFinding[]> {
  const res = await fetch(`${LLM_BASE_URL}/chat/completions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${LLM_API_KEY}`,
    },
    body: JSON.stringify({
      model: LLM_MODEL,
      temperature: 0,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content },
      ],
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`LLM request failed (${res.status}): ${body.slice(0, 300)}`);
  }

  const json = (await res.json()) as { choices: { message: { content: string } }[] };
  const raw = json.choices[0]?.message?.content ?? "[]";
  const cleaned = raw.trim().replace(/^```(json)?/i, "").replace(/```$/, "").trim();

  try {
    const parsed = JSON.parse(cleaned);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    console.error(`[benchmark] could not parse model output, treating as no findings:\n${raw.slice(0, 500)}`);
    return [];
  }
}

function matchesVulnClass(modelClass: string, expectedClass: string): boolean {
  const normalize = (s: string) => s.toLowerCase().replace(/[^a-z]/g, "");
  return normalize(modelClass).includes(normalize(expectedClass)) || normalize(expectedClass).includes(normalize(modelClass));
}

async function main() {
  const labelsRaw = JSON.parse(readFileSync(LABELS_PATH, "utf8")) as { samples: LabelEntry[] };
  const sampleFiles = new Set(readdirSync(SAMPLES_DIR));

  const results: {
    file: string;
    vulnClass: string;
    isKnownGap: boolean;
    modelFindings: ModelFinding[];
    caughtExpectedClass: boolean;
  }[] = [];

  console.log(`=== AI-Assisted Review Evaluation (model: ${LLM_MODEL}) ===\n`);

  const REQUEST_DELAY_MS = Number(process.env.LLM_REQUEST_DELAY_MS ?? "0");

  for (const label of labelsRaw.samples) {
    if (!sampleFiles.has(label.file)) continue;
    const content = readFileSync(join(SAMPLES_DIR, label.file), "utf8");

    if (REQUEST_DELAY_MS > 0) await new Promise((r) => setTimeout(r, REQUEST_DELAY_MS));

    let modelFindings: ModelFinding[] = [];
    try {
      modelFindings = await reviewSample(content);
    } catch (err) {
      console.error(`[benchmark] ${label.file}: ${(err as Error).message}`);
    }

    const caughtExpectedClass =
      label.vulnClass === "none"
        ? modelFindings.length === 0
        : modelFindings.some((f) => matchesVulnClass(f.vulnClass, label.vulnClass));

    results.push({
      file: label.file,
      vulnClass: label.vulnClass,
      isKnownGap: label.isKnownGap,
      modelFindings,
      caughtExpectedClass,
    });

    const tag = label.isKnownGap ? " [KNOWN GAP]" : "";
    console.log(
      `${caughtExpectedClass ? "[HIT] " : "[MISS]"} ${label.file}${tag} (expected: ${label.vulnClass})\n` +
        `        model reported: ${modelFindings.map((f) => f.vulnClass).join(", ") || "(none)"}`
    );
  }

  const gapResults = results.filter((r) => r.isKnownGap);
  const gapsCaught = gapResults.filter((r) => r.caughtExpectedClass).length;
  const nonGapResults = results.filter((r) => !r.isKnownGap);
  const nonGapCaught = nonGapResults.filter((r) => r.caughtExpectedClass).length;

  console.log("\n--- Aggregate ---");
  console.log(`Rule-covered categories: ${nonGapCaught}/${nonGapResults.length} agreed with ground truth`);
  console.log(
    `Known coverage gaps caught by AI: ${gapsCaught}/${gapResults.length} — these are vulnerabilities the ` +
      `deterministic rule engine cannot detect at all, so every one caught here is pure added value from ` +
      `AI-assisted review.`
  );

  const outPath = join(BENCH_DIR, "results_llm_eval.json");
  writeFileSync(
    outPath,
    JSON.stringify(
      {
        generatedAt: new Date().toISOString(),
        model: LLM_MODEL,
        aggregate: {
          ruleCoveredAgreement: `${nonGapCaught}/${nonGapResults.length}`,
          knownGapsCaught: `${gapsCaught}/${gapResults.length}`,
        },
        samples: results,
      },
      null,
      2
    )
  );
  console.log(`\nFull results written to ${outPath}`);
}

main();

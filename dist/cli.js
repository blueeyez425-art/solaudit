#!/usr/bin/env node

// src/rules/index.ts
function makeFinding(rule, filePath, line, snippet, description) {
  return {
    ruleId: rule.id,
    ruleName: rule.name,
    severity: rule.severity,
    filePath,
    line,
    snippet: snippet.trim(),
    description
  };
}
function splitLines(fileContent) {
  return fileContent.split(/\r\n|\r|\n/);
}
var missingSignerCheck = {
  id: "SOL-001",
  name: "Missing Signer Check",
  severity: "CRITICAL",
  description: "A transfer or mint_to call was found without an is_signer / Signer<'info> check within the preceding 10 lines. Add a `Signer<'info>` account type or an explicit `require!(ctx.accounts.authority.is_signer, ...)` check before authorizing fund movement.",
  check(fileContent, filePath) {
    const findings = [];
    const lines = splitLines(fileContent);
    const callPattern = /\b(transfer|mint_to)\s*\(/;
    lines.forEach((line, idx) => {
      if (!callPattern.test(line))
        return;
      if (!line.includes("ctx.accounts.") && !fileContent.includes("ctx.accounts."))
        return;
      const windowStart = Math.max(0, idx - 10);
      const window = lines.slice(windowStart, idx + 1).join(`
`);
      const hasSignerEvidence = /is_signer/.test(window) || /Signer<\s*'info\s*>/.test(window) || /#\[account\([^)]*signer[^)]*\)\]/i.test(window);
      if (!hasSignerEvidence) {
        findings.push(makeFinding(missingSignerCheck, filePath, idx + 1, line, "Verify the authority/owner account is a Signer or explicitly check `.is_signer` before transferring or minting tokens."));
      }
    });
    return findings;
  }
};
var uncheckedDeserialization = {
  id: "SOL-002",
  name: "Unchecked Account Deserialization",
  severity: "HIGH",
  description: "`Account::try_from` / `AccountLoader::try_from` was used to manually deserialize account data without a corresponding `#[account(...)]` constraint validating ownership or discriminator. Prefer typed `Account<'info, T>` fields validated by Anchor, or add explicit owner/discriminator checks.",
  check(fileContent, filePath) {
    const findings = [];
    const lines = splitLines(fileContent);
    const pattern = /(Account|AccountLoader)::try_from\s*\(/;
    lines.forEach((line, idx) => {
      if (!pattern.test(line))
        return;
      const prevLine = idx > 0 ? lines[idx - 1] : "";
      const hasConstraint = /#\[account\(/.test(prevLine) || /#\[account\(/.test(line);
      if (!hasConstraint) {
        findings.push(makeFinding(uncheckedDeserialization, filePath, idx + 1, line, "Add a `#[account(constraint = ..., owner = ...)]` attribute, or replace with a typed `Account<'info, T>` field so Anchor validates ownership and discriminator automatically."));
      }
    });
    return findings;
  }
};
var arbitraryCpi = {
  id: "SOL-003",
  name: "Arbitrary CPI (Cross-Program Invocation)",
  severity: "HIGH",
  description: "`invoke` or `invoke_signed` is called with a program id sourced from a user-supplied account rather than a hardcoded/verified program ID. This allows an attacker to substitute a malicious program. Add a `constraint = program.key() == expected_program::ID` check or use Anchor's `Program<'info, T>` type.",
  check(fileContent, filePath) {
    const findings = [];
    const lines = splitLines(fileContent);
    const cpiPattern = /\b(invoke|invoke_signed)\s*\(/;
    lines.forEach((line, idx) => {
      if (!cpiPattern.test(line))
        return;
      const windowStart = Math.max(0, idx - 3);
      const windowEnd = Math.min(lines.length, idx + 4);
      const window = lines.slice(windowStart, windowEnd).join(`
`);
      const usesAccountsAsProgram = /ctx\.accounts\.\w+\.(to_account_info\(\)|key\(\))/.test(window) && !/Program<\s*'info/.test(window);
      if (usesAccountsAsProgram) {
        findings.push(makeFinding(arbitraryCpi, filePath, idx + 1, line, "Validate the target program ID against a known constant (e.g. `token_program.key() == spl_token::ID`) or type the account as `Program<'info, T>` before invoking it."));
      }
    });
    return findings;
  }
};
var missingBumpCanonicalization = {
  id: "SOL-004",
  name: "Missing Bump Seed Canonicalization",
  severity: "HIGH",
  description: "PDA bump seeds must be derived via `find_program_address` and the canonical bump stored/validated on-chain. Calling `create_program_address` directly, or discarding the bump returned by `find_program_address`, allows bump-seed forgery attacks.",
  check(fileContent, filePath) {
    const findings = [];
    const lines = splitLines(fileContent);
    lines.forEach((line, idx) => {
      if (/create_program_address\s*\(/.test(line) && !/find_program_address/.test(line)) {
        findings.push(makeFinding(missingBumpCanonicalization, filePath, idx + 1, line, "Use `Pubkey::find_program_address` to derive the canonical bump instead of calling `create_program_address` directly with a caller-supplied bump."));
        return;
      }
      const fpaMatch = line.match(/let\s+(\([^)]*\)|\w+)\s*=\s*[\w:]*find_program_address\s*\(/);
      if (fpaMatch) {
        const binding = fpaMatch[1];
        const bindsBump = /\(\s*\w+\s*,\s*\w+\s*\)/.test(binding);
        if (!bindsBump) {
          findings.push(makeFinding(missingBumpCanonicalization, filePath, idx + 1, line, "Destructure and store the bump returned by `find_program_address` (e.g. `let (pda, bump) = ...`) and persist/validate it instead of discarding it."));
        }
      }
    });
    return findings;
  }
};
var integerOverflowRisk = {
  id: "SOL-005",
  name: "Integer Overflow Risk",
  severity: "MEDIUM",
  description: "Raw arithmetic (`+`, `-`, `*`) was performed on u64/u128-typed values without using checked or saturating arithmetic. Unchecked overflow can wrap silently in release builds without `overflow-checks = true`, corrupting balances. Use `.checked_add`/`.checked_sub`/`.checked_mul` or `saturating_*` and handle the `None` case.",
  check(fileContent, filePath) {
    const findings = [];
    const lines = splitLines(fileContent);
    const arithmeticPattern = /\b(\w*(amount|balance|supply|total|shares|stake)\w*)\s*(\+|\-|\*)\s*\w/i;
    const alreadySafe = /checked_(add|sub|mul|div)|saturating_(add|sub|mul)|wrapping_(add|sub|mul)/;
    lines.forEach((line, idx) => {
      if (alreadySafe.test(line))
        return;
      if (line.trim().startsWith("//"))
        return;
      if (arithmeticPattern.test(line)) {
        findings.push(makeFinding(integerOverflowRisk, filePath, idx + 1, line, "Replace raw arithmetic with `.checked_add()/.checked_sub()/.checked_mul()` (propagating errors via `ok_or(ErrorCode::MathOverflow)?`) or `saturating_*` equivalents."));
      }
    });
    return findings;
  }
};
var typeCosplay = {
  id: "SOL-006",
  name: "Type Cosplay / Missing Discriminator Check",
  severity: "HIGH",
  description: "Account data is manually deserialized with `try_from_slice` without validating an 8-byte Anchor discriminator or account type tag first. An attacker can pass an account of a different type with a compatible byte layout ('type cosplay') to bypass logic. Use Anchor's `Account<'info, T>` wrapper, which enforces discriminator checks automatically, or manually compare the first 8 bytes against `T::DISCRIMINATOR`.",
  check(fileContent, filePath) {
    const findings = [];
    const lines = splitLines(fileContent);
    lines.forEach((line, idx) => {
      if (!/try_from_slice\s*\(/.test(line))
        return;
      const windowStart = Math.max(0, idx - 5);
      const window = lines.slice(windowStart, idx + 1).join(`
`);
      const usesTypedAccountWrapper = /Account<\s*'info/.test(window);
      const checksDiscriminator = /discriminator/i.test(window);
      if (!usesTypedAccountWrapper && !checksDiscriminator) {
        findings.push(makeFinding(typeCosplay, filePath, idx + 1, line, "Verify the account's 8-byte Anchor discriminator matches the expected type before trusting deserialized fields, or switch to Anchor's `Account<'info, T>` type."));
      }
    });
    return findings;
  }
};
var insecureInit = {
  id: "SOL-007",
  name: "Insecure Account Initialization",
  severity: "MEDIUM",
  description: "An `#[account(init, ...)]` constraint is missing `payer` and/or `space`. Anchor requires both to safely allocate and rent-exempt a new account; omitting them causes a compile error in modern Anchor, but in hand-rolled or macro-generated code this pattern indicates the constraint block was copy-pasted incompletely and should be reviewed.",
  check(fileContent, filePath) {
    const findings = [];
    const blockRegex = /#\[account\(([\s\S]*?)\)\]/g;
    let match;
    while ((match = blockRegex.exec(fileContent)) !== null) {
      const block = match[1];
      if (!/\binit\b/.test(block))
        continue;
      const hasPayer = /\bpayer\s*=/.test(block);
      const hasSpace = /\bspace\s*=/.test(block);
      if (!hasPayer || !hasSpace) {
        const upToMatch = fileContent.slice(0, match.index);
        const line = upToMatch.split(/\r\n|\r|\n/).length;
        const missing = [!hasPayer && "payer", !hasSpace && "space"].filter(Boolean).join(" and ");
        findings.push(makeFinding(insecureInit, filePath, line, `#[account(${block.trim()})]`, `Add the missing \`${missing}\` argument(s) to this init constraint so Anchor allocates and rent-exempts the account correctly.`));
      }
    }
    return findings;
  }
};
var missingOwnerCheck = {
  id: "SOL-008",
  name: "Missing Owner Check",
  severity: "LOW",
  description: "A raw `AccountInfo` field is accessed via `ctx.accounts.` without a nearby `.owner` comparison. Raw `AccountInfo` accounts bypass Anchor's automatic ownership validation, so the program must manually verify `account.owner == expected_program_id` before trusting its data.",
  check(fileContent, filePath) {
    const findings = [];
    const lines = splitLines(fileContent);
    const rawFieldPattern = /pub\s+(\w+)\s*:\s*AccountInfo<\s*'info\s*>/;
    const rawFields = new Set;
    lines.forEach((line) => {
      const m = line.match(rawFieldPattern);
      if (m)
        rawFields.add(m[1]);
    });
    if (rawFields.size === 0)
      return findings;
    lines.forEach((line, idx) => {
      for (const field of rawFields) {
        const usagePattern = new RegExp(`ctx\\.accounts\\.${field}\\b`);
        if (!usagePattern.test(line))
          continue;
        const windowStart = Math.max(0, idx - 5);
        const windowEnd = Math.min(lines.length, idx + 6);
        const window = lines.slice(windowStart, windowEnd).join(`
`);
        const hasOwnerCheck = new RegExp(`${field}\\.owner`).test(window) || /\.owner\s*==/.test(window);
        if (!hasOwnerCheck) {
          findings.push(makeFinding(missingOwnerCheck, filePath, idx + 1, line, `Add an explicit \`require!(ctx.accounts.${field}.owner == &expected_program_id, ErrorCode::InvalidOwner)\` check before using this raw AccountInfo.`));
        }
      }
    });
    return findings;
  }
};
var rules = [
  missingSignerCheck,
  uncheckedDeserialization,
  arbitraryCpi,
  missingBumpCanonicalization,
  integerOverflowRisk,
  typeCosplay,
  insecureInit,
  missingOwnerCheck
];

// src/scanner.ts
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
function scanFile(filePath, rules2) {
  const content = readFileSync(filePath, "utf8");
  const findings = [];
  for (const rule of rules2) {
    try {
      const ruleFindings = rule.check(content, filePath);
      findings.push(...ruleFindings);
    } catch (err) {
      console.error(`[solaudit] rule ${rule.id} threw on ${filePath}: ${err.message}`);
    }
  }
  return findings.sort((a, b) => a.line - b.line);
}
function walk(dirPath, files = []) {
  const entries = readdirSync(dirPath);
  for (const entry of entries) {
    if (entry === "node_modules" || entry === "target" || entry === ".git")
      continue;
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
function tallySummary(findings) {
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
async function scanDirectory(targetPath, rules2) {
  const stat = statSync(targetPath);
  const rsFiles = stat.isDirectory() ? walk(targetPath) : targetPath.endsWith(".rs") ? [targetPath] : [];
  const allFindings = [];
  for (const file of rsFiles) {
    allFindings.push(...scanFile(file, rules2));
  }
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  allFindings.sort((a, b) => {
    const sev = severityOrder[a.severity] - severityOrder[b.severity];
    if (sev !== 0)
      return sev;
    if (a.filePath !== b.filePath)
      return a.filePath.localeCompare(b.filePath);
    return a.line - b.line;
  });
  return {
    scannedFiles: rsFiles.length,
    findings: allFindings,
    summary: tallySummary(allFindings)
  };
}

// src/output/report.ts
var RESET = "\x1B[0m";
var BOLD = "\x1B[1m";
var DIM = "\x1B[2m";
var RED = "\x1B[31m";
var ORANGE = "\x1B[38;5;208m";
var YELLOW = "\x1B[33m";
var BLUE = "\x1B[34m";
var GRAY = "\x1B[90m";
var CYAN = "\x1B[36m";
var GREEN = "\x1B[32m";
function colorFor(severity) {
  switch (severity) {
    case "CRITICAL":
      return RED;
    case "HIGH":
      return ORANGE;
    case "MEDIUM":
      return YELLOW;
    case "LOW":
      return BLUE;
    default:
      return GRAY;
  }
}
function badge(severity) {
  const color = colorFor(severity);
  return `${color}${BOLD} ${severity.padEnd(8)} ${RESET}`;
}
var SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
function printReport(result) {
  const timestamp = new Date().toISOString();
  console.log(`${BOLD}${CYAN}SolAudit${RESET} ${DIM}v0.1.0 — static analysis for Anchor/Solana programs${RESET}`);
  console.log(`${DIM}Scanned ${result.scannedFiles} file(s) at ${timestamp}${RESET}`);
  console.log(`${GRAY}${"─".repeat(70)}${RESET}`);
  if (result.findings.length === 0) {
    console.log(`${GREEN}${BOLD}✔ No issues found.${RESET}`);
  } else {
    const grouped = new Map;
    for (const finding of result.findings) {
      const bucket = grouped.get(finding.severity) ?? [];
      bucket.push(finding);
      grouped.set(finding.severity, bucket);
    }
    for (const severity of SEVERITY_ORDER) {
      const findings = grouped.get(severity);
      if (!findings || findings.length === 0)
        continue;
      console.log("");
      console.log(`${colorFor(severity)}${BOLD}${severity} (${findings.length})${RESET}`);
      for (const finding of findings) {
        console.log(`  ${badge(finding.severity)} ${BOLD}${finding.ruleId}${RESET} ${finding.ruleName}`);
        console.log(`    ${DIM}${finding.filePath}:${finding.line}${RESET}`);
        console.log(`    ${GRAY}│${RESET} ${finding.snippet}`);
        console.log(`    ${GRAY}└─${RESET} ${finding.description}`);
      }
    }
  }
  console.log("");
  console.log(`${GRAY}${"─".repeat(70)}${RESET}`);
  console.log(`${BOLD}Summary${RESET}`);
  console.log(`  ${RED}${BOLD}CRITICAL${RESET} ${result.summary.critical}   ` + `${ORANGE}${BOLD}HIGH${RESET} ${result.summary.high}   ` + `${YELLOW}${BOLD}MEDIUM${RESET} ${result.summary.medium}   ` + `${BLUE}${BOLD}LOW${RESET} ${result.summary.low}   ` + `${GRAY}${BOLD}INFO${RESET} ${result.summary.info}`);
  console.log(`  ${DIM}Total findings: ${result.findings.length} across ${result.scannedFiles} file(s)${RESET}`);
  console.log("");
}

// src/output/sarif.ts
var SARIF_VERSION = "2.1.0";
var TOOL_VERSION = "0.1.0";
function severityToSarifLevel(severity) {
  switch (severity) {
    case "CRITICAL":
    case "HIGH":
      return "error";
    case "MEDIUM":
      return "warning";
    default:
      return "note";
  }
}
function toFileUri(filePath) {
  return filePath.replace(/\\/g, "/").replace(/^\.\//, "");
}
function toSarif(result) {
  const sarifRules = rules.map((rule) => ({
    id: rule.id,
    name: rule.name.replace(/\s+/g, ""),
    shortDescription: { text: rule.name },
    fullDescription: { text: rule.description },
    defaultConfiguration: { level: severityToSarifLevel(rule.severity) },
    properties: { severity: rule.severity }
  }));
  const sarifResults = result.findings.map((finding) => ({
    ruleId: finding.ruleId,
    level: severityToSarifLevel(finding.severity),
    message: { text: `${finding.description} (${finding.snippet})` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: toFileUri(finding.filePath) },
          region: { startLine: Math.max(1, finding.line) }
        }
      }
    ]
  }));
  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: "SolAudit",
            informationUri: "https://github.com/blueeyez425-art/solaudit",
            version: TOOL_VERSION,
            rules: sarifRules
          }
        },
        results: sarifResults
      }
    ]
  };
}

// src/cli.ts
var SEVERITY_RANK = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4
};
function printHelp() {
  console.log(`SolAudit — static analysis CLI for Anchor/Solana programs

Usage:
  solaudit [path] [options]

Arguments:
  path                    File or directory to scan (default: current directory)

Options:
  --json                  Print raw scan results as JSON
  --sarif                 Print scan results as SARIF 2.1.0 JSON (for GitHub code scanning)
  --min-severity <level>  Only report findings at or above this severity
                          (CRITICAL | HIGH | MEDIUM | LOW | INFO)
  --help                  Show this help message

Examples:
  solaudit ./program
  bun run solaudit ./programs/vault --min-severity HIGH
  solaudit . --sarif > results.sarif

Exit codes:
  0   No CRITICAL or HIGH severity findings
  1   One or more CRITICAL or HIGH severity findings were found
`);
}
async function main() {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) {
    printHelp();
    process.exit(0);
  }
  const wantsJson = args.includes("--json");
  const wantsSarif = args.includes("--sarif");
  let minSeverity = "INFO";
  const minSeverityIdx = args.indexOf("--min-severity");
  if (minSeverityIdx !== -1) {
    const value = (args[minSeverityIdx + 1] || "").toUpperCase();
    if (value in SEVERITY_RANK) {
      minSeverity = value;
    } else {
      console.error(`[solaudit] invalid --min-severity value: "${args[minSeverityIdx + 1]}"`);
      process.exit(2);
    }
  }
  const positional = args.filter((arg, idx) => {
    if (arg.startsWith("-"))
      return false;
    if (args[idx - 1] === "--min-severity")
      return false;
    return true;
  });
  const targetPath = positional[0] || ".";
  const result = await scanDirectory(targetPath, rules);
  result.findings = result.findings.filter((finding) => SEVERITY_RANK[finding.severity] <= SEVERITY_RANK[minSeverity]);
  if (wantsSarif) {
    console.log(JSON.stringify(toSarif(result), null, 2));
  } else if (wantsJson) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printReport(result);
  }
  const hasBlockingFindings = result.findings.some((f) => f.severity === "CRITICAL" || f.severity === "HIGH");
  process.exit(hasBlockingFindings ? 1 : 0);
}
main().catch((err) => {
  console.error(`[solaudit] fatal error: ${err.message}`);
  process.exit(2);
});

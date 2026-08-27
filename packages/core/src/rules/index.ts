import type { Finding, Rule, Severity } from "../types";

function makeFinding(
  rule: { id: string; name: string; severity: Severity },
  filePath: string,
  line: number,
  snippet: string,
  description: string
): Finding {
  return {
    ruleId: rule.id,
    ruleName: rule.name,
    severity: rule.severity,
    filePath,
    line,
    snippet: snippet.trim(),
    description,
  };
}

function splitLines(fileContent: string): string[] {
  return fileContent.split(/\r\n|\r|\n/);
}

/** SOL-001: Missing Signer Check */
const missingSignerCheck: Rule = {
  id: "SOL-001",
  name: "Missing Signer Check",
  severity: "CRITICAL",
  description:
    "A transfer or mint_to call was found without an is_signer / Signer<'info> check within the preceding 10 lines. Add a `Signer<'info>` account type or an explicit `require!(ctx.accounts.authority.is_signer, ...)` check before authorizing fund movement.",
  check(fileContent, filePath) {
    const findings: Finding[] = [];
    const lines = splitLines(fileContent);
    const callPattern = /\b(transfer|mint_to)\s*\(/;

    lines.forEach((line, idx) => {
      if (!callPattern.test(line)) return;
      if (!line.includes("ctx.accounts.") && !fileContent.includes("ctx.accounts.")) return;

      const windowStart = Math.max(0, idx - 10);
      const window = lines.slice(windowStart, idx + 1).join("\n");
      const hasSignerEvidence =
        /is_signer/.test(window) ||
        /Signer<\s*'info\s*>/.test(window) ||
        /#\[account\([^)]*signer[^)]*\)\]/i.test(window);

      if (!hasSignerEvidence) {
        findings.push(
          makeFinding(
            missingSignerCheck,
            filePath,
            idx + 1,
            line,
            "Verify the authority/owner account is a Signer or explicitly check `.is_signer` before transferring or minting tokens."
          )
        );
      }
    });

    return findings;
  },
};

/** SOL-002: Unchecked Account Deserialization */
const uncheckedDeserialization: Rule = {
  id: "SOL-002",
  name: "Unchecked Account Deserialization",
  severity: "HIGH",
  description:
    "`Account::try_from` / `AccountLoader::try_from` was used to manually deserialize account data without a corresponding `#[account(...)]` constraint validating ownership or discriminator. Prefer typed `Account<'info, T>` fields validated by Anchor, or add explicit owner/discriminator checks.",
  check(fileContent, filePath) {
    const findings: Finding[] = [];
    const lines = splitLines(fileContent);
    const pattern = /(Account|AccountLoader)::try_from\s*\(/;

    lines.forEach((line, idx) => {
      if (!pattern.test(line)) return;
      const prevLine = idx > 0 ? lines[idx - 1] : "";
      const hasConstraint =
        /#\[account\(/.test(prevLine) || /#\[account\(/.test(line);

      if (!hasConstraint) {
        findings.push(
          makeFinding(
            uncheckedDeserialization,
            filePath,
            idx + 1,
            line,
            "Add a `#[account(constraint = ..., owner = ...)]` attribute, or replace with a typed `Account<'info, T>` field so Anchor validates ownership and discriminator automatically."
          )
        );
      }
    });

    return findings;
  },
};

/** SOL-003: Arbitrary CPI */
const arbitraryCpi: Rule = {
  id: "SOL-003",
  name: "Arbitrary CPI (Cross-Program Invocation)",
  severity: "HIGH",
  description:
    "`invoke` or `invoke_signed` is called with a program id sourced from a user-supplied account rather than a hardcoded/verified program ID. This allows an attacker to substitute a malicious program. Add a `constraint = program.key() == expected_program::ID` check or use Anchor's `Program<'info, T>` type.",
  check(fileContent, filePath) {
    const findings: Finding[] = [];
    const lines = splitLines(fileContent);
    const cpiPattern = /\b(invoke|invoke_signed)\s*\(/;

    lines.forEach((line, idx) => {
      if (!cpiPattern.test(line)) return;

      const windowStart = Math.max(0, idx - 3);
      const windowEnd = Math.min(lines.length, idx + 4);
      const window = lines.slice(windowStart, windowEnd).join("\n");

      const usesAccountsAsProgram =
        /ctx\.accounts\.\w+\.(to_account_info\(\)|key\(\))/.test(window) &&
        !/Program<\s*'info/.test(window);

      if (usesAccountsAsProgram) {
        findings.push(
          makeFinding(
            arbitraryCpi,
            filePath,
            idx + 1,
            line,
            "Validate the target program ID against a known constant (e.g. `token_program.key() == spl_token::ID`) or type the account as `Program<'info, T>` before invoking it."
          )
        );
      }
    });

    return findings;
  },
};

/** SOL-004: Missing Bump Seed Canonicalization */
const missingBumpCanonicalization: Rule = {
  id: "SOL-004",
  name: "Missing Bump Seed Canonicalization",
  severity: "HIGH",
  description:
    "PDA bump seeds must be derived via `find_program_address` and the canonical bump stored/validated on-chain. Calling `create_program_address` directly, or discarding the bump returned by `find_program_address`, allows bump-seed forgery attacks.",
  check(fileContent, filePath) {
    const findings: Finding[] = [];
    const lines = splitLines(fileContent);

    lines.forEach((line, idx) => {
      if (/create_program_address\s*\(/.test(line) && !/find_program_address/.test(line)) {
        findings.push(
          makeFinding(
            missingBumpCanonicalization,
            filePath,
            idx + 1,
            line,
            "Use `Pubkey::find_program_address` to derive the canonical bump instead of calling `create_program_address` directly with a caller-supplied bump."
          )
        );
        return;
      }

      const fpaMatch = line.match(/let\s+(\([^)]*\)|\w+)\s*=\s*[\w:]*find_program_address\s*\(/);
      if (fpaMatch) {
        const binding = fpaMatch[1];
        const bindsBump = /\(\s*\w+\s*,\s*\w+\s*\)/.test(binding);
        if (!bindsBump) {
          findings.push(
            makeFinding(
              missingBumpCanonicalization,
              filePath,
              idx + 1,
              line,
              "Destructure and store the bump returned by `find_program_address` (e.g. `let (pda, bump) = ...`) and persist/validate it instead of discarding it."
            )
          );
        }
      }
    });

    return findings;
  },
};

/** SOL-005: Integer Overflow Risk */
const integerOverflowRisk: Rule = {
  id: "SOL-005",
  name: "Integer Overflow Risk",
  severity: "MEDIUM",
  description:
    "Raw arithmetic (`+`, `-`, `*`) was performed on u64/u128-typed values without using checked or saturating arithmetic. Unchecked overflow can wrap silently in release builds without `overflow-checks = true`, corrupting balances. Use `.checked_add`/`.checked_sub`/`.checked_mul` or `saturating_*` and handle the `None` case.",
  check(fileContent, filePath) {
    const findings: Finding[] = [];
    const lines = splitLines(fileContent);
    const arithmeticPattern = /\b(\w*(amount|balance|supply|total|shares|stake)\w*)\s*(\+|\-|\*)\s*\w/i;
    const alreadySafe = /checked_(add|sub|mul|div)|saturating_(add|sub|mul)|wrapping_(add|sub|mul)/;

    lines.forEach((line, idx) => {
      if (alreadySafe.test(line)) return;
      if (line.trim().startsWith("//")) return;
      if (arithmeticPattern.test(line)) {
        findings.push(
          makeFinding(
            integerOverflowRisk,
            filePath,
            idx + 1,
            line,
            "Replace raw arithmetic with `.checked_add()/.checked_sub()/.checked_mul()` (propagating errors via `ok_or(ErrorCode::MathOverflow)?`) or `saturating_*` equivalents."
          )
        );
      }
    });

    return findings;
  },
};

/** SOL-006: Type Cosplay / Missing Discriminator Check */
const typeCosplay: Rule = {
  id: "SOL-006",
  name: "Type Cosplay / Missing Discriminator Check",
  severity: "HIGH",
  description:
    "Account data is manually deserialized with `try_from_slice` without validating an 8-byte Anchor discriminator or account type tag first. An attacker can pass an account of a different type with a compatible byte layout ('type cosplay') to bypass logic. Use Anchor's `Account<'info, T>` wrapper, which enforces discriminator checks automatically, or manually compare the first 8 bytes against `T::DISCRIMINATOR`.",
  check(fileContent, filePath) {
    const findings: Finding[] = [];
    const lines = splitLines(fileContent);

    lines.forEach((line, idx) => {
      if (!/try_from_slice\s*\(/.test(line)) return;

      const windowStart = Math.max(0, idx - 5);
      const window = lines.slice(windowStart, idx + 1).join("\n");
      const usesTypedAccountWrapper = /Account<\s*'info/.test(window);
      const checksDiscriminator = /discriminator/i.test(window);

      if (!usesTypedAccountWrapper && !checksDiscriminator) {
        findings.push(
          makeFinding(
            typeCosplay,
            filePath,
            idx + 1,
            line,
            "Verify the account's 8-byte Anchor discriminator matches the expected type before trusting deserialized fields, or switch to Anchor's `Account<'info, T>` type."
          )
        );
      }
    });

    return findings;
  },
};

/** SOL-007: Insecure Account Initialization */
const insecureInit: Rule = {
  id: "SOL-007",
  name: "Insecure Account Initialization",
  severity: "MEDIUM",
  description:
    "An `#[account(init, ...)]` constraint is missing `payer` and/or `space`. Anchor requires both to safely allocate and rent-exempt a new account; omitting them causes a compile error in modern Anchor, but in hand-rolled or macro-generated code this pattern indicates the constraint block was copy-pasted incompletely and should be reviewed.",
  check(fileContent, filePath) {
    const findings: Finding[] = [];
    // Match #[account(...)] blocks, possibly spanning multiple lines.
    const blockRegex = /#\[account\(([\s\S]*?)\)\]/g;
    let match: RegExpExecArray | null;

    while ((match = blockRegex.exec(fileContent)) !== null) {
      const block = match[1];
      if (!/\binit\b/.test(block)) continue;

      const hasPayer = /\bpayer\s*=/.test(block);
      const hasSpace = /\bspace\s*=/.test(block);

      if (!hasPayer || !hasSpace) {
        const upToMatch = fileContent.slice(0, match.index);
        const line = upToMatch.split(/\r\n|\r|\n/).length;
        const missing = [!hasPayer && "payer", !hasSpace && "space"].filter(Boolean).join(" and ");
        findings.push(
          makeFinding(
            insecureInit,
            filePath,
            line,
            `#[account(${block.trim()})]`,
            `Add the missing \`${missing}\` argument(s) to this init constraint so Anchor allocates and rent-exempts the account correctly.`
          )
        );
      }
    }

    return findings;
  },
};

/** SOL-008: Missing Owner Check */
const missingOwnerCheck: Rule = {
  id: "SOL-008",
  name: "Missing Owner Check",
  severity: "LOW",
  description:
    "A raw `AccountInfo` field is accessed via `ctx.accounts.` without a nearby `.owner` comparison. Raw `AccountInfo` accounts bypass Anchor's automatic ownership validation, so the program must manually verify `account.owner == expected_program_id` before trusting its data.",
  check(fileContent, filePath) {
    const findings: Finding[] = [];
    const lines = splitLines(fileContent);

    // Find field declarations typed as raw AccountInfo inside #[derive(Accounts)] structs.
    const rawFieldPattern = /pub\s+(\w+)\s*:\s*AccountInfo<\s*'info\s*>/;
    const rawFields = new Set<string>();
    lines.forEach((line) => {
      const m = line.match(rawFieldPattern);
      if (m) rawFields.add(m[1]);
    });

    if (rawFields.size === 0) return findings;

    lines.forEach((line, idx) => {
      for (const field of rawFields) {
        const usagePattern = new RegExp(`ctx\\.accounts\\.${field}\\b`);
        if (!usagePattern.test(line)) continue;

        const windowStart = Math.max(0, idx - 5);
        const windowEnd = Math.min(lines.length, idx + 6);
        const window = lines.slice(windowStart, windowEnd).join("\n");
        const hasOwnerCheck = new RegExp(`${field}\\.owner`).test(window) || /\.owner\s*==/.test(window);

        if (!hasOwnerCheck) {
          findings.push(
            makeFinding(
              missingOwnerCheck,
              filePath,
              idx + 1,
              line,
              `Add an explicit \`require!(ctx.accounts.${field}.owner == &expected_program_id, ErrorCode::InvalidOwner)\` check before using this raw AccountInfo.`
            )
          );
        }
      }
    });

    return findings;
  },
};

export const rules: Rule[] = [
  missingSignerCheck,
  uncheckedDeserialization,
  arbitraryCpi,
  missingBumpCanonicalization,
  integerOverflowRisk,
  typeCosplay,
  insecureInit,
  missingOwnerCheck,
];

export default rules;

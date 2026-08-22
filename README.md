# SolAudit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![npm version](https://img.shields.io/badge/npm-v0.1.0-blue.svg)](https://www.npmjs.com/package/solaudit)
[![build](https://img.shields.io/badge/build-passing-brightgreen.svg)](./.github/workflows/ci.yml)

**A zero-dependency, static-analysis CLI that scans Anchor/Solana Rust programs for the vulnerability patterns behind the most common on-chain exploits.**

SolAudit reads your `.rs` source files, applies a set of pattern-matching security rules (missing signer checks, arbitrary CPIs, unchecked deserialization, integer overflow, and more), and gives you an actionable report in seconds — with no external dependencies, no RPC calls, and no build step required to run it.

---

## Install

```bash
# Run instantly with npx (no install)
npx solaudit ./program

# Or install globally with Bun
bun add -g solaudit
solaudit ./program

# Or clone and run from source
git clone https://github.com/blueeyez425-art/solaudit.git
cd solaudit
bun run solaudit ./examples
```

## Usage

```bash
solaudit [path] [options]
```

| Flag | Description |
|---|---|
| `--json` | Print raw scan results as JSON |
| `--sarif` | Print results as SARIF 2.1.0 (for GitHub Code Scanning) |
| `--min-severity <level>` | Only report findings at or above `CRITICAL`\|`HIGH`\|`MEDIUM`\|`LOW`\|`INFO` |
| `--help` | Show usage |

### Example

```bash
$ solaudit ./examples
```

```
SolAudit v0.1.0 — static analysis for Anchor/Solana programs
Scanned 1 file(s) at 2026-08-22T18:32:37.205Z
──────────────────────────────────────────────────────────────────────

CRITICAL (2)
   CRITICAL  SOL-001 Missing Signer Check
    examples/vulnerable.rs:35
    │ token::transfer(cpi_ctx, amount)?;
    └─ Verify the authority/owner account is a Signer or explicitly
       check `.is_signer` before transferring or minting tokens.

HIGH (3)
   HIGH      SOL-003 Arbitrary CPI (Cross-Program Invocation)
    examples/vulnerable.rs:68
    │ invoke(&ix, &[ctx.accounts.target_program.to_account_info()])?;
    └─ Validate the target program ID against a known constant or type
       the account as `Program<'info, T>` before invoking it.

  HIGH      SOL-004 Missing Bump Seed Canonicalization
    examples/vulnerable.rs:76
    │ let signer_pda = Pubkey::create_program_address(seeds, ctx.program_id)
    └─ Use `Pubkey::find_program_address` to derive the canonical bump
       instead of calling `create_program_address` directly.

MEDIUM (3)
  MEDIUM    SOL-005 Integer Overflow Risk
    examples/vulnerable.rs:27
    │ vault.total_staked = vault.total_staked - amount;
    └─ Replace raw arithmetic with `.checked_sub()` / `.checked_add()`
       or `saturating_*` equivalents.

──────────────────────────────────────────────────────────────────────
Summary
  CRITICAL 2   HIGH 3   MEDIUM 3   LOW 6   INFO 0
  Total findings: 14 across 1 file(s)
```

Exit code is `1` when any `CRITICAL` or `HIGH` finding is present — making SolAudit a natural CI gate.

## Rules

| ID | Severity | Name | What it catches |
|---|---|---|---|
| `SOL-001` | CRITICAL | Missing Signer Check | `transfer`/`mint_to` calls made without a nearby `Signer<'info>` type or `.is_signer` check |
| `SOL-002` | HIGH | Unchecked Account Deserialization | `Account::try_from` / `AccountLoader::try_from` used without a validating `#[account(...)]` constraint |
| `SOL-003` | HIGH | Arbitrary CPI | `invoke`/`invoke_signed` targeting a program ID sourced from a caller-supplied account instead of a verified constant |
| `SOL-004` | HIGH | Missing Bump Seed Canonicalization | `create_program_address` used directly, or `find_program_address`'s bump discarded instead of stored/validated |
| `SOL-005` | MEDIUM | Integer Overflow Risk | Raw `+`/`-`/`*` arithmetic on balance-like fields instead of `checked_*`/`saturating_*` |
| `SOL-006` | HIGH | Type Cosplay / Missing Discriminator Check | Manual `try_from_slice` deserialization with no discriminator validation or `Account<'info, T>` wrapper |
| `SOL-007` | MEDIUM | Insecure Account Initialization | `#[account(init, ...)]` constraints missing `payer` and/or `space` |
| `SOL-008` | LOW | Missing Owner Check | Raw `AccountInfo` fields used without a nearby `.owner` comparison |

Each rule is implemented as real regex/line-scanning logic in [`src/rules/index.ts`](./src/rules/index.ts) — see that file (and its accompanying [tests](./src/rules/index.test.ts)) for the exact matching heuristics and false-positive guards.

## Output formats

SolAudit supports three output modes, so it fits into a terminal, a script, or a CI pipeline:

- **Human** (default) — colorized terminal report grouped by severity, for local development.
- **JSON** (`--json`) — the full `ScanResult` object (`scannedFiles`, `findings[]`, `summary`), for piping into other tooling.
- **SARIF** (`--sarif`) — [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) output compatible with GitHub Code Scanning, so findings show up as annotations directly on your pull requests.

```bash
solaudit ./programs --sarif > results.sarif
```

## GitHub Actions

Add SolAudit to your CI so every push and PR is scanned automatically:

```yaml
name: SolAudit

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: oven-sh/setup-bun@v2
        with:
          bun-version: latest
      - run: bun install
      - run: bun src/cli.ts ./programs --sarif > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

This repository's own [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) runs SolAudit against [`examples/vulnerable.rs`](./examples/vulnerable.rs) on every push.

## Project layout

```
src/
  types.ts             # Finding, Rule, ScanResult types
  rules/index.ts        # The 8 vulnerability rules (pattern-matching logic)
  scanner.ts            # File/directory walking + aggregation
  output/report.ts       # Colored terminal report
  output/sarif.ts        # SARIF 2.1.0 conversion
  cli.ts                # Argument parsing + entrypoint
examples/vulnerable.rs   # Intentionally vulnerable sample Anchor program
```

## Development

```bash
bun install
bun test              # run the unit test suite
bun run start ./examples   # run the CLI against the bundled example
bun run build         # bundle src/cli.ts -> dist/cli.js
```

## Contributing

Contributions are very welcome — new rules, false-positive fixes, additional output formats, or better heuristics are all in scope.

1. Fork the repo and create a branch from `main`.
2. Add or update a rule in `src/rules/index.ts` (each rule is a self-contained `Rule` object).
3. Add unit tests covering both a triggering and a non-triggering case (`src/rules/index.test.ts`).
4. Run `bun test` and `bun run build` before opening a PR.

Please open an issue first for larger changes (e.g. new output formats or a plugin system) so we can discuss the approach.

## License

[MIT](./LICENSE) © 2026 Cody Pack

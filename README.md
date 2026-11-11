# SolAudit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![npm version](https://img.shields.io/badge/npm-v0.3.0-blue.svg)](https://www.npmjs.com/package/solaudit)
[![build](https://img.shields.io/badge/build-passing-brightgreen.svg)](./.github/workflows/ci.yml)

**A zero-dependency static-analysis engine that scans Anchor/Solana Rust programs for the vulnerability patterns behind the most common on-chain exploits — available as a CLI and as a free web app.**

SolAudit reads `.rs` source files, applies a set of pattern-matching security rules (missing signer checks, arbitrary CPIs, unchecked deserialization, integer overflow, and more), and gives you an actionable report in seconds — no RPC calls, no wallet, no build step required to run it.

- **CLI** — `npx solaudit ./program`, for local development and CI.
- **Web app** — [solaudit-web.vercel.app](https://solaudit-web.vercel.app/) — paste a public GitHub repo URL or upload a single `.rs` file, no install required.

---

## Repository layout

This is a Bun workspaces monorepo. The CLI and the web app share one scanning engine, so there is a single source of truth for every rule — no drift between the two.

```
packages/core/    Shared engine: rules, scanner, output formatters (published nowhere; workspace-only)
cli/              npm package "solaudit" — the command-line tool
web/              Next.js app deployed to Vercel — the web version
examples/         Intentionally vulnerable sample Anchor program, used by both the CLI and web tests
```

## CLI

```bash
# Run instantly with npx (no install)
npx solaudit ./program

# Or install globally with Bun
bun add -g solaudit
solaudit ./program
```

```bash
solaudit [path] [options]
```

| Flag | Description |
|---|---|
| `--json` | Print raw scan results as JSON |
| `--sarif` | Print results as SARIF 2.1.0 (for GitHub Code Scanning) |
| `--min-severity <level>` | Only report findings at or above `CRITICAL`\|`HIGH`\|`MEDIUM`\|`LOW`\|`INFO` |
| `--experimental` | Also run opt-in experimental rules (`SOL-012` Duplicate Mutable Accounts, `SOL-013` Token Account Not Bound to Mint, `SOL-015` Mint/Freeze Authority Never Revoked); higher signal, more false positives |
| `--include-tests` | Also scan test/fuzz/fixture/example code (skipped by default; findings there are rarely actionable) |
| `--help` | Show usage |

### Example

```bash
$ solaudit ./examples
```

```
SolAudit v0.3.2 — static analysis for Anchor/Solana programs
Scanned 1 file(s) at 2026-08-27T06:00:00.000Z
──────────────────────────────────────────────────────────────────────

CRITICAL (2)
   CRITICAL  SOL-001 Missing Signer Check
    examples/vulnerable.rs:35
    │ token::transfer(cpi_ctx, amount)?;
    └─ Verify the authority/owner account is a Signer or explicitly
       check `.is_signer` before transferring or minting tokens.

──────────────────────────────────────────────────────────────────────
Summary
  CRITICAL 2   HIGH 3   MEDIUM 3   LOW 6   INFO 0
  Total findings: 14 across 1 file(s)
```

Exit code is `1` when any `CRITICAL` or `HIGH` finding is present — making SolAudit a natural CI gate.

## Web app

**Live at [solaudit-web.vercel.app](https://solaudit-web.vercel.app/)** — no CLI, no local Anchor toolchain, no wallet required:

1. Paste a public GitHub repo URL **or** upload a single `.rs` file.
2. The server fetches `.rs` files via GitHub's API (no `git clone`) and scans them with the exact same engine as the CLI.
3. Get a report grouped by severity, right in the browser.

Optional: set `GITHUB_TOKEN` (see `web/.env.example`) to raise the GitHub API rate limit from 60 to 5,000 requests/hour. No special token scopes are needed for public repos.

### Running the web app locally

```bash
bun install          # from the repo root — links the workspace packages
cd web
bun run dev
```

## Rules

| ID | Severity | Name | What it catches |
|---|---|---|---|
| `SOL-001` | CRITICAL | Missing Signer Check | `transfer`/`mint_to` calls with no signer evidence anywhere: no nearby `is_signer` check, no `Signer<'info>` field on the governing Accounts struct, and no PDA signing (`invoke_signed` / `new_with_signer`). Also flags PDA-signed transfers whose *destination* is a caller-supplied unchecked account with no `Signer` governing the instruction (the classic vault drain) |
| `SOL-002` | HIGH | Unchecked Account Deserialization | `Account::try_from` / `AccountLoader::try_from` on an account with no validating `#[account(...)]` constraint (constraint-aware: fields carrying `owner`/`constraint`/`has_one` bindings are recognized as validated) |
| `SOL-003` | HIGH | Arbitrary CPI | `invoke`/`invoke_signed` whose program ID comes from a raw (unchecked) program account (`program_id: ctx.accounts.*` or a raw `*_program` field); typed `Program<'info, T>` targets are recognized as safe |
| `SOL-004` | HIGH | Missing Bump Seed Canonicalization / Unverified PDA | `create_program_address` called directly with a bump that didn't come from a nearby `find_program_address` (which is canonical by construction); also raw, mutable vault/treasury/pool-style accounts used in value movement with no `seeds`/`address` binding |
| `SOL-005` | MEDIUM | Integer Overflow Risk | Raw `+`/`-`/`*` arithmetic *written into account state* (field/compound assignment) on balance-like values instead of `checked_*`/`saturating_*`; also variable-exponent `pow()` in value math (e.g. `2u64.pow(level)` in a fee curve) |
| `SOL-006` | HIGH | Type Cosplay / Missing Discriminator Check | Manual `try_from_slice` deserialization with no discriminator validation or `Account<'info, T>` wrapper |
| `SOL-007` | MEDIUM | Insecure Account Initialization | `#[account(init, ...)]` constraints missing `payer` and/or `space` |
| `SOL-008` | LOW | Missing Owner Check | Raw `AccountInfo`/`UncheckedAccount` fields with no constraint binding whose data is trusted (deserialized/read, including through `let x = &ctx.accounts.f` aliases) or whose key is assigned into persistent state, with no genuine `.owner ==` comparison; usages are scoped to the owning struct's handlers |
| `SOL-009` | HIGH | Insecure Manual Account Closure | An account's lamports manually drained to zero (`lamports.borrow_mut() = 0` or `try_borrow_mut_lamports() = 0`) without discriminator zeroing or owner reassignment (unlike Anchor's `close = destination`), enabling closed-account revival |
| `SOL-010` | MEDIUM | Reinitialization Risk via init_if_needed | `#[account(init_if_needed, ...)]` without canonical PDA seeds / `has_one` constraints, letting a pre-existing attacker-crafted account pass as freshly initialized |
| `SOL-011` | MEDIUM | Missing Rent-Exemption Check | A partial lamport withdrawal with no nearby `Rent::get()?.minimum_balance(...)` check, risking runtime garbage-collection of the account |
| `SOL-014` | MEDIUM | Insecure On-Chain Randomness | A handler derives an outcome from public on-chain entropy (clock slot/timestamp, recent blockhash, slot-hashes) reduced via modulo/bitmask, in the same handler that moves value — predictable "randomness" attackers can grind or pre-compute. Requires entropy + reduction within a few lines + actual value movement, and suppresses regions using a real randomness oracle (Switchboard VRF, Orao) |
| `SOL-016` | MEDIUM | init Without seeds — Caller-Chosen Address | Singleton-style state (config/pool/market/treasury-like) created via bare `init` with no `seeds` binding — the address is a caller-chosen keypair, so unlimited competing instances can exist (the "multiple global configs" audit class). Scoped to singleton-suggestive names; skips `init_if_needed` (SOL-010), `token::`/`associated_token::` inits, and structs already anchored by a PDA-bound account |
| `SOL-017` | HIGH | Unvalidated Oracle / Price Feed | A raw oracle/feed account accepted with no identity validation visible anywhere in the file (the Loopscale $6M class), or a Pyth price read via `get_price_unchecked` with no staleness bound (the GoonFi class). Suppressed when the feed is validated in-handler, CPI-forwarded to an `address`-pinned program, or loaded through a checked loader |

Each rule is implemented as real regex/line-scanning logic in [`packages/core/src/rules/index.ts`](./packages/core/src/rules/index.ts) — see that file (and its accompanying [tests](./packages/core/src/rules/index.test.ts)) for the exact matching heuristics and false-positive guards.

## Accuracy

On the committed labeled suite in [`benchmark/`](./benchmark), the deterministic engine scores **100% precision, 100% recall, 100% F1** on rule-covered categories.

### Real-world validation (0.3.1)

0.3.0 was scanned against 9 major open-source protocols (marginfi, Drift, Orca Whirlpools, Marinade, Squads, Phoenix, Clockwork, Saber, and Cashio — the real $50M exploit, as a control). The result drove a rewrite of how the engine reads Anchor code: it now parses `#[derive(Accounts)]` structs and understands the constraint layer (`Signer`, `owner`/`has_one`/`constraint`/`seeds`, handler `Context<T>` mapping, `#[cfg(test)]` exclusion), instead of pattern-matching handler bodies alone.

- **Default findings across the 9 repos dropped from 1,232 to 158 (−87%)** — marginfi went from 521 findings to 20; Drift from 454 to 77.
- The remaining findings are *more* actionable, not fewer ideas: suppressions only happen on positive evidence of validation.
- Under `--experimental`, the new `SOL-013` rule fires on Cashio's actual vulnerable pattern — a token account whose mint is never bound despite a mint account being in scope (the class behind the infinite-mint exploit).

Benchmark label integrity note: three samples' labels were revised in 0.3.1 to match SOL-008's sharpened definition (raw accounts whose *data* is trusted or whose key is *assigned into state*); each revision is documented inline in [`benchmark/labels.json`](./benchmark/labels.json).

### Ground-truth validation (0.3.2): SolScape

0.3.1 was measured against **purpose-built ground truth**: [SolScape](https://github.com/blueeyez425-art/solaudit/tree/main/examples/solscape), a complete (intentionally vulnerable) Anchor game program — a persistent on-chain territory map with a marketplace, treasury, and player profiles — seeded with 9 real exploit classes (missing-signer treasury drain, unchecked PDA substitution, overflow price curve, arbitrary CPI, unbound token mint, close-then-revive, raw-byte trust, reinitialization) plus 4 correctly-secured control handlers. The answer key was written **before** the scan.

- **0.3.1 caught 2 of 9 seeded bugs** and false-flagged 2 of 4 controls. We published that scorecard, then fixed the engine.
- **0.3.2 catches 8 of 9 by default, 9 of 9 with `--experimental`** (the unbound-mint class is SOL-013), with **all 4 controls clean**.

**0.3.3 fix:** SOL-005 had a redundant in-rule test-path guard that silently skipped it whenever a target lived under an `examples/`-style path — meaning the documented SolScape reproduction command under-reported by one class. The guard is removed (filtering happens once, at the scanner layer, honoring `--include-tests`); the reproduction command now genuinely yields 9/9. Found while compiling SolScape; caught by the same fixture.
- Fixes: SOL-001 now detects PDA-signed transfers to caller-chosen unchecked recipients when no `Signer` governs the instruction (the classic vault drain); SOL-003 only flags CPIs whose *program* is a raw account (typed `Program<'info, T>` no longer flags); SOL-004 also flags unseeds-verified vault/treasury/pool accounts used in value movement; SOL-005 catches variable-exponent `pow()` in value math; SOL-008 follows `let x = &ctx.accounts.f` aliases, scopes usages to the owning struct's handlers, and no longer mistakes `field.owner = ...` assignments for checks; SOL-009 recognizes `try_borrow_mut_lamports() = 0` manual closes.
- marginfi re-scan sanity check: 24 findings (was 20) — the main program stays clean; the new signal lands in mock/integration programs.

Fixture revisions disclosed: SolScape's `withdraw_treasury` was rewritten to the genuinely exploitable `invoke_signed` shape (v1's plain `invoke` could not actually drain), `close_tile` now leaves data intact (v1 zeroed it, which is the *safe* pattern), and `buy_tile_spl` gained the realistic typed-token + mint shape SOL-013 is designed to scope to. v1 is archived in the fixture directory.

**Duplicate mutable accounts**, **token accounts unbound to their mint** (the Cashio class), and **unrevoked mint/freeze authorities** (the classic token rug vector) are covered by the experimental `SOL-012`, `SOL-013`, and `SOL-015` rules, available via `solaudit --experimental`. A “distinctness” heuristic false-positives on common legitimate patterns (for example a deposit instruction’s user/vault token accounts of the same type with no explicit `!=` constraint), so it stays opt-in to protect the default ruleset's precision. `SOL-015` stays opt-in because revocation may live in a different source file and protocol-controlled mints retain authority deliberately. These numbers describe this suite, not general security effectiveness.

### 0.3.4

- **New default rule `SOL-014` (Insecure On-Chain Randomness)** — catches handlers that derive outcomes from public on-chain entropy (clock slot/timestamp, recent blockhash, slot-hashes) reduced via modulo/bitmask while moving value. This is the class behind repeated exploits of on-chain games and lotteries. Precision-guarded by an entropy↔reduction proximity window and value-movement requirement, and suppressed when a real randomness oracle (Switchboard VRF, Orao) is in use. Verified: flags the seeded coin-flip sample, stays quiet on deadline-style clock use and on oracle-based games, and produced **zero false positives on marginfi's main program** (139 files, heavy `Clock` usage for interest accrual).
- **New experimental rule `SOL-015` (Mint/Freeze Authority Never Revoked)** — flags mints initialized with no `set_authority` revocation anywhere in the file (the classic rug vector: indefinite inflation, holder freezing). Opt-in because revocation may live in another file and protocol-controlled mints retain authority deliberately.
- Benchmark suite extended to 17 samples (vulnerable coin flip, VRF-safe control, unrevoked-mint known gap): **100% precision / 100% recall / 100% F1 maintained**; SolScape ground truth still 9/9 with `--experimental`, hardened build still clean.
- Housekeeping: the CLI banner version no longer drifts (single source of truth), and a clean scan now prints an explicit reminder that 0 findings ≠ 0 bugs.

### 0.3.5

- **New default rule `SOL-016` (init Without seeds — Caller-Chosen Address)** — flags singleton-style state accounts created via bare `init` with no `seeds` binding: the address is a caller-chosen keypair, so anyone can create unlimited competing instances — the "multiple global config accounts" class from production audit reports. Precision-scoped to singleton-suggestive names; skips `init_if_needed` (SOL-010's territory), `token::`/`associated_token::` inits (address derived internally), and structs already anchored by a seeds-bound account (admin-gated child creation, e.g. marginfi's `add_pool`).
- **New default rule `SOL-017` (Unvalidated Oracle / Price Feed)** — two patterns behind ~$8M+ of real incidents: (A) a raw oracle/price-feed account with no identity validation anywhere in the file (the Loopscale $6M class: attacker substitutes a fake feed and prices collateral arbitrarily), suppressed when the feed is validated in-handler or forwarded to an `address`-pinned CPI program that validates its own accounts (the marginfi → Solend pattern); (B) `get_price_unchecked`/`get_ema_price_unchecked` reads with no staleness bound (the GoonFi class), suppressed when preceded by a checked loader.
- **Test-path detection now excludes `mocks/` directories** — marginfi's drift-/solend-/juplend-mocks are intentionally vulnerable test doubles and were inflating real-protocol scans.
- **Fix: struct-driven findings now report the field's declaration line** instead of the start of its attribute/doc block.
- Validation: benchmark extended to 21 samples — **100% precision / 100% recall / 100% F1 maintained**, experimental gap coverage 2/2; **zero new-rule findings on marginfi's main program**; SolScape ground truth unchanged (9/9 with `--experimental`, hardened build clean). One benchmark label revised (`sol-008-vulnerable` now also expects SOL-017 — its raw, unvalidated `price_feed` is exactly the targeted pattern); revision documented inline in [`benchmark/labels.json`](./benchmark/labels.json).

## What SolAudit is (and isn't)

SolAudit is a **first-pass scanner for known Solana vulnerability classes**, not an audit.

- It catches the bug classes it has rules for — measurably, against published ground truth ([SolScape](./examples/solscape) and the [benchmark](./benchmark)).
- A clean scan means none of those known classes were detected. It does **not** mean the program is safe: logic flaws, economic/oracle attacks, and unknown vulnerability classes are out of scope for any static scanner.
- Non-Anchor programs and custom validation layers reduce visibility; findings there need manual triage.
- If the program will hold real funds, get a manual review or professional audit regardless of scan results.

## Output formats (CLI)

- **Human** (default) — colorized terminal report grouped by severity.
- **JSON** (`--json`) — the full `ScanResult` object (`scannedFiles`, `findings[]`, `summary`).
- **SARIF** (`--sarif`) — [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) output compatible with GitHub Code Scanning.
- **Experimental rules** (`--experimental`) — opt into noisier, higher-signal heuristics (`SOL-012` Duplicate Mutable Accounts, `SOL-013` Token Account Not Bound to Mint, `SOL-015` Mint/Freeze Authority Never Revoked). Recommended for deep manual reviews rather than CI gates.

## GitHub Actions

SolAudit ships as a ready-to-use [GitHub Action](./action.yml). Drop this into `.github/workflows/solaudit.yml` in your own repo and every push/PR gets scanned automatically, with results uploaded straight to your repo's Security tab:

```yaml
name: SolAudit

on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # required to upload SARIF results

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: blueeyez425-art/solaudit@main
        with:
          path: ./programs        # file or directory to scan (default: .)
          min-severity: INFO      # lowest severity to report (default: INFO)
          fail-on-findings: true  # fail the build on any CRITICAL/HIGH finding (default: true)
          upload-sarif: true      # upload results to code scanning (default: true)
```

No `security-events: write` permission in your workflow? Set `upload-sarif: false` and the action will still run the scan and fail the build on CRITICAL/HIGH findings — it just won't publish to the Security tab.

Prefer to wire it up manually instead of using the packaged action:

```yaml
- uses: actions/checkout@v4
- run: npx solaudit ./programs --sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

This repository's own [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) runs the full test suite, builds the CLI and web app, and uses this repo's own action against `examples/` on every push.

## Development

```bash
bun install                    # installs and links all workspaces
cd packages/core && bun test   # run the engine's unit test suite
cd cli && bun run build        # bundle cli/src/cli.ts -> cli/dist/cli.js
cd web && bun run build        # production-build the web app
```

## Contributing

Contributions are very welcome — new rules, false-positive fixes, additional output formats, or web UI improvements are all in scope.

1. Fork the repo and create a branch from `main`.
2. Add or update a rule in `packages/core/src/rules/index.ts` (each rule is a self-contained `Rule` object).
3. Add unit tests covering both a triggering and a non-triggering case (`packages/core/src/rules/index.test.ts`).
4. Run `bun test` (from `packages/core`) before opening a PR.

Please open an issue first for larger changes so we can discuss the approach.

## Support

SolAudit is free and open source, and development continues with or without tips. If it catches a bug or saves you real time and you'd like to say thanks, tips are appreciated — never expected: [flipcash.com/d142ad60-e966-4967-bfa3-6d2332e59342](https://flipcash.com/d142ad60-e966-4967-bfa3-6d2332e59342)

## License

[MIT](./LICENSE) © 2026 Cody Pack

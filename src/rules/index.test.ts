import { describe, expect, test } from "bun:test";
import { rules } from "./index";

function ruleById(id: string) {
  const rule = rules.find((r) => r.id === id);
  if (!rule) throw new Error(`rule ${id} not found`);
  return rule;
}

describe("SOL-001 Missing Signer Check", () => {
  test("flags transfer with no signer evidence nearby", () => {
    const src = `
      pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let cpi_accounts = Transfer {
          from: ctx.accounts.vault_token_account.to_account_info(),
          to: ctx.accounts.user_token_account.to_account_info(),
          authority: ctx.accounts.vault_authority.to_account_info(),
        };
        token::transfer(cpi_ctx, amount)?;
        Ok(())
      }
    `;
    const findings = ruleById("SOL-001").check(src, "test.rs");
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe("SOL-001");
  });

  test("does not flag when is_signer check is nearby", () => {
    const src = `
      pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        require!(ctx.accounts.authority.is_signer, ErrorCode::Unauthorized);
        token::transfer(cpi_ctx, amount)?;
        Ok(())
      }
    `;
    const findings = ruleById("SOL-001").check(src, "test.rs");
    expect(findings.length).toBe(0);
  });
});

describe("SOL-004 Missing Bump Seed Canonicalization", () => {
  test("flags create_program_address without find_program_address", () => {
    const src = `let pda = Pubkey::create_program_address(seeds, program_id)?;`;
    const findings = ruleById("SOL-004").check(src, "test.rs");
    expect(findings.length).toBe(1);
  });

  test("does not flag find_program_address with bump destructured", () => {
    const src = `let (pda, bump) = Pubkey::find_program_address(seeds, program_id);`;
    const findings = ruleById("SOL-004").check(src, "test.rs");
    expect(findings.length).toBe(0);
  });
});

describe("SOL-005 Integer Overflow Risk", () => {
  test("flags raw arithmetic on balance-like fields", () => {
    const src = `vault.total_staked = vault.total_staked + amount;`;
    const findings = ruleById("SOL-005").check(src, "test.rs");
    expect(findings.length).toBe(1);
  });

  test("does not flag checked arithmetic", () => {
    const src = `vault.total_staked = vault.total_staked.checked_add(amount).ok_or(ErrorCode::MathOverflow)?;`;
    const findings = ruleById("SOL-005").check(src, "test.rs");
    expect(findings.length).toBe(0);
  });
});

describe("SOL-007 Insecure Account Initialization", () => {
  test("flags init without space", () => {
    const src = `#[account(init, payer = authority)]\npub vault: Account<'info, Vault>,`;
    const findings = ruleById("SOL-007").check(src, "test.rs");
    expect(findings.length).toBe(1);
  });

  test("does not flag init with payer and space", () => {
    const src = `#[account(init, payer = authority, space = 8 + 32 + 8)]\npub vault: Account<'info, Vault>,`;
    const findings = ruleById("SOL-007").check(src, "test.rs");
    expect(findings.length).toBe(0);
  });
});

describe("rules registry", () => {
  test("exposes exactly 8 rules with unique ids", () => {
    expect(rules.length).toBe(8);
    const ids = new Set(rules.map((r) => r.id));
    expect(ids.size).toBe(8);
  });
});

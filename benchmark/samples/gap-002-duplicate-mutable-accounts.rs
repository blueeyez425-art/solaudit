use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("11111111111111111111111111111111");

// NOT COVERED BY ANY CURRENT SOL-0xx RULE.
//
// `swap` takes two separate token accounts, `account_a` and `account_b`, and
// moves funds from one into the other. Nothing constrains them to be
// *different* accounts (e.g. `constraint = account_a.key() != account_b.key()`).
// A caller can pass the SAME token account for both `account_a` and
// `account_b`. Depending on how the surrounding logic computes balances
// before/after the two transfers, this "duplicate mutable account" pattern
// commonly lets an attacker mint themselves free balance out of a single
// account being credited and debited against itself in ways the program
// author never validated.
#[program]
pub mod amm {
    use super::*;

    pub fn swap(ctx: Context<Swap>, amount: u64) -> Result<()> {
        let cpi_accounts = Transfer {
            from: ctx.accounts.account_a.to_account_info(),
            to: ctx.accounts.account_b.to_account_info(),
            authority: ctx.accounts.authority.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::transfer(cpi_ctx, amount)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(mut)]
    pub account_a: Account<'info, TokenAccount>,
    // BUG: no `constraint = account_b.key() != account_a.key()` here, so
    // account_a and account_b are allowed to be the same account.
    #[account(mut)]
    pub account_b: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

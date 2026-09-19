use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("11111111111111111111111111111111");

#[program]
pub mod vault {
    use super::*;

    // VULNERABLE: `authority` is typed as a raw AccountInfo, never checked as a
    // Signer, yet it is used to authorize a token transfer out of the vault.
    // Anyone can call this instruction naming any vault + destination pair and
    // drain funds without ever signing as the real owner.
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let cpi_accounts = Transfer {
            from: ctx.accounts.vault_token_account.to_account_info(),
            to: ctx.accounts.destination_token_account.to_account_info(),
            authority: ctx.accounts.authority.clone(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::transfer(cpi_ctx, amount)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault_token_account: Account<'info, TokenAccount>,
    #[account(mut)]
    pub destination_token_account: Account<'info, TokenAccount>,
    /// CHECK: never validated as a Signer before being used as CPI authority
    pub authority: AccountInfo<'info>,
    pub token_program: Program<'info, Token>,
}

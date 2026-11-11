use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod vuln_protocol {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        ctx.accounts.config.authority = ctx.accounts.admin.key();
        Ok(())
    }
}

#[account]
pub struct Config {
    pub authority: Pubkey,
    pub fee_bps: u16,
    pub paused: bool,
}

// VULNERABLE: `init` without `seeds` — the config address is a caller-chosen
// keypair, so anyone can create unlimited competing "global config" accounts
// and trick integrators/keepers into reading the attacker's instance.
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = admin, space = 8 + 33)]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

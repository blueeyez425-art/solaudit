use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod pda_vault {
    use super::*;

    // VULNERABLE: the bump is supplied by the caller as an instruction argument
    // and passed straight into `create_program_address` instead of being
    // derived (and canonicalized) via `find_program_address`. An attacker can
    // brute-force an alternate valid bump that produces a *different* but
    // still on-curve-off PDA, letting them forge authority over an account
    // that was never actually initialized by this program.
    pub fn withdraw(ctx: Context<Withdraw>, bump: u8) -> Result<()> {
        let seeds = &[b"vault", ctx.accounts.owner.key.as_ref(), &[bump]];
        let pda = Pubkey::create_program_address(seeds, ctx.program_id)?;
        require_keys_eq!(pda, ctx.accounts.vault.key());
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: AccountInfo<'info>,
    pub owner: Signer<'info>,
}

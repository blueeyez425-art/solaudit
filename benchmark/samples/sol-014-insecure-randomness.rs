use anchor_lang::prelude::*;
use anchor_lang::system_program;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod coinflip {
    use super::*;

    // VULNERABLE: the outcome is derived from the on-chain slot, which is
    // public, partly validator-influenced entropy. An attacker can simulate
    // the roll off-chain (or grind transactions until the slot favors them)
    // and only submit winning plays, draining the vault over time.
    pub fn play(ctx: Context<Play>, guess: u8) -> Result<()> {
        require!(guess <= 1, ErrorCode::InvalidGuess);
        let clock = Clock::get()?;
        let roll = clock.slot % 2;
        if roll == guess as u64 {
            let payout = ctx.accounts.vault.lamports() / 10;
            let seeds: &[&[u8]] = &[b"vault", &[ctx.bumps.vault]];
            system_program::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.system_program.to_account_info(),
                    system_program::Transfer {
                        from: ctx.accounts.vault.to_account_info(),
                        to: ctx.accounts.player.to_account_info(),
                    },
                    &[seeds],
                ),
                payout,
            )?;
        }
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Play<'info> {
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: SystemAccount<'info>,
    #[account(mut)]
    pub player: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("guess must be 0 or 1")]
    InvalidGuess,
}

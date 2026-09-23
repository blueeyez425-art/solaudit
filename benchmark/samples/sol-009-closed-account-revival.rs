use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

// NOW COVERED BY SOL-009 (Insecure Manual Account Closure).
//
// `close_position` drains the account's lamports to `destination` to "close"
// it, but it never zeroes the account's discriminator/data or reassigns its
// owner. Anchor's own `close = destination` constraint does both automatically,
// but this hand-rolled version skips that step. Because the account still has
// its old, non-zeroed 8-byte discriminator and full lamport-refundable data,
// an attacker can immediately refund rent lamports back into the "closed"
// account in the same transaction and have a later instruction in the same
// tx (or a later tx, before garbage collection is guaranteed) treat it as
// still-open, letting them e.g. re-claim already-withdrawn funds.
#[program]
pub mod perp_market {
    use super::*;

    pub fn close_position(ctx: Context<ClosePosition>) -> Result<()> {
        let position = ctx.accounts.position.to_account_info();
        let destination = ctx.accounts.destination.to_account_info();

        let dest_starting_lamports = destination.lamports();
        **destination.lamports.borrow_mut() =
            dest_starting_lamports.checked_add(position.lamports()).unwrap();
        **position.lamports.borrow_mut() = 0;
        // BUG: no discriminator zeroing, no owner reassignment to System Program.
        // `position` is still a live, readable account with stale data until
        // the runtime eventually garbage-collects it.
        Ok(())
    }
}

#[derive(Accounts)]
pub struct ClosePosition<'info> {
    #[account(mut)]
    pub position: Account<'info, Position>,
    #[account(mut)]
    pub destination: SystemAccount<'info>,
}

#[account]
pub struct Position {
    pub owner: Pubkey,
    pub collateral: u64,
}

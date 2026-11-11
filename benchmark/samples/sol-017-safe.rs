use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod safe_lending {
    use super::*;

    pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
        // SAFE (pattern B): staleness-bounded read.
        let price = ctx.accounts.price_update.get_price_no_older_than(
            &Clock::get()?,
            60,
            &feed_id,
        )?;
        let _ = (price, amount);
        Ok(())
    }
}

// SAFE (pattern A): the feed's identity is pinned by a stored address
// constraint in the accounts struct.
#[derive(Accounts)]
pub struct Borrow<'info> {
    #[account(address = config.oracle_feed)]
    pub oracle: AccountInfo<'info>,
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub user: Signer<'info>,
}

#[account]
pub struct Config {
    pub oracle_feed: Pubkey,
}

#[account]
pub struct Vault {
    pub total_deposits: u64,
}

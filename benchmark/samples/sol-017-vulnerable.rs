use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod vuln_lending {
    use super::*;

    pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
        // VULNERABLE (pattern B): price read with no staleness bound.
        let price = ctx.accounts.price_update.get_price_unchecked(&feed_id)?;
        let _ = (price, amount);
        Ok(())
    }
}

// VULNERABLE (pattern A): the feed is a raw AccountInfo with no constraint
// and nothing in this file validates its owner/program — an attacker can
// pass a fake oracle account and price collateral arbitrarily. (Loopscale.)
#[derive(Accounts)]
pub struct Borrow<'info> {
    /// CHECK: price feed
    pub oracle: AccountInfo<'info>,
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub user: Signer<'info>,
}

#[account]
pub struct Vault {
    pub total_deposits: u64,
}

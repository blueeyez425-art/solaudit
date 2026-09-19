use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod staking_pool {
    use super::*;

    // VULNERABLE: `total_staked` is updated with raw `+`/`-` arithmetic. In a
    // release build without `overflow-checks = true` in Cargo.toml, adding a
    // very large `amount` silently wraps instead of aborting, corrupting the
    // pool's accounting and potentially letting a staker mint phantom shares.
    pub fn stake(ctx: Context<Stake>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.total_staked = pool.total_staked + amount;
        pool.total_shares = pool.total_shares + amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Stake<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
}

#[account]
pub struct Pool {
    pub total_staked: u64,
    pub total_shares: u64,
}

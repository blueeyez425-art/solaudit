use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod oracle_consumer {
    use super::*;

    // VULNERABLE: `price_feed` is a raw AccountInfo, so Anchor never validates
    // which program owns it. The handler reads price data straight out of it
    // with no ownership validation at all, so a caller can pass in any
    // account (including one they fully control) shaped to look like a price
    // feed and manipulate the "oracle" price used downstream.
    pub fn consume_price(ctx: Context<ConsumePrice>) -> Result<u64> {
        let data = ctx.accounts.price_feed.try_borrow_data()?;
        let price = u64::from_le_bytes(data[0..8].try_into().unwrap());
        Ok(price)
    }
}

#[derive(Accounts)]
pub struct ConsumePrice<'info> {
    /// CHECK: no owner validation performed anywhere in this instruction
    pub price_feed: AccountInfo<'info>,
}

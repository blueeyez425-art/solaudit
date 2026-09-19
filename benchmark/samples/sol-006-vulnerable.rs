use anchor_lang::prelude::*;
use borsh::BorshDeserialize;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod lending {
    use super::*;

    // VULNERABLE: raw bytes from an untyped account are deserialized directly
    // with `try_from_slice`, with no discriminator check and no typed
    // `Account<'info, T>` wrapper beforehand. `UserPosition` and
    // `AdminPosition` happen to share the same byte layout in this program
    // ("type cosplay"), so a user could pass their own `UserPosition` account
    // where an `AdminPosition` is expected and have it deserialize as one,
    // bypassing the admin-only check entirely.
    pub fn liquidate(ctx: Context<Liquidate>) -> Result<()> {
        let data = ctx.accounts.position.try_borrow_data()?;
        let position = AdminPosition::try_from_slice(&data)?;
        require!(position.is_admin, ErrorCode::Unauthorized);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Liquidate<'info> {
    /// CHECK: manually deserialized, no discriminator validation
    pub position: AccountInfo<'info>,
}

#[derive(BorshDeserialize)]
pub struct AdminPosition {
    pub is_admin: bool,
    pub authority: Pubkey,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized")]
    Unauthorized,
}

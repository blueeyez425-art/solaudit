use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod escrow {
    use super::*;

    // VULNERABLE: the escrow state account is manually deserialized from a raw
    // AccountInfo with no #[account(...)] constraint validating its owner or
    // discriminator first. A caller can pass in an account owned by a totally
    // different program and this line will happily deserialize whatever bytes
    // are there, trusting fields that were never actually validated.
    pub fn cancel(ctx: Context<Cancel>) -> Result<()> {
        let escrow_state: Account<EscrowState> = Account::try_from(&ctx.accounts.escrow_info)?;
        require_keys_eq!(escrow_state.initializer, ctx.accounts.initializer.key());
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Cancel<'info> {
    /// CHECK: raw account, manually deserialized in the handler
    pub escrow_info: AccountInfo<'info>,
    pub initializer: Signer<'info>,
}

#[account]
pub struct EscrowState {
    pub initializer: Pubkey,
    pub amount: u64,
}

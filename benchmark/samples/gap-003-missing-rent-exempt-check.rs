use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

// NOT COVERED BY ANY CURRENT SOL-0xx RULE.
//
// `partial_withdraw` lets the owner pull an arbitrary amount of lamports out
// of `vault` with no check that the account's remaining balance stays above
// the rent-exemption minimum for its size. If a caller drains it below that
// threshold, the runtime can purge the account entirely on the next epoch
// boundary, permanently destroying any remaining state (and, if other
// instructions assume this account always exists once initialized, opening
// up re-initialization or accounting-drift bugs elsewhere in the program).
#[program]
pub mod treasury {
    use super::*;

    pub fn partial_withdraw(ctx: Context<PartialWithdraw>, lamports: u64) -> Result<()> {
        let vault = ctx.accounts.vault.to_account_info();
        let destination = ctx.accounts.destination.to_account_info();

        **vault.lamports.borrow_mut() = vault.lamports().checked_sub(lamports).unwrap();
        **destination.lamports.borrow_mut() = destination.lamports().checked_add(lamports).unwrap();
        // BUG: no comparison against `Rent::get()?.minimum_balance(vault.data_len())`
        // before allowing the withdrawal to proceed.
        Ok(())
    }
}

#[derive(Accounts)]
pub struct PartialWithdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, VaultState>,
    #[account(mut)]
    pub destination: SystemAccount<'info>,
    pub owner: Signer<'info>,
}

#[account]
pub struct VaultState {
    pub owner: Pubkey,
}

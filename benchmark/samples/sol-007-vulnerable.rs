use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod registry {
    use super::*;

    pub fn create_entry(_ctx: Context<CreateEntry>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CreateEntry<'info> {
    // VULNERABLE: `init` is present but `space` was never specified. This
    // constraint block was likely copy-pasted from another instruction and
    // trimmed incompletely; without `space`, account allocation is undefined
    // and this pattern should never ship in a reviewed program.
    #[account(init, payer = authority)]
    pub entry: Account<'info, Entry>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Entry {
    pub owner: Pubkey,
    pub value: u64,
}

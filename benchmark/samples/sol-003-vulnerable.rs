use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;
use anchor_lang::solana_program::instruction::Instruction;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod router {
    use super::*;

    // VULNERABLE: the "target program" is whatever account the caller passes
    // in for `ctx.accounts.target_program`, with no check that it equals a
    // known, expected program ID. A malicious caller can substitute their own
    // program here and have this instruction invoke it with vault-derived
    // signing authority, effectively hijacking the CPI.
    pub fn route(ctx: Context<Route>, data: Vec<u8>) -> Result<()> {
        let ix = Instruction {
            program_id: ctx.accounts.target_program.key(),
            accounts: vec![],
            data,
        };
        invoke(&ix, &[ctx.accounts.target_program.to_account_info()])?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Route<'info> {
    /// CHECK: caller-supplied, never checked against a known program ID
    pub target_program: AccountInfo<'info>,
}

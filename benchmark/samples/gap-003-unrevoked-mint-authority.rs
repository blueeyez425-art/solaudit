use anchor_lang::prelude::*;
use anchor_spl::token::{self, InitializeMint, Mint, Token};

declare_id!("11111111111111111111111111111111");

#[program]
pub mod token_launcher {
    use super::*;

    // GAP: the mint is created with a mint authority and a freeze authority,
    // and nothing anywhere in the program ever revokes them (no
    // set_authority call). The authority can inflate supply at will or
    // freeze any holder's tokens — the classic rug vector.
    //
    // The experimental SOL-015 rule detects this; it stays opt-in because
    // revocation may live in a different source file of the same project,
    // and protocol-controlled mints retain authority deliberately.
    pub fn create_token(ctx: Context<CreateToken>) -> Result<()> {
        let cpi_accounts = InitializeMint {
            mint: ctx.accounts.mint.to_account_info(),
            rent: ctx.accounts.rent.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::initialize_mint(
            cpi_ctx,
            9,
            &ctx.accounts.authority.key(),
            Some(&ctx.accounts.authority.key()),
        )?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CreateToken<'info> {
    /// CHECK: initialized via CPI in the handler
    #[account(mut)]
    pub mint: AccountInfo<'info>,
    pub authority: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
}

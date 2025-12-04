use {
    crate::{
        commands::CommandExec,
        constants::{LAMPORTS_PER_SOL, SYSTEM_INSTRUCTION_TRANSFER, SYSTEM_PROGRAM_ID},
        context::ScillaContext,
        error::ScillaResult,
        prompt::prompt_data,
        ui::show_spinner,
    },
    comfy_table::{Cell, Table, presets::UTF8_FULL},
    console::style,
    solana_instruction::{AccountMeta, Instruction},
    solana_pubkey::Pubkey,
    solana_signature::Signature,
    solana_transaction::Transaction,
    std::str::FromStr,
};

/// Commands related to wallet or account management
#[derive(Debug, Clone)]
pub enum AccountCommand {
    Fetch,
    Balance,
    Transfer,
    Airdrop,
    ConfirmTransaction,
    LargestAccounts,
    NonceAccount,
    GoBack,
}

fn lamports_to_sol(lamports: u64) -> f64 {
    lamports as f64 / LAMPORTS_PER_SOL as f64
}

impl AccountCommand {
    pub fn description(&self) -> &'static str {
        match self {
            AccountCommand::Fetch => "Fetch Account info",
            AccountCommand::Balance => "Get Account Balance",
            AccountCommand::Transfer => "Transfer SOL",
            AccountCommand::Airdrop => "Request Airdrop",
            AccountCommand::ConfirmTransaction => "Confirm a pending transaction",
            AccountCommand::LargestAccounts => "Fetch cluster’s largest accounts",
            AccountCommand::NonceAccount => "Inspect or manage nonce accounts",
            AccountCommand::GoBack => "Go back",
        }
    }
}

impl AccountCommand {
    pub async fn process_command(&self, ctx: &ScillaContext) -> ScillaResult<()> {
        match self {
            AccountCommand::Fetch => {
                let pubkey: Pubkey = prompt_data("Enter Pubkey :")?;
                show_spinner(self.description(), fetch_acc_data(ctx, &pubkey)).await?;
            }
            AccountCommand::Balance => {
                let pubkey: Pubkey = prompt_data("Enter Pubkey :")?;
                show_spinner(self.description(), fetch_account_balance(ctx, &pubkey)).await?;
            }
            AccountCommand::Transfer => {
                let recipient: Pubkey = prompt_data("Enter recipient pubkey:")?;
                let amount: f64 = prompt_data("Enter amount (in SOL):")?;
                show_spinner(self.description(), transfer_sol(ctx, &recipient, amount)).await?;
            }
            AccountCommand::Airdrop => {
                show_spinner(self.description(), request_sol_airdrop(ctx)).await?;
            }
            AccountCommand::ConfirmTransaction => {
                let signature: Signature = prompt_data("Enter transaction signature:")?;
                show_spinner(self.description(), confirm_transaction(ctx, &signature)).await?;
            }
            AccountCommand::LargestAccounts => {
                show_spinner(self.description(), fetch_largest_accounts(ctx)).await?;
            }
            AccountCommand::NonceAccount => {
                let pubkey: Pubkey = prompt_data("Enter nonce account pubkey:")?;
                show_spinner(self.description(), fetch_nonce_account(ctx, &pubkey)).await?;
            }
            AccountCommand::GoBack => {
                return Ok(CommandExec::GoBack);
            }
        };

        Ok(CommandExec::Process(()))
    }
}

async fn request_sol_airdrop(ctx: &ScillaContext) -> anyhow::Result<()> {
    let sig = ctx.rpc().request_airdrop(ctx.pubkey(), 1).await;
    match sig {
        Ok(signature) => {
            println!(
                "{} {}",
                style("Airdrop requested successfully!").green().bold(),
                style(format!("Signature: {}", signature)).cyan()
            );
        }
        Err(err) => {
            eprintln!(
                "{} {}",
                style("Airdrop failed:").red().bold(),
                style(err).red()
            );
        }
    }

    Ok(())
}

async fn fetch_acc_data(ctx: &ScillaContext, pubkey: &Pubkey) -> anyhow::Result<()> {
    let acc = ctx.rpc().get_account(pubkey).await?;

    println!(
        "{}\n{}",
        style("Account info:").green().bold(),
        style(format!("{:#?}", acc)).cyan()
    );

    Ok(())
}

async fn fetch_account_balance(ctx: &ScillaContext, pubkey: &Pubkey) -> anyhow::Result<()> {
    let acc = ctx.rpc().get_account(pubkey).await?;
    let acc_balance = lamports_to_sol(acc.lamports);

    println!(
        "{}\n{}",
        style("Account balance in SOL:").green().bold(),
        style(format!("{:#?}", acc_balance)).cyan()
    );

    Ok(())
}

async fn transfer_sol(ctx: &ScillaContext, recipient: &Pubkey, amount: f64) -> anyhow::Result<()> {
    // Input validation
    if amount <= 0.0 {
        return Err(anyhow::anyhow!("Transfer amount must be greater than 0"));
    }

    // Check sender has sufficient balance
    let sender_account = ctx.rpc().get_account(ctx.pubkey()).await?;
    let sender_balance = lamports_to_sol(sender_account.lamports);

    if amount > sender_balance {
        return Err(anyhow::anyhow!(
            "Insufficient balance. Have {:.6} SOL, trying to send {:.6} SOL",
            sender_balance,
            amount
        ));
    }

    let lamports = (amount * (LAMPORTS_PER_SOL as f64)).round() as u64;
    let recent_blockhash = ctx.rpc().get_latest_blockhash().await?;

    let mut instruction_data = vec![SYSTEM_INSTRUCTION_TRANSFER];
    instruction_data.extend_from_slice(&lamports.to_le_bytes());

    let program_id = Pubkey::from_str(SYSTEM_PROGRAM_ID)?;

    let instruction = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(*ctx.pubkey(), true),
            AccountMeta::new(*recipient, false),
        ],
        data: instruction_data,
    };

    let transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(ctx.pubkey()),
        &[ctx.keypair()],
        recent_blockhash,
    );

    let signature = ctx.rpc().send_and_confirm_transaction(&transaction).await?;

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_header(vec![
            Cell::new("Field").add_attribute(comfy_table::Attribute::Bold),
            Cell::new("Value").add_attribute(comfy_table::Attribute::Bold),
        ])
        .add_row(vec![
            Cell::new("Recipient"),
            Cell::new(recipient.to_string()),
        ])
        .add_row(vec![
            Cell::new("Amount (SOL)"),
            Cell::new(format!("{:.6}", amount)),
        ])
        .add_row(vec![
            Cell::new("Signature"),
            Cell::new(signature.to_string()),
        ]);

    println!("\n{}", style("TRANSFER SUCCESSFUL").green().bold());
    println!("{}", table);

    Ok(())
}

async fn confirm_transaction(ctx: &ScillaContext, signature: &Signature) -> anyhow::Result<()> {
    let confirmed = ctx.rpc().confirm_transaction(signature).await?;

    let status = if confirmed {
        "Confirmed"
    } else {
        "Not Confirmed"
    };
    let status_color = if confirmed {
        style(status).green()
    } else {
        style(status).yellow()
    };

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_header(vec![
            Cell::new("Field").add_attribute(comfy_table::Attribute::Bold),
            Cell::new("Value").add_attribute(comfy_table::Attribute::Bold),
        ])
        .add_row(vec![
            Cell::new("Signature"),
            Cell::new(signature.to_string()),
        ])
        .add_row(vec![
            Cell::new("Status"),
            Cell::new(status_color.to_string()),
        ]);

    println!("\n{}", style("TRANSACTION CONFIRMATION").green().bold());
    println!("{}", table);

    Ok(())
}

async fn fetch_largest_accounts(ctx: &ScillaContext) -> anyhow::Result<()> {
    use solana_rpc_client_api::config::RpcLargestAccountsConfig;

    let config = RpcLargestAccountsConfig {
        commitment: None,
        filter: None,
        sort_results: Some(true),
    };

    let response = ctx.rpc().get_largest_accounts_with_config(config).await?;
    let largest_accounts = response.value;

    let mut table = Table::new();
    table.load_preset(UTF8_FULL).set_header(vec![
        Cell::new("#").add_attribute(comfy_table::Attribute::Bold),
        Cell::new("Address").add_attribute(comfy_table::Attribute::Bold),
        Cell::new("Balance (SOL)").add_attribute(comfy_table::Attribute::Bold),
    ]);

    for (idx, account) in largest_accounts.iter().enumerate() {
        let balance_sol = lamports_to_sol(account.lamports);
        table.add_row(vec![
            Cell::new(format!("{}", idx + 1)),
            Cell::new(account.address.clone()),
            Cell::new(format!("{:.2}", balance_sol)),
        ]);
    }

    println!("\n{}", style("LARGEST ACCOUNTS").green().bold());
    println!("{}", table);

    Ok(())
}

async fn fetch_nonce_account(ctx: &ScillaContext, pubkey: &Pubkey) -> anyhow::Result<()> {
    let account = ctx.rpc().get_account(pubkey).await?;

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_header(vec![
            Cell::new("Field").add_attribute(comfy_table::Attribute::Bold),
            Cell::new("Value").add_attribute(comfy_table::Attribute::Bold),
        ])
        .add_row(vec![Cell::new("Address"), Cell::new(pubkey.to_string())])
        .add_row(vec![
            Cell::new("Lamports"),
            Cell::new(format!("{}", account.lamports)),
        ])
        .add_row(vec![
            Cell::new("Balance (SOL)"),
            Cell::new(format!("{:.6}", lamports_to_sol(account.lamports))),
        ])
        .add_row(vec![
            Cell::new("Owner"),
            Cell::new(account.owner.to_string()),
        ])
        .add_row(vec![
            Cell::new("Executable"),
            Cell::new(format!("{}", account.executable)),
        ])
        .add_row(vec![
            Cell::new("Rent Epoch"),
            Cell::new(format!("{}", account.rent_epoch)),
        ]);

    println!("\n{}", style("NONCE ACCOUNT INFO").green().bold());
    println!("{}", table);

    Ok(())
}

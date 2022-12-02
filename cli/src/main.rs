use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use console::{style, Emoji};
use dialoguer::{theme::ColorfulTheme, Confirm};
use isomdl_18013_7::{isomdl::presentation::device::PermittedItems, ResponseRedirectType, Wallet};
use url::Url;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Wallet {
        #[command(subcommand)]
        command: WalletCommands,
    },
}

#[derive(Subcommand)]
enum WalletCommands {
    Submit { url: Url },
}

async fn submit(url: &Url) -> Result<()> {
    let wallet = Wallet::new();
    println!(
        "{} {}Request...",
        style("[1/2]").bold().dim(),
        Emoji("➡️ ", "")
    );
    let request_response = wallet.request(url).await?;

    let permitted_items: PermittedItems = request_response
        .requested_items
        .clone()
        .into_iter()
        .map(|req| {
            let namespaces = req
                .namespaces
                .into_inner()
                .into_iter()
                .map(|(ns, es)| {
                    let ids = es.into_inner().into_keys().collect();
                    (ns, ids)
                })
                .collect();
            (req.doc_type, namespaces)
        })
        .collect();
    if !Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(format!(
            "Do you want to shared the following information: {:?}?",
            permitted_items,
        ))
        .report(false)
        .interact()?
    {
        return Err(anyhow!("Exchange aborted."));
    }

    println!(
        "{} {}Response...",
        style("[2/2]").bold().dim(),
        Emoji("➡️ ", "")
    );
    match wallet
        .response(
            &request_response.request_object,
            &request_response.manager,
            &request_response.requested_items,
            permitted_items,
        )
        .await?
    {
        ResponseRedirectType::Post => Ok(()),
        ResponseRedirectType::InApp(url) => {
            let url_str = url.to_string();
            if !Confirm::new()
                .with_prompt(format!("You will now be redirected to: {}", url_str,))
                .interact()?
            {
                return Err(anyhow!("Exchange aborted."));
            }
            open::that(url_str)?;
            Ok(())
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match &cli.command {
        Commands::Wallet { command } => match command {
            WalletCommands::Submit { url } => submit(url).await,
        },
    }
}

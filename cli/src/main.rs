use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use console::{style, Emoji};
use dialoguer::Confirm;
use isomdl_18013_7::{isomdl::presentation::device::PermittedItems, RedirectType, Wallet};
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
    let redirect_type = wallet.request(url).await?;
    let (request_object, requested_items, manager) = match redirect_type {
        RedirectType::Post {
            request_object,
            requested_items,
            manager,
        } => (request_object, requested_items, manager),
        isomdl_18013_7::RedirectType::InApp(_) => Err(anyhow!("Unsupported in-app redirect flow"))?,
    };

    let permitted_items: PermittedItems = requested_items
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
    if !Confirm::new()
        .with_prompt(format!(
            "Do you want to shared the following information: {:?}?",
            permitted_items,
        ))
        .interact()?
    {
        return Err(anyhow!("Exchange aborted."));
    }

    println!(
        "{} {}Response...",
        style("[2/2]").bold().dim(),
        Emoji("➡️ ", "")
    );
    wallet
        .response(&request_object, &manager, &requested_items, permitted_items)
        .await?;
    Ok(())
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

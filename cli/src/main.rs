use anyhow::Result;
use clap::{Parser, Subcommand};
use console::{style, Emoji};
use isomdl_18013_7::Wallet;
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
    let wallet = Wallet {
        client: reqwest::Client::new(),
    };
    println!(
        "{} {}Request...",
        style("[1/2]").bold().dim(),
        Emoji("➡️ ", "")
    );
    let request_object = wallet.request(url).await?;
    println!(
        "{} {}Response...",
        style("[2/2]").bold().dim(),
        Emoji("➡️ ", "")
    );
    wallet.response(request_object).await?;
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

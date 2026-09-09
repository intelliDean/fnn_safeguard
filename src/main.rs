#![allow(dead_code, unused_imports)]

use anyhow::Result;
use clap::Parser;
use fnn_safeguard::cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize structured logging without printing sensitive keys
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    cli.dispatch().await
}

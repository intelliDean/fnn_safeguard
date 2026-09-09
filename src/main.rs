#![allow(dead_code, unused_imports)]

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

mod commands;
mod config;
mod core;
mod isolation;
mod rpc;

#[derive(Parser, Debug)]
#[command(
    name = "fnn-safeguard",
    version,
    about = "Verified Recovery Points and Pre-Upgrade Qualification for Fiber Network Nodes",
    long_about = "FNN Safeguard verifies Fiber node backups, generates cryptographic manifests, tests restores in isolated environments with blocked P2P egress, and qualifies upgrades."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Collects a non-secret inventory of the running Fiber node
    Inspect(InspectArgs),

    /// Validates an official FNN backup, checks completeness, and generates a manifest
    Backup(BackupArgs),

    /// Executes an isolated restore drill with Fiber P2P networking blocked
    Drill(DrillArgs),
}

#[derive(Args, Debug)]
struct InspectArgs {
    /// FNN JSON-RPC 2.0 endpoint URL
    #[arg(long, default_value = "http://127.0.0.1:8227", env = "FNN_RPC_URL")]
    rpc_url: String,

    /// Optional Biscuit authorization token for RPC
    #[arg(long, env = "FNN_AUTH_TOKEN")]
    auth_token: Option<String>,

    /// Path to active FNN config file (for checksum calculation)
    #[arg(long, default_value = "config.yml")]
    config: PathBuf,

    /// Base node directory (defaults to current directory)
    #[arg(long, default_value = ".")]
    node_dir: PathBuf,

    /// Output report in machine-readable JSON format
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct BackupArgs {
    /// Perform full cryptographic and structural verification
    #[arg(long, default_value_t = true)]
    verify: bool,

    /// Specific backup directory to verify (defaults to latest in node-dir)
    #[arg(long)]
    backup_dir: Option<PathBuf>,

    /// Node directory containing the backups/ folder
    #[arg(long, default_value = ".")]
    node_dir: PathBuf,

    /// Trigger an immediate backup via FNN admin RPC before verifying
    #[arg(long)]
    trigger: bool,

    /// FNN JSON-RPC 2.0 URL (used if --trigger is specified)
    #[arg(long, default_value = "http://127.0.0.1:8227", env = "FNN_RPC_URL")]
    rpc_url: String,

    /// Optional Biscuit authorization token
    #[arg(long, env = "FNN_AUTH_TOKEN")]
    auth_token: Option<String>,

    /// Path to config file for manifest checksum
    #[arg(long, default_value = "config.yml")]
    config: PathBuf,

    /// Expected node public key (hex) to verify key derivation
    #[arg(long)]
    expected_pubkey: Option<String>,

    /// Output report in JSON format
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct DrillArgs {
    /// Recovery point to restore ('latest' or specific backup path)
    #[arg(long, default_value = "latest")]
    backup: String,

    /// Node base directory to discover latest backup
    #[arg(long, default_value = ".")]
    node_dir: PathBuf,

    /// Path to an official fnn binary for native --restore execution
    #[arg(long)]
    fnn_bin: Option<PathBuf>,

    /// Execute drill inside an isolated Docker container with --network none
    #[arg(long)]
    docker: bool,

    /// Docker image to use for container drill
    #[arg(long)]
    docker_image: Option<String>,

    /// Output report in JSON format
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging without printing sensitive keys
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Inspect(args) => {
            commands::InspectCommand::run(commands::InspectOptions {
                rpc_url: args.rpc_url,
                auth_token: args.auth_token,
                config_path: Some(args.config),
                node_dir: Some(args.node_dir),
                json_output: args.json,
            })
            .await?;
        }
        Commands::Backup(args) => {
            commands::BackupCommand::run(commands::BackupOptions {
                backup_dir: args.backup_dir,
                node_dir: Some(args.node_dir),
                trigger_rpc: args.trigger,
                rpc_url: Some(args.rpc_url),
                auth_token: args.auth_token,
                config_path: Some(args.config),
                expected_pubkey: args.expected_pubkey,
                json_output: args.json,
            })
            .await?;
        }
        Commands::Drill(args) => {
            commands::DrillCommand::run(commands::DrillOptions {
                backup_path: Some(args.backup),
                node_dir: Some(args.node_dir),
                fnn_bin: args.fnn_bin,
                use_docker: args.docker,
                docker_image: args.docker_image,
                json_output: args.json,
            })
            .await?;
        }
    }

    Ok(())
}

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

use crate::commands::{
    BackupCommand, BackupOptions, DrillCommand, DrillOptions, InspectCommand, InspectOptions,
};

#[derive(Parser, Debug)]
#[command(
    name = "fnn-safeguard",
    version,
    about = "Verified Recovery Points and Pre-Upgrade Qualification for Fiber Network Nodes",
    long_about = "FNN Safeguard verifies Fiber node backups, generates cryptographic manifests, tests restores in isolated environments with blocked P2P egress, and qualifies upgrades."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

impl Cli {
    pub async fn dispatch(self) -> Result<()> {
        match self.command {
            Commands::Inspect(args) => {
                InspectCommand::run(args.into()).await?;
            }
            Commands::Backup(args) => {
                BackupCommand::run(args.into()).await?;
            }
            Commands::Drill(args) => {
                DrillCommand::run(args.into()).await?;
            }
        }
        Ok(())
    }
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Collects a non-secret inventory of the running Fiber node
    Inspect(InspectArgs),

    /// Validates an official FNN backup, checks completeness, and generates a manifest
    Backup(BackupArgs),

    /// Executes an isolated restore drill with Fiber P2P networking blocked
    Drill(DrillArgs),
}

#[derive(Args, Debug)]
pub struct InspectArgs {
    /// FNN JSON-RPC 2.0 endpoint URL
    #[arg(long, default_value = "http://127.0.0.1:8227", env = "FNN_RPC_URL")]
    pub rpc_url: String,

    /// Optional Biscuit authorization token for RPC
    #[arg(long, env = "FNN_AUTH_TOKEN")]
    pub auth_token: Option<String>,

    /// Path to active FNN config file (for checksum calculation)
    #[arg(long, default_value = "config.yml")]
    pub config: PathBuf,

    /// Base node directory (defaults to current directory)
    #[arg(long, default_value = ".")]
    pub node_dir: PathBuf,

    /// Output report in machine-readable JSON format
    #[arg(long)]
    pub json: bool,
}

impl From<InspectArgs> for InspectOptions {
    fn from(args: InspectArgs) -> Self {
        Self {
            rpc_url: args.rpc_url,
            auth_token: args.auth_token,
            config_path: Some(args.config),
            node_dir: Some(args.node_dir),
            json_output: args.json,
        }
    }
}

#[derive(Args, Debug)]
pub struct BackupArgs {
    /// Perform full cryptographic and structural verification
    #[arg(long, default_value_t = true)]
    pub verify: bool,

    /// Specific backup directory to verify (defaults to latest in node-dir)
    #[arg(long)]
    pub backup_dir: Option<PathBuf>,

    /// Node directory containing the backups/ folder
    #[arg(long, default_value = ".")]
    pub node_dir: PathBuf,

    /// Trigger an immediate backup via FNN admin RPC before verifying
    #[arg(long)]
    pub trigger: bool,

    /// FNN JSON-RPC 2.0 URL (used if --trigger is specified)
    #[arg(long, default_value = "http://127.0.0.1:8227", env = "FNN_RPC_URL")]
    pub rpc_url: String,

    /// Optional Biscuit authorization token
    #[arg(long, env = "FNN_AUTH_TOKEN")]
    pub auth_token: Option<String>,

    /// Path to config file for manifest checksum
    #[arg(long, default_value = "config.yml")]
    pub config: PathBuf,

    /// Expected node public key (hex) to verify key derivation
    #[arg(long)]
    pub expected_pubkey: Option<String>,

    /// Output report in JSON format
    #[arg(long)]
    pub json: bool,
}

impl From<BackupArgs> for BackupOptions {
    fn from(args: BackupArgs) -> Self {
        Self {
            backup_dir: args.backup_dir,
            node_dir: Some(args.node_dir),
            trigger_rpc: args.trigger,
            rpc_url: Some(args.rpc_url),
            auth_token: args.auth_token,
            config_path: Some(args.config),
            expected_pubkey: args.expected_pubkey,
            json_output: args.json,
        }
    }
}

#[derive(Args, Debug)]
pub struct DrillArgs {
    /// Recovery point to restore ('latest' or specific backup path)
    #[arg(long, default_value = "latest")]
    pub backup: String,

    /// Node base directory to discover latest backup
    #[arg(long, default_value = ".")]
    pub node_dir: PathBuf,

    /// Path to an official fnn binary for native --restore execution
    #[arg(long)]
    pub fnn_bin: Option<PathBuf>,

    /// Execute drill inside an isolated Docker container with --network none
    #[arg(long)]
    pub docker: bool,

    /// Docker image to use for container drill
    #[arg(long)]
    pub docker_image: Option<String>,

    /// Output report in JSON format
    #[arg(long)]
    pub json: bool,
}

impl From<DrillArgs> for DrillOptions {
    fn from(args: DrillArgs) -> Self {
        Self {
            backup_path: Some(args.backup),
            node_dir: Some(args.node_dir),
            fnn_bin: args.fnn_bin,
            use_docker: args.docker,
            docker_image: args.docker_image,
            json_output: args.json,
        }
    }
}

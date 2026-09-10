use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::config::ConfigSanitizer;
use crate::core::reporter::{CheckStatus, TerminalReporter};
use crate::rpc::client::FnnRpcClient;
use crate::rpc::types::ChannelInfo;

#[derive(Debug, Clone)]
pub struct InspectOptions {
    pub rpc_url: String,
    pub auth_token: Option<String>,
    pub config_path: Option<PathBuf>,
    pub node_dir: Option<PathBuf>,
    pub json_output: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct InspectReport {
    pub node_public_key: String,
    pub fnn_version: String,
    pub fnn_commit: String,
    pub network: String,
    pub ready_channels: usize,
    pub stale_channels: usize,
    pub total_channels: usize,
    pub total_payments: usize,
    pub config_checksum: String,
    pub latest_backup_path: Option<String>,
    pub backup_age_description: String,
    pub recovery_status: String,
}

#[derive(Default)]
struct ChannelCounts {
    ready: usize,
    stale: usize,
    total: usize,
}

struct BackupFreshness {
    latest_path: Option<String>,
    age_description: String,
    status: String,
}

pub struct InspectCommand;

impl InspectCommand {
    pub async fn run(opts: InspectOptions) -> Result<InspectReport> {
        let client = FnnRpcClient::new(&opts.rpc_url, opts.auth_token)?;

        let node_info =
            client.node_info().await.context("Failed to fetch node_info from FNN RPC")?;

        let channel_res =
            client.list_channels(None).await.context("Failed to list channels from FNN RPC")?;
        let channel_counts = Self::aggregate_channels(&channel_res.channels);

        let payments = client
            .list_all_payments(None, None)
            .await
            .context("Failed to query payments from FNN RPC")?;
        let total_payments = payments.len();

        let config_file = opts.config_path.unwrap_or_else(|| PathBuf::from("config.yml"));
        let (config_checksum, _) = ConfigSanitizer::sanitize_and_hash(&config_file)?;

        let freshness = Self::evaluate_backup_freshness(opts.node_dir.as_deref());

        let report = InspectReport {
            node_public_key: node_info.pubkey.clone(),
            fnn_version: node_info.version.clone(),
            fnn_commit: node_info.commit_hash.clone(),
            network: if node_info.chain_hash.starts_with("0x92b1") {
                "mainnet".to_string()
            } else {
                "testnet".to_string()
            },
            ready_channels: channel_counts.ready,
            stale_channels: channel_counts.stale,
            total_channels: channel_counts.total,
            total_payments,
            config_checksum,
            latest_backup_path: freshness.latest_path,
            backup_age_description: freshness.age_description,
            recovery_status: freshness.status,
        };

        Self::render_report(&report, opts.json_output);

        Ok(report)
    }

    /// Aggregates channel counts by status (Ready / ChannelReady, Stale, Total).
    fn aggregate_channels(channels: &[ChannelInfo]) -> ChannelCounts {
        let mut ready = 0;
        let mut stale = 0;
        for ch in channels {
            if ch.state.is_ready() {
                ready += 1;
            } else if ch.state.is_stale() {
                stale += 1;
            }
        }

        ChannelCounts { ready, stale, total: channels.len() }
    }

    /// Discovers and formats backup freshness from disk.
    fn evaluate_backup_freshness(node_dir: Option<&Path>) -> BackupFreshness {
        let search_dir = node_dir.unwrap_or_else(|| Path::new("."));
        let latest = ConfigSanitizer::discover_latest_backup(search_dir);

        let Some(path) = latest else {
            return BackupFreshness {
                latest_path: None,
                age_description: "No backup discovered".to_string(),
                status: "WARN".to_string(),
            };
        };

        let path_str = path.display().to_string();
        let mut age_desc = "Discovered".to_string();
        let mut status = "PASS".to_string();

        let opt_dt = path
            .file_name()
            .and_then(|f| f.to_str())
            .and_then(|name| name.parse::<i64>().ok())
            .and_then(DateTime::from_timestamp_millis);

        if let Some(dt) = opt_dt {
            let duration = Utc::now().signed_duration_since(dt);
            let mins = duration.num_minutes();
            if mins < 60 {
                age_desc = format!("{} minutes ago", mins.max(1));
            } else {
                age_desc = format!("{} hours ago", duration.num_hours());
            }
            status = "PASS".to_string();
        }

        BackupFreshness { latest_path: Some(path_str), age_description: age_desc, status }
    }

    /// Formats the inspection report for terminal display or JSON.
    fn render_report(report: &InspectReport, json_output: bool) {
        if json_output {
            TerminalReporter::print_json(report);
            return;
        }

        let commit_preview = &report.fnn_commit[0..7.min(report.fnn_commit.len())];

        TerminalReporter::header("FNN Safeguard: Node Inspection Report");
        TerminalReporter::row("Node public key:", &report.node_public_key);
        TerminalReporter::row(
            "FNN version:",
            format!("{} ({})", report.fnn_version, commit_preview),
        );
        TerminalReporter::row("Network:", &report.network);
        TerminalReporter::row("Ready channels:", report.ready_channels);
        TerminalReporter::row("Stale channels:", report.stale_channels);
        TerminalReporter::row("Total payments:", report.total_payments);
        TerminalReporter::row("Config checksum:", &report.config_checksum);
        TerminalReporter::row("Latest recovery point:", &report.backup_age_description);
        TerminalReporter::status_row(
            "Recovery status:",
            if report.recovery_status == "PASS" { CheckStatus::Pass } else { CheckStatus::Warn },
            None,
        );
        TerminalReporter::footer(report.recovery_status == "PASS", &report.recovery_status);
    }
}

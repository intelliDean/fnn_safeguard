use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::config::ConfigSanitizer;
use crate::core::reporter::{CheckStatus, TerminalReporter};
use crate::rpc::client::FnnRpcClient;

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

pub struct InspectCommand;

impl InspectCommand {
    pub async fn run(
        rpc_url: &str,
        auth_token: Option<String>,
        config_path: Option<PathBuf>,
        node_dir: Option<PathBuf>,
        json_output: bool,
    ) -> Result<InspectReport> {
        let client = FnnRpcClient::new(rpc_url, auth_token)?;

        // 1. Fetch live node info
        let node_info = client
            .node_info()
            .await
            .context("Failed to fetch node_info from FNN RPC")?;

        // 2. Fetch channels
        let channel_res = client.list_channels(None).await.unwrap_or_default();
        let mut channel_counts: HashMap<String, usize> = HashMap::new();
        for ch in &channel_res.channels {
            *channel_counts.entry(ch.state.as_str().to_string()).or_insert(0) += 1;
        }

        let ready_channels = *channel_counts.get("Ready").unwrap_or(&0);
        let stale_channels = *channel_counts.get("Stale").unwrap_or(&0);
        let total_channels = channel_res.channels.len();

        // 3. Fetch payments
        let payment_res = client.list_payments(None).await.unwrap_or_default();
        let total_payments = payment_res.payments.len();

        // 4. Hash configuration without printing secrets
        let config_file = config_path.unwrap_or_else(|| PathBuf::from("config.yml"));
        let (config_checksum, _) = ConfigSanitizer::sanitize_and_hash(&config_file)?;

        // 5. Detect latest backup if node_dir is provided
        let mut latest_backup_str = None;
        let mut backup_age_desc = "No backup discovered".to_string();
        let mut recovery_status = "WARN".to_string();

        let search_dir = node_dir.unwrap_or_else(|| PathBuf::from("."));
        if let Some(latest) = ConfigSanitizer::discover_latest_backup(&search_dir) {
            let path_str = latest.display().to_string();
            latest_backup_str = Some(path_str);
            if let Some(file_name) = latest.file_name().and_then(|f| f.to_str()) {
                if let Ok(millis) = file_name.parse::<i64>() {
                    if let Some(dt) = DateTime::from_timestamp_millis(millis) {
                        let duration = Utc::now().signed_duration_since(dt);
                        let mins = duration.num_minutes();
                        if mins < 60 {
                            backup_age_desc = format!("{} minutes ago", mins.max(1));
                        } else {
                            backup_age_desc = format!("{} hours ago", duration.num_hours());
                        }
                        recovery_status = "PASS".to_string();
                    }
                }
            }
            if backup_age_desc == "No backup discovered" {
                backup_age_desc = "Discovered".to_string();
                recovery_status = "PASS".to_string();
            }
        }

        let report = InspectReport {
            node_public_key: node_info.pubkey.clone(),
            fnn_version: node_info.version.clone(),
            fnn_commit: node_info.commit_hash.clone(),
            network: if node_info.chain_hash.starts_with("0x92b1") {
                "mainnet".to_string()
            } else {
                "testnet".to_string()
            },
            ready_channels,
            stale_channels,
            total_channels,
            total_payments,
            config_checksum,
            latest_backup_path: latest_backup_str,
            backup_age_description: backup_age_desc,
            recovery_status,
        };

        if json_output {
            TerminalReporter::print_json(&report);
        } else {
            TerminalReporter::header("FNN Safeguard: Node Inspection Report");
            TerminalReporter::row("Node public key:", &report.node_public_key);
            TerminalReporter::row("FNN version:", format!("{} ({})", report.fnn_version, &report.fnn_commit[0..7.min(report.fnn_commit.len())]));
            TerminalReporter::row("Network:", &report.network);
            TerminalReporter::row("Ready channels:", report.ready_channels);
            TerminalReporter::row("Stale channels:", report.stale_channels);
            TerminalReporter::row("Total payments:", report.total_payments);
            TerminalReporter::row("Config checksum:", &report.config_checksum);
            TerminalReporter::row("Latest recovery point:", &report.backup_age_description);
            TerminalReporter::status_row(
                "Recovery status:",
                if report.recovery_status == "PASS" {
                    CheckStatus::Pass
                } else {
                    CheckStatus::Warn
                },
                None,
            );
            TerminalReporter::footer(report.recovery_status == "PASS", &report.recovery_status);
        }

        Ok(report)
    }
}

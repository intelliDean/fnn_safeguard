use anyhow::{bail, Context, Result};
use colored::Colorize;
use serde::Serialize;
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::sleep;

use crate::config::ConfigSanitizer;
use crate::core::reporter::{CheckStatus, TerminalReporter};
use crate::core::validator::BackupValidator;
use crate::rpc::client::FnnRpcClient;

#[derive(Debug, Clone, Serialize)]
pub struct BackupVerificationReport {
    pub backup_dir: String,
    pub is_valid: bool,
    pub node_public_key: String,
    pub database_type: String,
    pub total_bytes: u64,
    pub file_count: usize,
    pub bundle_checksum: String,
    pub manifest_path: String,
    pub errors: Vec<String>,
}

pub struct BackupCommand;

impl BackupCommand {
    pub async fn run(
        backup_dir: Option<PathBuf>,
        node_dir: Option<PathBuf>,
        trigger_rpc: bool,
        rpc_url: Option<&str>,
        auth_token: Option<String>,
        config_path: Option<PathBuf>,
        expected_pubkey: Option<String>,
        json_output: bool,
    ) -> Result<BackupVerificationReport> {
        // 1. If trigger_rpc is requested, invoke admin.backup
        if trigger_rpc {
            let url = rpc_url.unwrap_or("http://127.0.0.1:8227");
            let client = FnnRpcClient::new(url, auth_token)?;
            client.trigger_backup().await.context("Failed to trigger FNN admin backup via RPC")?;
            // Allow brief moment for disk checkpoint to complete
            sleep(Duration::from_millis(500)).await;
        }

        // 2. Resolve backup directory
        let resolved_dir = if let Some(dir) = backup_dir {
            dir
        } else {
            let base = node_dir.unwrap_or_else(|| PathBuf::from("."));
            ConfigSanitizer::discover_latest_backup(&base)
                .ok_or_else(|| anyhow::anyhow!("No backup directory found in {:?}", base))?
        };

        if !resolved_dir.exists() {
            bail!("Backup directory does not exist: {:?}", resolved_dir);
        }

        // 3. Inspect and validate completeness
        let validation = BackupValidator::inspect_and_validate(&resolved_dir, expected_pubkey.as_deref())?;

        // 4. Compute config checksum
        let config_file = config_path.unwrap_or_else(|| PathBuf::from("config.yml"));
        let (config_checksum, _) = ConfigSanitizer::sanitize_and_hash(&config_file)?;

        // 5. Generate & save manifest if valid
        let (bundle_checksum, manifest_path) = if validation.is_valid {
            let manifest = BackupValidator::build_manifest(
                &resolved_dir,
                "testnet", // Default, or read from node_info
                "v0.9.0",
                "e6cb7ac",
                &config_checksum,
                None,
                None,
                expected_pubkey.as_deref(),
            )?;
            let path = manifest.save_to_dir(&resolved_dir)?;
            (manifest.bundle_checksum, path.display().to_string())
        } else {
            (String::new(), String::new())
        };

        let report = BackupVerificationReport {
            backup_dir: resolved_dir.display().to_string(),
            is_valid: validation.is_valid,
            node_public_key: validation.derived_pubkey.clone(),
            database_type: validation.database_type.clone(),
            total_bytes: validation.total_bytes,
            file_count: validation.file_count,
            bundle_checksum,
            manifest_path,
            errors: validation.errors.clone(),
        };

        if json_output {
            TerminalReporter::print_json(&report);
        } else {
            TerminalReporter::header("FNN Safeguard: Backup Verification Report");
            TerminalReporter::row("Backup directory:", &report.backup_dir);
            TerminalReporter::status_row(
                "Backup completeness:",
                if report.is_valid { CheckStatus::Pass } else { CheckStatus::Fail },
                None,
            );
            TerminalReporter::row("Database type:", &report.database_type);
            TerminalReporter::row("Node public key:", if report.node_public_key.is_empty() { "N/A" } else { &report.node_public_key });
            TerminalReporter::row("Total files / size:", format!("{} files ({} bytes)", report.file_count, report.total_bytes));
            if report.is_valid {
                TerminalReporter::row("Bundle checksum:", &report.bundle_checksum);
                TerminalReporter::row("Manifest generated:", &report.manifest_path);
            } else {
                for err in &report.errors {
                    println!("  {} {}", "[ERROR]".red().bold(), err);
                }
            }
            TerminalReporter::footer(report.is_valid, if report.is_valid { "PASS" } else { "REJECTED" });
        }

        if !report.is_valid {
            bail!("Backup verification failed: {:?}", report.errors);
        }

        Ok(report)
    }
}

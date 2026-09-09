use anyhow::{bail, Context, Result, anyhow};
use colored::Colorize;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time::sleep;

use crate::config::ConfigSanitizer;
use crate::core::reporter::{CheckStatus, TerminalReporter};
use crate::core::validator::{BackupValidationResult, BackupValidator, BuildManifestParams};
use crate::rpc::client::FnnRpcClient;

#[derive(Debug, Clone)]
pub struct BackupOptions {
    pub backup_dir: Option<PathBuf>,
    pub node_dir: Option<PathBuf>,
    pub trigger_rpc: bool,
    pub rpc_url: Option<String>,
    pub auth_token: Option<String>,
    pub config_path: Option<PathBuf>,
    pub expected_pubkey: Option<String>,
    pub json_output: bool,
}

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
    pub async fn run(opts: BackupOptions) -> Result<BackupVerificationReport> {
        if opts.trigger_rpc {
            Self::trigger_admin_backup(opts.rpc_url.as_deref(), opts.auth_token.clone()).await?;
        }

        let resolved_dir = Self::resolve_backup_dir(opts.backup_dir.as_deref(), opts.node_dir.as_deref())?;
        let validation = BackupValidator::inspect_and_validate(&resolved_dir, opts.expected_pubkey.as_deref())?;

        let config_file = opts.config_path.unwrap_or_else(|| PathBuf::from("config.yml"));
        let (config_checksum, _) = ConfigSanitizer::sanitize_and_hash(&config_file)?;

        let (bundle_checksum, manifest_path) = if validation.is_valid {
            Self::generate_manifest(&resolved_dir, &config_checksum, opts.expected_pubkey.as_deref())?
        } else {
            (String::new(), String::new())
        };

        let report = Self::build_report(&resolved_dir, &validation, bundle_checksum, manifest_path);
        Self::render_report(&report, opts.json_output);

        if !report.is_valid {
            bail!("Backup verification failed: {:?}", report.errors);
        }

        Ok(report)
    }

    /// Triggers an immediate point-in-time backup via FNN admin RPC.
    async fn trigger_admin_backup(rpc_url: Option<&str>, auth_token: Option<String>) -> Result<()> {
        let url = rpc_url.unwrap_or("http://127.0.0.1:8227");
        let client = FnnRpcClient::new(url, auth_token)?;
        client.trigger_backup().await.context("Failed to trigger FNN admin backup via RPC")?;
        // Brief pause to allow the disk checkpoint to flush
        sleep(Duration::from_millis(500)).await;
        Ok(())
    }

    /// Resolves the backup directory from either an explicit path or auto-discovery.
    fn resolve_backup_dir(backup_dir: Option<&Path>, node_dir: Option<&Path>) -> Result<PathBuf> {
        let dir = if let Some(dir) = backup_dir {
            dir.to_path_buf()
        } else {
            let base = node_dir.unwrap_or_else(|| Path::new("."));
            ConfigSanitizer::discover_latest_backup(base)
                .ok_or_else(|| anyhow!("No backup directory found in {:?}", base))?
        };

        if !dir.exists() {
            bail!("Backup directory does not exist: {:?}", dir);
        }

        Ok(dir)
    }

    /// Constructs and saves a cryptographic manifest for a valid backup.
    fn generate_manifest(
        backup_dir: &Path,
        config_checksum: &str,
        expected_pubkey: Option<&str>,
    ) -> Result<(String, String)> {
        let params = BuildManifestParams {
            network: "testnet",
            fnn_version: "v0.9.0",
            fnn_commit: "e6cb7ac",
            config_checksum,
            channel_count: None,
            payment_count: None,
            expected_pubkey,
        };
        let manifest = BackupValidator::build_manifest(backup_dir, &params)?;
        let path = manifest.save_to_dir(backup_dir)?;
        Ok((manifest.bundle_checksum, path.display().to_string()))
    }

    fn build_report(
        backup_dir: &Path,
        validation: &BackupValidationResult,
        bundle_checksum: String,
        manifest_path: String,
    ) -> BackupVerificationReport {
        BackupVerificationReport {
            backup_dir: backup_dir.display().to_string(),
            is_valid: validation.is_valid,
            node_public_key: validation.derived_pubkey.clone(),
            database_type: validation.database_type.clone(),
            total_bytes: validation.total_bytes,
            file_count: validation.file_count,
            bundle_checksum,
            manifest_path,
            errors: validation.errors.clone(),
        }
    }

    fn render_report(report: &BackupVerificationReport, json_output: bool) {
        if json_output {
            TerminalReporter::print_json(report);
            return;
        }

        TerminalReporter::header("FNN Safeguard: Backup Verification Report");
        TerminalReporter::row("Backup directory:", &report.backup_dir);
        TerminalReporter::status_row(
            "Backup completeness:",
            if report.is_valid { CheckStatus::Pass } else { CheckStatus::Fail },
            None,
        );
        TerminalReporter::row("Database type:", &report.database_type);
        TerminalReporter::row(
            "Node public key:",
            if report.node_public_key.is_empty() { "N/A" } else { &report.node_public_key },
        );
        TerminalReporter::row(
            "Total files / size:",
            format!("{} files ({} bytes)", report.file_count, report.total_bytes),
        );

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
}

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use colored::Colorize;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time::sleep;

use crate::config::ConfigSanitizer;
use crate::core::reporter::{CheckStatus, TerminalReporter};
use crate::core::validator::{BackupValidationResult, BackupValidator, BuildManifestParams};
use crate::rpc::client::FnnRpcClient;
use crate::rpc::types::{ChannelInfo, PaymentInfo};

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
    pub qualification: String,
    pub node_public_key: String,
    pub network: String,
    pub fnn_version: String,
    pub database_type: String,
    pub total_bytes: u64,
    pub file_count: usize,
    pub bundle_checksum: String,
    pub manifest_path: String,
    pub manifest_verified: bool,
    pub errors: Vec<String>,
}

#[derive(Debug, Default)]
struct RpcCaptures {
    pub node_info_json: serde_json::Value,
    pub channels_json: serde_json::Value,
    pub payments_json: serde_json::Value,
}

#[derive(Debug, Clone, Default)]
struct LiveNodeData {
    pub node_pubkey: Option<String>,
    pub network: Option<String>,
    pub version: Option<String>,
    pub commit: Option<String>,
    pub ready_channels: Option<u32>,
    pub total_payments: Option<u32>,
    pub channel_id_digest: Option<String>,
    pub payment_hash_digest: Option<String>,
    pub channel_state_distribution: Option<HashMap<String, u32>>,
    pub payment_status_distribution: Option<HashMap<String, u32>>,
    pub raw_channels: Vec<ChannelInfo>,
    pub raw_payments: Vec<PaymentInfo>,
}

pub struct BackupCommand;

impl BackupCommand {
    pub async fn run(opts: BackupOptions) -> Result<BackupVerificationReport> {
        let node_base = opts.node_dir.as_deref().unwrap_or_else(|| Path::new("."));
        let parent_dirs = Self::get_backup_parent_dirs(node_base);

        let (live_data, captures) =
            Self::fetch_live_node_data(opts.rpc_url.as_deref(), opts.auth_token.clone()).await;

        let (resolved_dir, backup_response, backup_dir_detected) = if opts.trigger_rpc {
            let existing_dirs = Self::list_existing_backup_dirs(&parent_dirs);
            let trigger_ts = Utc::now();
            let backup_rpc_result =
                Self::trigger_admin_backup(opts.rpc_url.as_deref(), opts.auth_token.clone()).await;
            let backup_response_json = match &backup_rpc_result {
                Ok(raw) => raw.clone(),
                Err(e) => serde_json::json!({"error": e.to_string()}),
            };
            backup_rpc_result.context("Failed to trigger FNN admin backup via RPC")?;
            let new_dir =
                Self::wait_for_new_backup(&parent_dirs, &existing_dirs, Duration::from_secs(15))
                    .await?;
            let detected_json = serde_json::json!({
                "triggered_at": trigger_ts.to_rfc3339(),
                "detected_at": Utc::now().to_rfc3339(),
                "backup_dir": new_dir.display().to_string(),
            });
            (new_dir, backup_response_json, Some(detected_json))
        } else {
            let dir =
                Self::resolve_backup_dir(opts.backup_dir.as_deref(), opts.node_dir.as_deref())?;
            (dir, serde_json::Value::Null, None)
        };

        // Write sanitized raw RPC capture files into the backup directory
        Self::write_rpc_captures(
            &resolved_dir,
            &captures,
            &backup_response,
            backup_dir_detected,
        )?;

        // If dev.toml exists in node_dir, copy it into the backup directory so standalone restores have chain spec
        if let Some(nd) = opts.node_dir.as_deref() {
            let dev_toml = nd.join("dev.toml");
            if dev_toml.exists() {
                let _ = fs::copy(&dev_toml, resolved_dir.join("dev.toml"));
            }
        }

        let validation =
            BackupValidator::inspect_and_validate(&resolved_dir, opts.expected_pubkey.as_deref())?;

        let config_file = opts
            .config_path
            .unwrap_or_else(|| PathBuf::from("config.yml"));
        let (config_checksum, _) = ConfigSanitizer::sanitize_and_hash(&config_file)
            .unwrap_or_else(|_| ("sha256:unknown".to_string(), String::new()));

        let timestamp = Self::parse_backup_timestamp(&resolved_dir);

        let (bundle_checksum, manifest_path, manifest_verified, manifest_errors) =
            if validation.is_valid {
                Self::generate_and_verify_manifest(
                    &resolved_dir,
                    &config_checksum,
                    &validation,
                    &live_data,
                    timestamp,
                    opts.expected_pubkey.as_deref(),
                )?
            } else {
                (String::new(), String::new(), false, Vec::new())
            };

        let mut combined_errors = validation.errors.clone();
        combined_errors.extend(manifest_errors);
        let overall_valid = validation.is_valid && manifest_verified && combined_errors.is_empty();

        let is_live = live_data.version.is_some() && live_data.network.is_some();
        let qualification = if is_live {
            "LIVE_NODE_QUALIFIED".to_string()
        } else {
            "STRUCTURAL_ONLY".to_string()
        };
        let network = live_data.network.unwrap_or_else(|| "UNKNOWN".to_string());
        let version = live_data.version.unwrap_or_else(|| "UNKNOWN".to_string());

        let report = BackupVerificationReport {
            backup_dir: resolved_dir.display().to_string(),
            is_valid: overall_valid,
            qualification,
            node_public_key: validation.derived_pubkey.clone(),
            network,
            fnn_version: version,
            database_type: validation.database_type.clone(),
            total_bytes: validation.total_bytes,
            file_count: validation.file_count,
            bundle_checksum,
            manifest_path,
            manifest_verified,
            errors: combined_errors,
        };

        Self::render_report(&report, opts.json_output);

        if !report.is_valid {
            bail!("Backup verification failed: {:?}", report.errors);
        }

        Ok(report)
    }

    /// Queries live node information, channels, and payments via RPC.
    /// Returns structured inventory data with digests plus raw sanitized captures.
    async fn fetch_live_node_data(
        rpc_url: Option<&str>,
        auth_token: Option<String>,
    ) -> (LiveNodeData, RpcCaptures) {
        let url = rpc_url.unwrap_or("http://127.0.0.1:8227");
        let Ok(client) = FnnRpcClient::new(url, auth_token) else {
            return (LiveNodeData::default(), RpcCaptures::default());
        };

        let Ok(node_info) = client.node_info().await else {
            return (LiveNodeData::default(), RpcCaptures::default());
        };

        let network = if node_info.chain_hash.starts_with("0x92b1") {
            "mainnet".to_string()
        } else {
            "testnet".to_string()
        };

        // Safe to capture in full — node_info contains no private keys
        let node_info_json = serde_json::to_value(&node_info).unwrap_or(serde_json::Value::Null);

        let (channels, channels_json) = match client.list_channels(None).await {
            Ok(ch_res) => {
                let json = serde_json::to_value(&ch_res).unwrap_or(serde_json::Value::Null);
                (ch_res.channels, json)
            }
            Err(_) => (Vec::<ChannelInfo>::new(), serde_json::Value::Null),
        };

        let (payments, payments_json) = match client.list_all_payments(None, None).await {
            Ok(pays) => {
                // Sanitize payments: keep payment_hash and status only; redact amounts
                let sanitized: Vec<serde_json::Value> = pays
                    .iter()
                    .map(|p| {
                        serde_json::json!({
                            "payment_hash": p.payment_hash,
                            "status": p.status.map(|s| s.as_str()),
                        })
                    })
                    .collect();
                let json = serde_json::json!({ "payments": sanitized });
                (pays, json)
            }
            Err(_) => (Vec::<PaymentInfo>::new(), serde_json::Value::Null),
        };

        let ready_channels = channels.iter().filter(|ch| ch.state.is_ready()).count() as u32;
        let total_payments = payments.len() as u32;

        // SHA-256 of sorted channel_id list — allows comparison without leaking raw IDs
        let channel_id_digest = if !channels.is_empty() {
            let mut ids: Vec<&str> = channels.iter().map(|c| c.channel_id.as_str()).collect();
            ids.sort_unstable();
            let mut h = Sha256::new();
            for id in &ids {
                h.update(id.as_bytes());
            }
            Some(hex::encode(h.finalize()))
        } else {
            None
        };

        // SHA-256 of sorted payment_hash list
        let payment_hash_digest = if !payments.is_empty() {
            let mut hashes: Vec<&str> = payments.iter().map(|p| p.payment_hash.as_str()).collect();
            hashes.sort_unstable();
            let mut h = Sha256::new();
            for hash in &hashes {
                h.update(hash.as_bytes());
            }
            Some(hex::encode(h.finalize()))
        } else {
            None
        };

        // Channel state distribution: state_name → count
        let channel_state_distribution = if !channels.is_empty() {
            let mut dist: HashMap<String, u32> = HashMap::new();
            for ch in &channels {
                *dist.entry(ch.state.as_str().to_string()).or_insert(0) += 1;
            }
            Some(dist)
        } else {
            None
        };

        // Payment status distribution: status → count
        let payment_status_distribution = if !payments.is_empty() {
            let mut dist: HashMap<String, u32> = HashMap::new();
            for p in &payments {
                let s = p
                    .status
                    .as_ref()
                    .map(|s| s.as_str())
                    .unwrap_or("Unknown")
                    .to_string();
                *dist.entry(s).or_insert(0) += 1;
            }
            Some(dist)
        } else {
            None
        };

        let captures = RpcCaptures {
            node_info_json,
            channels_json,
            payments_json,
        };

        let data = LiveNodeData {
            node_pubkey: Some(node_info.pubkey),
            network: Some(network),
            version: Some(node_info.version),
            commit: Some(node_info.commit_hash),
            ready_channels: Some(ready_channels),
            total_payments: Some(total_payments),
            channel_id_digest,
            payment_hash_digest,
            channel_state_distribution,
            payment_status_distribution,
            raw_channels: channels,
            raw_payments: payments,
        };

        (data, captures)
    }

    /// Writes sanitized raw RPC capture files into the backup directory.
    fn write_rpc_captures(
        backup_dir: &Path,
        captures: &RpcCaptures,
        backup_response: &serde_json::Value,
        backup_dir_detected: Option<serde_json::Value>,
    ) -> Result<()> {
        let write_if_non_null = |filename: &str, val: &serde_json::Value| -> Result<()> {
            if val.is_null() {
                return Ok(());
            }
            let path = backup_dir.join(filename);
            fs::write(&path, serde_json::to_string_pretty(val)?)
                .with_context(|| format!("Failed to write {filename} to backup dir"))?;
            Ok(())
        };

        write_if_non_null("rpc-node-info.json", &captures.node_info_json)?;
        write_if_non_null("rpc-list-channels.json", &captures.channels_json)?;
        write_if_non_null("rpc-list-payments.json", &captures.payments_json)?;
        write_if_non_null("rpc-backup-response.json", backup_response)?;
        if let Some(detected) = backup_dir_detected {
            write_if_non_null("rpc-backup-dir-detected.json", &detected)?;
        }

        Ok(())
    }

    /// Triggers an immediate point-in-time backup via FNN admin RPC.
    /// Returns the raw JSON response for capture in rpc-backup-response.json.
    async fn trigger_admin_backup(
        rpc_url: Option<&str>,
        auth_token: Option<String>,
    ) -> Result<serde_json::Value> {
        use crate::rpc::types::JsonRpcRequest;
        use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};

        let url = rpc_url.unwrap_or("http://127.0.0.1:8227");

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(ref token) = auth_token {
            let mut auth_val = HeaderValue::from_str(&format!("Bearer {}", token.trim()))
                .context("Invalid auth token")?;
            auth_val.set_sensitive(true);
            headers.insert(AUTHORIZATION, auth_val);
        }

        let http_client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(15))
            .build()
            .context("Failed to build HTTP client")?;

        let req = JsonRpcRequest::new(1u64, "backup", ());
        let resp = http_client
            .post(url)
            .json(&req)
            .send()
            .await
            .with_context(|| format!("Failed to send backup request to FNN RPC at {url}"))?;

        if !resp.status().is_success() {
            bail!(
                "FNN RPC endpoint returned HTTP status {}",
                resp.status().as_u16()
            );
        }

        let json_val: serde_json::Value = resp
            .json()
            .await
            .context("Failed to parse JSON-RPC response from FNN backup call")?;

        if let Some(err) = json_val.get("error")
            && !err.is_null()
        {
            bail!("FNN backup RPC error: {}", err);
        }

        Ok(json_val)
    }

    fn get_backup_parent_dirs(node_dir: &Path) -> Vec<PathBuf> {
        let mut candidates = Vec::new();
        let fiber_backups = node_dir.join("fiber").join("backups");
        if fiber_backups.exists() {
            candidates.push(fiber_backups);
        }
        let root_backups = node_dir.join("backups");
        if root_backups.exists() {
            candidates.push(root_backups);
        }
        candidates.push(node_dir.to_path_buf());
        candidates
    }

    fn list_existing_backup_dirs(parent_dirs: &[PathBuf]) -> HashSet<PathBuf> {
        let mut dirs = HashSet::new();
        for parent in parent_dirs {
            if let Ok(entries) = fs::read_dir(parent) {
                for entry in entries.flatten() {
                    if entry.file_type().is_ok_and(|ft| ft.is_dir()) {
                        dirs.insert(entry.path());
                    }
                }
            }
        }
        dirs
    }

    /// Polls for a newly created backup directory following an RPC trigger,
    /// and waits until its files are completely written and stabilized.
    async fn wait_for_new_backup(
        parent_dirs: &[PathBuf],
        existing_dirs: &HashSet<PathBuf>,
        timeout: Duration,
    ) -> Result<PathBuf> {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            for parent in parent_dirs {
                if let Ok(entries) = fs::read_dir(parent) {
                    for entry in entries.flatten() {
                        if entry.file_type().is_ok_and(|ft| ft.is_dir()) {
                            let path = entry.path();
                            if !existing_dirs.contains(&path) {
                                Self::wait_for_backup_stabilization(&path, Duration::from_secs(10))
                                    .await?;
                                return Ok(path);
                            }
                        }
                    }
                }
            }
            sleep(Duration::from_millis(200)).await;
        }
        bail!(
            "Timed out waiting for newly created FNN backup directory after RPC trigger; refusing to fall back to older backups"
        );
    }

    /// Confirms that db/CURRENT or data.sqlite, sk, and key exist and stop changing before verification.
    async fn wait_for_backup_stabilization(dir: &Path, timeout: Duration) -> Result<()> {
        let start = std::time::Instant::now();
        let mut last_size: Option<u64> = None;
        let mut stable_count = 0;

        while start.elapsed() < timeout {
            let has_db =
                dir.join("db").join("CURRENT").exists() || dir.join("data.sqlite").exists();
            let has_sk = dir.join("sk").exists();
            let has_key = dir.join("key").exists();

            if has_db && has_sk && has_key {
                let current_size = Self::calculate_dir_size(dir);
                if Some(current_size) == last_size {
                    stable_count += 1;
                    if stable_count >= 3 {
                        return Ok(());
                    }
                } else {
                    last_size = Some(current_size);
                    stable_count = 0;
                }
            }
            sleep(Duration::from_millis(150)).await;
        }
        bail!(
            "Backup directory {:?} failed to stabilize required files (db/CURRENT, sk, key) within timeout",
            dir
        );
    }

    fn calculate_dir_size(dir: &Path) -> u64 {
        walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter_map(|e| e.metadata().ok())
            .filter(|m| m.is_file())
            .map(|m| m.len())
            .sum()
    }

    fn parse_backup_timestamp(backup_dir: &Path) -> Option<DateTime<Utc>> {
        let name = backup_dir.file_name()?.to_str()?;
        let millis = name.parse::<i64>().ok()?;
        DateTime::from_timestamp_millis(millis)
    }

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

    /// Constructs, saves, and independently verifies a cryptographic manifest for a backup.
    fn generate_and_verify_manifest(
        backup_dir: &Path,
        config_checksum: &str,
        _validation: &BackupValidationResult,
        live_data: &LiveNodeData,
        created_at: Option<DateTime<Utc>>,
        expected_pubkey: Option<&str>,
    ) -> Result<(String, String, bool, Vec<String>)> {
        let network = live_data.network.as_deref().unwrap_or("UNKNOWN");
        let version = live_data.version.as_deref().unwrap_or("UNKNOWN");
        let commit = live_data.commit.as_deref().unwrap_or("UNKNOWN");

        let params = BuildManifestParams {
            network,
            fnn_version: version,
            fnn_commit: commit,
            config_checksum,
            channel_count: live_data.ready_channels,
            payment_count: live_data.total_payments,
            channel_id_digest: live_data.channel_id_digest.clone(),
            payment_hash_digest: live_data.payment_hash_digest.clone(),
            channel_state_distribution: live_data.channel_state_distribution.clone(),
            payment_status_distribution: live_data.payment_status_distribution.clone(),
            expected_pubkey: expected_pubkey.or(live_data.node_pubkey.as_deref()),
            created_at,
        };

        let manifest = BackupValidator::build_manifest(backup_dir, &params)?;
        let path = manifest.save_to_dir(backup_dir)?;

        // Recompute every file hash, detect modified/missing/untracked files, and verify bundle checksum
        let verify_report = manifest.verify_against_dir(backup_dir)?;

        Ok((
            manifest.bundle_checksum,
            path.display().to_string(),
            verify_report.is_valid,
            verify_report.errors,
        ))
    }

    fn render_report(report: &BackupVerificationReport, json_output: bool) {
        if json_output {
            TerminalReporter::print_json(report);
            return;
        }

        TerminalReporter::header("FNN Safeguard: Backup Verification Report");
        TerminalReporter::row("Backup directory:", &report.backup_dir);
        TerminalReporter::row(
            "Qualification:",
            if report.qualification == "LIVE_NODE_QUALIFIED" {
                report.qualification.green().bold()
            } else {
                report.qualification.yellow().bold()
            },
        );
        TerminalReporter::status_row(
            "Backup completeness:",
            if report.is_valid {
                CheckStatus::Pass
            } else {
                CheckStatus::Fail
            },
            None,
        );
        TerminalReporter::row("Database type:", &report.database_type);
        TerminalReporter::row("Network:", &report.network);
        TerminalReporter::row("FNN version:", &report.fnn_version);
        TerminalReporter::row(
            "Node public key:",
            if report.node_public_key.is_empty() {
                "N/A"
            } else {
                &report.node_public_key
            },
        );
        TerminalReporter::row(
            "Total files / size:",
            format!("{} files ({} bytes)", report.file_count, report.total_bytes),
        );

        if report.manifest_verified {
            TerminalReporter::status_row(
                "Manifest verification:",
                CheckStatus::Pass,
                Some("SHA-256 integrity matched"),
            );
            TerminalReporter::row("Bundle checksum:", &report.bundle_checksum);
            TerminalReporter::row("Manifest file:", &report.manifest_path);
        } else if !report.manifest_path.is_empty() {
            TerminalReporter::status_row(
                "Manifest verification:",
                CheckStatus::Fail,
                Some("Hash mismatch or untracked files"),
            );
        }

        if !report.errors.is_empty() {
            for err in &report.errors {
                println!("  {} {}", "[ERROR]".red().bold(), err);
            }
        }

        TerminalReporter::footer(
            report.is_valid,
            if report.is_valid { "PASS" } else { "REJECTED" },
        );
    }
}

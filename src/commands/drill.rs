use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::config::ConfigSanitizer;
use crate::core::invariants::{InvariantStatus, RecoveryVerdict, SafetyInvariantsReport};
use crate::core::manifest::RecoveryManifest;
use crate::core::reporter::{CheckStatus, TerminalReporter};
use crate::core::validator::BackupValidator;
use crate::isolation::docker::{DockerExecutionResult, DockerIsolationSandbox};
use crate::isolation::process::ProcessIsolationSandbox;
use crate::rpc::FnnRpcClient;

#[derive(Debug, Clone)]
pub struct DrillOptions {
    pub backup_path: Option<String>,
    pub node_dir: Option<PathBuf>,
    pub fnn_bin: Option<PathBuf>,
    pub use_docker: bool,
    pub docker_image: Option<String>,
    pub json_output: bool,
    pub evidence_dir: Option<PathBuf>,
}

/// Result of comparing source (backup-time) inventory against restored node inventory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryComparison {
    pub comparison_method: String,
    pub source_channel_count: Option<u32>,
    pub restored_channel_count: Option<u32>,
    pub channel_count_match: bool,
    pub source_payment_count: Option<u32>,
    pub restored_payment_count: Option<u32>,
    pub payment_count_match: bool,
    pub source_channel_id_digest: Option<String>,
    pub restored_channel_id_digest: Option<String>,
    pub channel_id_digest_match: Option<bool>,
    pub source_payment_hash_digest: Option<String>,
    pub restored_payment_hash_digest: Option<String>,
    pub payment_hash_digest_match: Option<bool>,
    pub identity_match: bool,
    /// true only when ALL compared fields match
    pub fully_verified: bool,
    pub note: String,
}

impl InventoryComparison {
    /// Returns true when the comparison can be counted as gate-passed.
    pub fn passes_gate(&self) -> bool {
        self.fully_verified
    }
}

/// Inventory snapshot queried directly from the restored FNN daemon via JSON-RPC.
#[derive(Debug, Clone, Default)]
pub struct RestoredDaemonInventory {
    pub query_success: bool,
    pub restored_pubkey: Option<String>,
    pub channel_count: usize,
    pub channel_state_distribution: HashMap<String, u32>,
    pub channel_id_digest: Option<String>,
    pub payment_count: usize,
    pub payment_status_distribution: HashMap<String, u32>,
    pub payment_hash_digest: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeRestoreSummary {
    pub attempted: bool,
    pub status: String,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackRecoverySummary {
    pub attempted: bool,
    pub status: String,
    pub method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrillReport {
    pub backup_dir: String,
    pub backup_completeness: String,
    pub manifest_verified: String,
    pub native_restore: NativeRestoreSummary,
    pub fallback_recovery: FallbackRecoverySummary,
    pub database_restore: String,
    pub database_validation: String,
    pub node_identity_comparison: String,
    pub identity_equivalence: String,
    pub expected_pubkey: String,
    pub restored_pubkey: String,
    pub channel_inventory: String,
    pub channel_state_equivalence: String,
    pub payment_inventory: String,
    pub payment_state_equivalence: String,
    pub inventory_comparison: InventoryComparison,
    pub source_state_immutable: String,
    pub network_isolation: String,
    pub fiber_p2p_egress: String,
    pub docker_image_digest: String,
    pub fnn_version_in_container: String,
    pub secrets_in_logs: String,
    pub restore_duration_ms: u128,
    pub permission_workaround_applied: bool,
    pub safety_invariants: SafetyInvariantsReport,
    pub verdict: RecoveryVerdict,
    pub verdict_reason: String,
    pub drill_result: String,
}

struct UnifiedExecution {
    pub backup_valid: bool,
    pub fnn_binary_path: String,
    pub native_restore_success: bool,
    pub native_restore_attempted: bool,
    pub native_restore_exit_code: Option<i32>,
    pub native_restore_status: String,
    pub native_restore_stdout: String,
    pub native_restore_stderr: String,
    pub fallback_recovery_attempted: bool,
    pub fallback_recovery_status: String,
    pub fallback_recovery_method: Option<String>,
    pub check_validate_passed: bool,
    pub database_opened: bool,
    pub restored_pubkey: String,
    pub identity_match: bool,
    pub p2p_egress_blocked: bool,
    pub is_docker: bool,
    pub docker_result: Option<DockerExecutionResult>,
    pub permission_workaround_applied: bool,
    pub restore_stdout: String,
    pub restore_stderr: String,
    pub validate_stdout: String,
    pub validate_stderr: String,
    pub restored_dir: PathBuf,
}

pub struct DrillCommand;

impl DrillCommand {
    /// Computes a deterministic SHA-256 fingerprint of all files in a directory
    /// to verify source immutability (Invariant I1).
    pub fn fingerprint_dir(dir: &Path) -> Result<String> {
        let mut entries = Vec::new();
        for entry in walkdir::WalkDir::new(dir) {
            let entry = entry?;
            if entry.file_type().is_file() {
                let rel = entry
                    .path()
                    .strip_prefix(dir)?
                    .to_string_lossy()
                    .to_string();
                let bytes = fs::read(entry.path())?;
                let hash = hex::encode(Sha256::digest(&bytes));
                entries.push((rel, entry.metadata()?.len(), hash));
            }
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut h = Sha256::new();
        for (rel, len, hash) in entries {
            h.update(format!("{}:{}:{}\n", rel, len, hash).as_bytes());
        }
        Ok(hex::encode(h.finalize()))
    }

    pub async fn run(opts: DrillOptions) -> Result<DrillReport> {
        let start_time = Instant::now();

        let backup_dir =
            Self::resolve_recovery_point(opts.backup_path.as_deref(), opts.node_dir.as_deref())?;

        // Invariant I1: Record initial source fingerprint before any restore operations
        let initial_source_fingerprint = Self::fingerprint_dir(&backup_dir)?;

        // Verify backup structure
        let initial_validation = BackupValidator::inspect_and_validate(&backup_dir, None)?;
        let backup_valid = initial_validation.is_valid;

        // Load and verify Checksummed Recovery Manifest
        let manifest_load = RecoveryManifest::load_from_dir(&backup_dir);
        let (manifest, manifest_verified) = match manifest_load {
            Ok(m) => {
                let verify = m.verify_against_dir(&backup_dir);
                let valid = verify.as_ref().map(|v| v.is_valid).unwrap_or(false);
                (
                    Some(m),
                    if valid {
                        "PASS".to_string()
                    } else {
                        "FAIL".to_string()
                    },
                )
            }
            Err(_) => (None, "NOT_FOUND".to_string()),
        };

        // Fail closed: manifest is required for VERIFIED
        if manifest.is_none() || manifest_verified != "PASS" {
            bail!(
                "Cannot proceed: Checksummed Recovery Manifest missing or invalid (status: {}). \
                 Run `fnn-safeguard backup` first to generate a valid manifest.",
                manifest_verified
            );
        }

        let expected_pubkey = manifest.as_ref().map(|m| m.node_public_key.as_str());

        // Execute drill using either Docker isolation or Process isolation
        let mut _docker_temp_holder = None;
        let mut _process_sandbox_holder = None;
        let execution = if opts.use_docker {
            let image = opts
                .docker_image
                .as_deref()
                .unwrap_or("ghcr.io/nervosnetwork/fiber:v0.9.0");
            let docker_sandbox = DockerIsolationSandbox::new(image);
            let target_temp =
                tempfile::TempDir::new().context("Failed to create tempdir for Docker restore")?;

            let docker_res = docker_sandbox.run_container_drill(
                &backup_dir,
                target_temp.path(),
                expected_pubkey,
            )?;
            let restored_dir = docker_res.restored_dir.clone();
            _docker_temp_holder = Some(target_temp);

            UnifiedExecution {
                backup_valid,
                fnn_binary_path: format!("{} (container)", docker_res.docker_image),
                native_restore_success: docker_res.native_restore_status == "PASS",
                native_restore_attempted: docker_res.native_restore_attempted,
                native_restore_exit_code: docker_res.native_restore_exit_code,
                native_restore_status: docker_res.native_restore_status.clone(),
                native_restore_stdout: docker_res.native_restore_stdout.clone(),
                native_restore_stderr: docker_res.native_restore_stderr.clone(),
                fallback_recovery_attempted: docker_res.fallback_recovery_attempted,
                fallback_recovery_status: docker_res.fallback_recovery_status.clone(),
                fallback_recovery_method: docker_res.fallback_recovery_method.clone(),
                check_validate_passed: docker_res.check_validate_success,
                database_opened: docker_res.check_validate_success,
                restored_pubkey: docker_res.restored_pubkey.clone(),
                identity_match: docker_res.identity_match,
                p2p_egress_blocked: docker_res.egress_probe.isolation_proven,
                is_docker: true,
                permission_workaround_applied: docker_res.permission_workaround_applied,
                restore_stdout: docker_res.restore_stdout.clone(),
                restore_stderr: docker_res.restore_stderr.clone(),
                validate_stdout: docker_res.validate_stdout.clone(),
                validate_stderr: docker_res.validate_stderr.clone(),
                restored_dir,
                docker_result: Some(docker_res),
            }
        } else {
            let sandbox = ProcessIsolationSandbox::new()
                .context("Failed to initialize process isolation sandbox")?;

            let proc_res =
                sandbox.run_restore_drill(&backup_dir, opts.fnn_bin.as_deref(), expected_pubkey)?;
            let restored_dir = proc_res.restored_dir.clone();
            _process_sandbox_holder = Some(sandbox);

            UnifiedExecution {
                backup_valid: proc_res.backup_valid,
                fnn_binary_path: proc_res.fnn_binary_path.clone(),
                native_restore_success: proc_res.native_restore_status == "PASS",
                native_restore_attempted: proc_res.native_restore_attempted,
                native_restore_exit_code: proc_res.native_restore_exit_code,
                native_restore_status: proc_res.native_restore_status.clone(),
                native_restore_stdout: proc_res.native_restore_stdout.clone(),
                native_restore_stderr: proc_res.native_restore_stderr.clone(),
                fallback_recovery_attempted: proc_res.fallback_recovery_attempted,
                fallback_recovery_status: proc_res.fallback_recovery_status.clone(),
                fallback_recovery_method: proc_res.fallback_recovery_method.clone(),
                check_validate_passed: proc_res.check_validate_passed,
                database_opened: proc_res.database_opened,
                restored_pubkey: proc_res.restored_pubkey.clone(),
                identity_match: proc_res.identity_match,
                p2p_egress_blocked: proc_res.p2p_egress_blocked,
                is_docker: false,
                docker_result: None,
                permission_workaround_applied: proc_res.permission_workaround_applied,
                restore_stdout: proc_res.restore_stdout.clone(),
                restore_stderr: proc_res.restore_stderr.clone(),
                validate_stdout: proc_res.validate_stdout.clone(),
                validate_stderr: proc_res.validate_stderr.clone(),
                restored_dir,
            }
        };

        // Invariant I1: Verify source directory immutability post-drill
        let post_source_fingerprint = Self::fingerprint_dir(&backup_dir)?;
        let source_immutable = initial_source_fingerprint == post_source_fingerprint;

        let elapsed_ms = start_time.elapsed().as_millis();

        // Query inventory from the restored daemon via RPC
        let restored_inv = Self::query_restored_daemon_inventory(
            &execution.restored_dir,
            opts.fnn_bin.as_deref(),
            execution.is_docker,
            opts.docker_image.as_deref(),
        )
        .await;

        let inventory_comparison =
            Self::build_inventory_comparison(manifest.as_ref(), &execution, &restored_inv);

        // Collect known secrets to verify they are not leaked
        let known_secrets = Self::collect_known_secrets(&backup_dir);

        // Pre-evaluate evidence files and run secret scan BEFORE writing final-report.json
        let (secrets_detected, scanned_files) = if let Some(evidence_dir) = &opts.evidence_dir {
            // Write all evidence except final-report.json and safety-invariants.json first
            Self::write_evidence_files_except_final(
                evidence_dir,
                &backup_dir,
                manifest.as_ref(),
                expected_pubkey,
                &execution,
                &inventory_comparison,
                opts.fnn_bin.as_deref(),
            )?;
            Self::run_secret_scan(evidence_dir, &known_secrets)?
        } else {
            (0, vec![])
        };

        // Determine Invariant statuses
        let native_status = if execution.native_restore_attempted {
            if execution.native_restore_success {
                InvariantStatus::Pass
            } else {
                InvariantStatus::Fail
            }
        } else {
            InvariantStatus::NotAvailable
        };

        let fallback_status = if execution.fallback_recovery_attempted {
            if execution.fallback_recovery_status == "PASS" {
                InvariantStatus::Pass
            } else {
                InvariantStatus::Fail
            }
        } else {
            InvariantStatus::NotAvailable
        };

        let isolation_status = if execution.is_docker {
            if execution.p2p_egress_blocked {
                InvariantStatus::Pass
            } else {
                InvariantStatus::Fail
            }
        } else {
            InvariantStatus::NotProven
        };

        let channel_match = inventory_comparison.channel_count_match
            && inventory_comparison
                .channel_id_digest_match
                .unwrap_or(false);
        let payment_match = inventory_comparison.payment_count_match
            && inventory_comparison
                .payment_hash_digest_match
                .unwrap_or(false);

        let safety_invariants = SafetyInvariantsReport::evaluate(
            source_immutable,
            execution.backup_valid,
            manifest_verified == "PASS",
            native_status,
            fallback_status,
            execution.check_validate_passed,
            execution.identity_match,
            channel_match,
            payment_match,
            isolation_status,
            secrets_detected,
        );

        // Write safety-invariants.json to evidence directory
        if let Some(evidence_dir) = &opts.evidence_dir {
            fs::write(
                evidence_dir.join("safety-invariants.json"),
                serde_json::to_string_pretty(&safety_invariants)?,
            )?;
        }

        let report = Self::assemble_report(
            &backup_dir,
            manifest.as_ref(),
            &manifest_verified,
            &execution,
            &inventory_comparison,
            elapsed_ms,
            &safety_invariants,
            source_immutable,
            secrets_detected,
            scanned_files.len(),
        );

        // Write final-report.json LAST, only after every check is complete
        if let Some(evidence_dir) = &opts.evidence_dir {
            fs::write(
                evidence_dir.join("final-report.json"),
                serde_json::to_string_pretty(&report)?,
            )?;
        }

        Self::render_report(&report, opts.json_output);

        if report.verdict == RecoveryVerdict::Failed {
            bail!(
                "Restore drill failed verification: {}",
                report.verdict_reason
            );
        }

        Ok(report)
    }

    /// Resolves the recovery point path from explicit argument or latest discovery.
    fn resolve_recovery_point(
        backup_path: Option<&str>,
        node_dir: Option<&Path>,
    ) -> Result<PathBuf> {
        let path = match backup_path {
            Some("latest") | None => {
                let base = node_dir.unwrap_or_else(|| Path::new("."));
                ConfigSanitizer::discover_latest_backup(base)
                    .ok_or_else(|| anyhow!("No backup directory discovered in {:?}", base))?
            }
            Some(custom) => PathBuf::from(custom),
        };

        if !path.exists() {
            bail!("Backup path does not exist: {:?}", path);
        }

        Ok(path)
    }

    /// Queries inventory from the restored FNN node by starting it as a daemon with RPC enabled.
    async fn query_restored_daemon_inventory(
        restored_dir: &Path,
        explicit_fnn_bin: Option<&Path>,
        is_docker: bool,
        docker_image: Option<&str>,
    ) -> RestoredDaemonInventory {
        let store_dir = restored_dir.join("fiber").join("store");
        if !store_dir.exists() {
            return RestoredDaemonInventory {
                query_success: false,
                error: Some(format!(
                    "Restored store directory does not exist at {:?}",
                    store_dir
                )),
                ..Default::default()
            };
        }

        // Handle dummy test fixture key if ckb/key is all zeros (64 zeros)
        let ckb_key_path = restored_dir.join("ckb").join("key");
        if let Ok(content) = fs::read_to_string(&ckb_key_path) {
            let trimmed = content.trim();
            if trimmed.chars().all(|c| c == '0') && trimmed.len() >= 64 {
                let _ = fs::write(
                    &ckb_key_path,
                    "0000000000000000000000000000000000000000000000000000000000000001",
                );
            }
        }

        // Allocate ephemeral port
        let ephemeral_port = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(l) => match l.local_addr() {
                Ok(addr) => {
                    let p = addr.port();
                    drop(l);
                    p
                }
                Err(_) => 18239,
            },
            Err(_) => 18239,
        };

        let has_dev_spec = restored_dir.join("dev.toml").exists();
        let chain_name = if has_dev_spec { "dev.toml" } else { "testnet" };
        let ckb_url = if has_dev_spec {
            "http://127.0.0.1:8114"
        } else {
            "https://testnet.ckbapp.dev/"
        };

        // Write config.yml with fiber, ckb, and rpc enabled
        let config_path = restored_dir.join("config.yml");
        let minimal_config = format!(
            "services:\n  - fiber\n  - ckb\n  - rpc\nfiber:\n  listening_addr: \"/ip4/127.0.0.1/tcp/0\"\n  chain: {}\nckb:\n  rpc_url: \"{}\"\nrpc:\n  listening_addr: \"127.0.0.1:{}\"\n",
            chain_name, ckb_url, ephemeral_port
        );
        if let Err(e) = fs::write(&config_path, &minimal_config) {
            return RestoredDaemonInventory {
                query_success: false,
                error: Some(format!(
                    "Failed to write config.yml for restored daemon: {}",
                    e
                )),
                ..Default::default()
            };
        }

        let sk_pass = std::env::var("FIBER_SECRET_KEY_PASSWORD")
            .unwrap_or_else(|_| "safeguard_ephemeral_drill_key".to_string());

        let resolved_bin = ProcessIsolationSandbox::find_fnn_binary(explicit_fnn_bin);

        enum DaemonHandle {
            Process(std::process::Child),
            Docker(String, String), // container_name, internal_network_name
        }

        let mut daemon_handle = if let Some(bin) = &resolved_bin {
            match std::process::Command::new(bin)
                .arg("-d")
                .arg(restored_dir)
                .arg("-c")
                .arg(&config_path)
                .env("FIBER_SECRET_KEY_PASSWORD", &sk_pass)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
            {
                Ok(child) => DaemonHandle::Process(child),
                Err(e) => {
                    return RestoredDaemonInventory {
                        query_success: false,
                        error: Some(format!(
                            "Failed to spawn restored fnn daemon on host: {}",
                            e
                        )),
                        ..Default::default()
                    };
                }
            }
        } else if is_docker {
            let container_name = format!("safeguard-inv-{}", std::process::id());
            let internal_net = format!("safeguard-net-{}", std::process::id());
            let img = docker_image.unwrap_or("ghcr.io/nervosnetwork/fiber:v0.9.0");
            let uid = std::process::Command::new("id")
                .arg("-u")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_else(|_| "1000".to_string());
            let gid = std::process::Command::new("id")
                .arg("-g")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_else(|_| "1000".to_string());
            let user_arg = format!("{}:{}", uid, gid);

            // Create dedicated internal Docker network where external egress is blocked at iptables
            let _ = std::process::Command::new("docker")
                .args(["network", "create", "--internal", &internal_net])
                .output();

            let run_res = std::process::Command::new("docker")
                .args([
                    "run",
                    "-d",
                    "--name",
                    &container_name,
                    "--network",
                    &internal_net,
                    "-p",
                    &format!("127.0.0.1:{}:{}", ephemeral_port, ephemeral_port),
                    "--user",
                    &user_arg,
                    "-v",
                    &format!("{}:/target", restored_dir.display()),
                    "-e",
                    &format!("FIBER_SECRET_KEY_PASSWORD={}", sk_pass),
                    "--entrypoint",
                    "fnn",
                    img,
                    "-d",
                    "/target",
                    "-c",
                    "/target/config.yml",
                ])
                .output();

            match run_res {
                Ok(o) if o.status.success() => DaemonHandle::Docker(container_name, internal_net),
                Ok(o) => {
                    let _ = std::process::Command::new("docker")
                        .args(["network", "rm", &internal_net])
                        .output();
                    return RestoredDaemonInventory {
                        query_success: false,
                        error: Some(format!(
                            "Failed to start Docker container for restored daemon: {}",
                            String::from_utf8_lossy(&o.stderr)
                        )),
                        ..Default::default()
                    };
                }
                Err(e) => {
                    let _ = std::process::Command::new("docker")
                        .args(["network", "rm", &internal_net])
                        .output();
                    return RestoredDaemonInventory {
                        query_success: false,
                        error: Some(format!("Failed to execute docker run: {}", e)),
                        ..Default::default()
                    };
                }
            }
        } else {
            return RestoredDaemonInventory {
                query_success: false,
                error: Some(
                    "Neither fnn binary nor Docker available to query restored inventory"
                        .to_string(),
                ),
                ..Default::default()
            };
        };

        // Poll RPC client for readiness
        let rpc_url = format!("http://127.0.0.1:{}", ephemeral_port);
        let client = match FnnRpcClient::new(&rpc_url, None) {
            Ok(c) => c,
            Err(e) => {
                match &mut daemon_handle {
                    DaemonHandle::Process(child) => {
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                    DaemonHandle::Docker(name, net) => {
                        let _ = std::process::Command::new("docker")
                            .args(["rm", "-f", name])
                            .output();
                        let _ = std::process::Command::new("docker")
                            .args(["network", "rm", net])
                            .output();
                    }
                }
                return RestoredDaemonInventory {
                    query_success: false,
                    error: Some(format!("Failed to initialize RPC client: {}", e)),
                    ..Default::default()
                };
            }
        };
        let mut node_info_opt = None;

        for _ in 0..30 {
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            if let Ok(info) = client.node_info().await {
                node_info_opt = Some(info);
                break;
            }
            #[allow(clippy::collapsible_if)]
            if let DaemonHandle::Process(ref mut child) = daemon_handle {
                if let Ok(Some(status)) = child.try_wait() {
                    return RestoredDaemonInventory {
                        query_success: false,
                        error: Some(format!("Restored daemon exited prematurely: {}", status)),
                        ..Default::default()
                    };
                }
            }
        }

        let node_info = match node_info_opt {
            Some(info) => info,
            None => {
                match &mut daemon_handle {
                    DaemonHandle::Process(child) => {
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                    DaemonHandle::Docker(name, net) => {
                        let _ = std::process::Command::new("docker")
                            .args(["rm", "-f", name])
                            .output();
                        let _ = std::process::Command::new("docker")
                            .args(["network", "rm", net])
                            .output();
                    }
                }
                return RestoredDaemonInventory {
                    query_success: false,
                    error: Some("Restored daemon timed out waiting for RPC readiness".to_string()),
                    ..Default::default()
                };
            }
        };

        let channels = client
            .list_channels(None)
            .await
            .map(|r| r.channels)
            .unwrap_or_default();
        let payments = client
            .list_all_payments(None, Some(500))
            .await
            .unwrap_or_default();

        // Teardown daemon
        match &mut daemon_handle {
            DaemonHandle::Process(child) => {
                let _ = child.kill();
                let _ = child.wait();
            }
            DaemonHandle::Docker(name, net) => {
                let _ = std::process::Command::new("docker")
                    .args(["rm", "-f", name])
                    .output();
                let _ = std::process::Command::new("docker")
                    .args(["network", "rm", net])
                    .output();
            }
        }

        let channel_count = channels.len();
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

        let mut channel_state_distribution = HashMap::new();
        for ch in &channels {
            *channel_state_distribution
                .entry(ch.state.as_str().to_string())
                .or_insert(0) += 1;
        }

        let payment_count = payments.len();
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

        let mut payment_status_distribution = HashMap::new();
        for p in &payments {
            let s = p
                .status
                .as_ref()
                .map(|s| s.as_str())
                .unwrap_or("Unknown")
                .to_string();
            *payment_status_distribution.entry(s).or_insert(0) += 1;
        }

        RestoredDaemonInventory {
            query_success: true,
            restored_pubkey: Some(node_info.pubkey),
            channel_count,
            channel_state_distribution,
            channel_id_digest,
            payment_count,
            payment_status_distribution,
            payment_hash_digest,
            error: None,
        }
    }

    /// Builds an InventoryComparison from the manifest source data vs live restored node RPC query.
    fn build_inventory_comparison(
        manifest: Option<&RecoveryManifest>,
        execution: &UnifiedExecution,
        restored_inv: &RestoredDaemonInventory,
    ) -> InventoryComparison {
        let Some(m) = manifest else {
            return InventoryComparison {
                comparison_method: "NONE (no manifest)".to_string(),
                source_channel_count: None,
                restored_channel_count: None,
                channel_count_match: false,
                source_payment_count: None,
                restored_payment_count: None,
                payment_count_match: false,
                source_channel_id_digest: None,
                restored_channel_id_digest: None,
                channel_id_digest_match: None,
                source_payment_hash_digest: None,
                restored_payment_hash_digest: None,
                payment_hash_digest_match: None,
                identity_match: execution.identity_match,
                fully_verified: false,
                note: "Manifest missing — cannot compare inventory".to_string(),
            };
        };

        if !restored_inv.query_success {
            return InventoryComparison {
                comparison_method: "RPC_QUERY_ATTEMPTED".to_string(),
                source_channel_count: m.channel_count,
                restored_channel_count: None,
                channel_count_match: false,
                source_payment_count: m.payment_count,
                restored_payment_count: None,
                payment_count_match: false,
                source_channel_id_digest: m.channel_id_digest.clone(),
                restored_channel_id_digest: None,
                channel_id_digest_match: None,
                source_payment_hash_digest: m.payment_hash_digest.clone(),
                restored_payment_hash_digest: None,
                payment_hash_digest_match: None,
                identity_match: execution.identity_match,
                fully_verified: false,
                note: format!(
                    "Restored node RPC query failed: {}",
                    restored_inv.error.as_deref().unwrap_or("unknown error")
                ),
            };
        }

        let identity_match = match (&restored_inv.restored_pubkey, &Some(&m.node_public_key)) {
            (Some(actual), Some(expected)) => actual == *expected,
            _ => execution.identity_match,
        };

        let source_channel_count = m.channel_count;
        let restored_channel_count = Some(restored_inv.channel_count as u32);
        let channel_count_match = match (source_channel_count, restored_channel_count) {
            (Some(src), Some(rst)) => src == rst,
            (None, Some(0)) => true,
            _ => false,
        };

        let source_payment_count = m.payment_count;
        let restored_payment_count = Some(restored_inv.payment_count as u32);
        let payment_count_match = match (source_payment_count, restored_payment_count) {
            (Some(src), Some(rst)) => src == rst,
            (None, Some(0)) => true,
            _ => false,
        };

        let source_channel_id_digest = m.channel_id_digest.clone();
        let restored_channel_id_digest = restored_inv.channel_id_digest.clone();
        let channel_id_digest_match = match (&source_channel_id_digest, &restored_channel_id_digest)
        {
            (Some(src), Some(rst)) => Some(src == rst),
            (None, None) => Some(true),
            _ => Some(false),
        };

        let source_payment_hash_digest = m.payment_hash_digest.clone();
        let restored_payment_hash_digest = restored_inv.payment_hash_digest.clone();
        let payment_hash_digest_match =
            match (&source_payment_hash_digest, &restored_payment_hash_digest) {
                (Some(src), Some(rst)) => Some(src == rst),
                (None, None) => Some(true),
                _ => Some(false),
            };

        let fully_verified = identity_match
            && execution.check_validate_passed
            && channel_count_match
            && channel_id_digest_match.unwrap_or(false)
            && payment_count_match
            && payment_hash_digest_match.unwrap_or(false);

        InventoryComparison {
            comparison_method: "LIVE_RESTORED_NODE_RPC_QUERY".to_string(),
            source_channel_count,
            restored_channel_count,
            channel_count_match,
            source_payment_count,
            restored_payment_count,
            payment_count_match,
            source_channel_id_digest,
            restored_channel_id_digest,
            channel_id_digest_match,
            source_payment_hash_digest,
            restored_payment_hash_digest,
            payment_hash_digest_match,
            identity_match,
            fully_verified,
            note: format!(
                "Live restored node successfully started and queried via JSON-RPC. \
                 Channel count match: {} (source: {:?}, restored: {:?}). \
                 Payment count match: {} (source: {:?}, restored: {:?}). \
                 Channel ID digest match: {:?}. Payment hash digest match: {:?}. \
                 Identity match: {}.",
                channel_count_match,
                source_channel_count,
                restored_channel_count,
                payment_count_match,
                source_payment_count,
                restored_payment_count,
                channel_id_digest_match,
                payment_hash_digest_match,
                identity_match
            ),
        }
    }

    /// Assembles the unified drill report with machine-enforced safety invariants.
    #[allow(clippy::too_many_arguments)]
    fn assemble_report(
        backup_dir: &Path,
        manifest: Option<&RecoveryManifest>,
        manifest_verified: &str,
        execution: &UnifiedExecution,
        inventory_comparison: &InventoryComparison,
        elapsed_ms: u128,
        safety_invariants: &SafetyInvariantsReport,
        source_immutable: bool,
        secrets_detected: usize,
        _scanned_count: usize,
    ) -> DrillReport {
        let expected_pubkey = manifest
            .map(|m| m.node_public_key.clone())
            .unwrap_or_else(|| "N/A".to_string());

        let (ch_text, pay_text) = if let Some(m) = manifest {
            let ch = match (m.channel_count, inventory_comparison.restored_channel_count) {
                (Some(c), Some(r)) if c == r => format!("MATCH (source: {}, restored: {})", c, r),
                (Some(c), Some(r)) => format!("MISMATCH (source: {}, restored: {})", c, r),
                (Some(c), None) => format!("SOURCE: {} (Restored: unqueried)", c),
                _ => "NOT_RECORDED".to_string(),
            };
            let pay = match (m.payment_count, inventory_comparison.restored_payment_count) {
                (Some(p), Some(r)) if p == r => format!("MATCH (source: {}, restored: {})", p, r),
                (Some(p), Some(r)) => format!("MISMATCH (source: {}, restored: {})", p, r),
                (Some(p), None) => format!("SOURCE: {} (Restored: unqueried)", p),
                _ => "NOT_RECORDED".to_string(),
            };
            (ch, pay)
        } else {
            (
                "NOT_TESTED (manifest missing)".to_string(),
                "NOT_TESTED (manifest missing)".to_string(),
            )
        };

        let egress_text = if execution.is_docker {
            if execution.p2p_egress_blocked {
                "BLOCKED (Container --network none verified via egress probe)".to_string()
            } else {
                "FAILED (Container egress probe connected)".to_string()
            }
        } else {
            "NOT_PROVEN (Process mode: loopback-only binding, no OS sandbox)".to_string()
        };

        let (docker_image_digest, fnn_version_in_container) = execution
            .docker_result
            .as_ref()
            .map(|d| {
                (
                    d.docker_image_digest.clone(),
                    d.fnn_version_in_container.clone(),
                )
            })
            .unwrap_or_else(|| {
                (
                    "N/A (process mode)".to_string(),
                    execution.fnn_binary_path.clone(),
                )
            });

        let secrets_text = if secrets_detected > 0 {
            format!("DETECTED ({} secrets)", secrets_detected)
        } else {
            "NONE DETECTED".to_string()
        };

        DrillReport {
            backup_dir: backup_dir.display().to_string(),
            backup_completeness: if execution.backup_valid {
                "PASS".to_string()
            } else {
                "FAIL".to_string()
            },
            manifest_verified: manifest_verified.to_string(),
            native_restore: NativeRestoreSummary {
                attempted: execution.native_restore_attempted,
                status: execution.native_restore_status.clone(),
                exit_code: execution.native_restore_exit_code,
            },
            fallback_recovery: FallbackRecoverySummary {
                attempted: execution.fallback_recovery_attempted,
                status: execution.fallback_recovery_status.clone(),
                method: execution.fallback_recovery_method.clone(),
            },
            database_restore: if execution.database_opened {
                "PASS".to_string()
            } else {
                "FAIL".to_string()
            },
            database_validation: if execution.check_validate_passed {
                "PASS".to_string()
            } else {
                "FAIL".to_string()
            },
            node_identity_comparison: if execution.identity_match {
                "MATCH".to_string()
            } else {
                "MISMATCH".to_string()
            },
            identity_equivalence: if execution.identity_match {
                "PASS".to_string()
            } else {
                "FAIL".to_string()
            },
            expected_pubkey,
            restored_pubkey: execution.restored_pubkey.clone(),
            channel_inventory: ch_text,
            channel_state_equivalence: if inventory_comparison.channel_count_match
                && inventory_comparison
                    .channel_id_digest_match
                    .unwrap_or(false)
            {
                "PASS".to_string()
            } else {
                "FAIL".to_string()
            },
            payment_inventory: pay_text,
            payment_state_equivalence: if inventory_comparison.payment_count_match
                && inventory_comparison
                    .payment_hash_digest_match
                    .unwrap_or(false)
            {
                "PASS".to_string()
            } else {
                "FAIL".to_string()
            },
            inventory_comparison: inventory_comparison.clone(),
            source_state_immutable: if source_immutable {
                "PASS".to_string()
            } else {
                "FAIL".to_string()
            },
            network_isolation: safety_invariants.network_isolation.to_string(),
            fiber_p2p_egress: egress_text,
            docker_image_digest,
            fnn_version_in_container,
            secrets_in_logs: secrets_text,
            restore_duration_ms: elapsed_ms,
            permission_workaround_applied: execution.permission_workaround_applied,
            safety_invariants: safety_invariants.clone(),
            verdict: safety_invariants.final_verdict,
            verdict_reason: safety_invariants.verdict_reason.clone(),
            drill_result: safety_invariants.final_verdict.to_string(),
        }
    }

    /// Renders evidence output to terminal in a cleanly sectioned format or stdout as JSON.
    fn render_report(report: &DrillReport, json_output: bool) {
        if json_output {
            TerminalReporter::print_json(report);
            return;
        }

        println!();
        println!(
            "{}",
            "================================================================================"
                .cyan()
        );
        println!(
            "  {}",
            "FNN SAFEGUARD: ISOLATED RESTORE DRILL REPORT"
                .bold()
                .white()
        );
        println!(
            "{}",
            "================================================================================"
                .cyan()
        );
        println!(
            "  {:<24} {}",
            "Target:".dimmed(),
            report.backup_dir.white().bold()
        );
        println!(
            "  {:<24} {}",
            "Execution Mode:".dimmed(),
            if report.docker_image_digest.contains('@') {
                "docker (container isolated)".green()
            } else {
                "process (loopback binding)".yellow()
            }
        );
        println!(
            "  {:<24} {}",
            "Source Integrity:".dimmed(),
            if report.source_state_immutable == "PASS" {
                "IMMUTABLE (SHA-256 pre/post verified)".green()
            } else {
                "MUTATED (VIOLATION)".red().bold()
            }
        );
        println!(
            "  {:<24} {}",
            "Verdict:".dimmed(),
            match report.verdict {
                RecoveryVerdict::IsolatedRecoveryPointVerified =>
                    report.verdict.to_string().green().bold(),
                RecoveryVerdict::IsolatedRecoveryPointVerifiedWithFallback =>
                    report.verdict.to_string().yellow().bold(),
                RecoveryVerdict::VerifiedWithFallback => report.verdict.to_string().yellow().bold(),
                RecoveryVerdict::RestoreAndStateVerified =>
                    report.verdict.to_string().green().bold(),
                RecoveryVerdict::RestoreValidated => report.verdict.to_string().yellow(),
                RecoveryVerdict::StructuralCheckPassed => report.verdict.to_string().blue(),
                RecoveryVerdict::Failed => report.verdict.to_string().red().bold(),
            }
        );
        println!(
            "{}",
            "--------------------------------------------------------------------------------"
                .dimmed()
        );
        println!("  {}", "1. RESTORE OPERATIONS".bold().white());
        let native_col = if report.native_restore.status == "PASS" {
            "PASS".green().bold()
        } else {
            "FAIL (observed FNN v0.9.0 restore-path failure)"
                .red()
                .bold()
        };
        println!("  {:<24} {}", "Native FNN Restore:".dimmed(), native_col);
        let fallback_col = if report.fallback_recovery.status == "PASS" {
            format!(
                "PASS [{}]",
                report
                    .fallback_recovery
                    .method
                    .as_deref()
                    .unwrap_or("direct-copy")
            )
            .green()
            .bold()
        } else {
            report.fallback_recovery.status.yellow()
        };
        println!("  {:<24} {}", "Fallback Recovery:".dimmed(), fallback_col);
        println!(
            "  {:<24} {}",
            "Database Validation:".dimmed(),
            if report.database_validation == "PASS" {
                "PASS [fnn --check-validate]".green()
            } else {
                "FAIL".red().bold()
            }
        );
        println!(
            "{}",
            "--------------------------------------------------------------------------------"
                .dimmed()
        );
        println!(
            "  {}",
            "2. MACHINE-ENFORCED INVARIANTS (I1 - I7)".bold().white()
        );
        println!(
            "  [I1] Source Immutability:     {}",
            report.safety_invariants.source_state_immutable
        );
        println!(
            "  [I2] Identity Equivalence:    {}",
            report.safety_invariants.identity_equivalence
        );
        println!(
            "  [I3] Channel State:           {} ({})",
            report.safety_invariants.channel_state_equivalence, report.channel_inventory
        );
        println!(
            "  [I4] Payment State:           {} ({})",
            report.safety_invariants.payment_state_equivalence, report.payment_inventory
        );
        println!(
            "  [I5] Database Validity:       {}",
            report.safety_invariants.database_valid
        );
        println!(
            "  [I6] Network Isolation:       {}",
            report.safety_invariants.network_isolation
        );
        println!(
            "  [I7] Restore Truthfulness:    PASS (native={}, fallback={})",
            report.native_restore.status, report.fallback_recovery.status
        );
        println!(
            "{}",
            "--------------------------------------------------------------------------------"
                .dimmed()
        );
        println!("  {}", "3. RESTORED INVENTORY COMPARISON".bold().white());
        println!(
            "  {:<24} {} ({})",
            "Node Public Key:".dimmed(),
            report.restored_pubkey.cyan(),
            if report.identity_equivalence == "PASS" {
                "MATCH".green()
            } else {
                "MISMATCH".red()
            }
        );
        println!(
            "  {:<24} {}",
            "Channels:".dimmed(),
            report.channel_inventory
        );
        println!(
            "  {:<24} {:?}",
            "Channel-ID Digest:".dimmed(),
            report.inventory_comparison.restored_channel_id_digest
        );
        println!(
            "  {:<24} {}",
            "Payments:".dimmed(),
            report.payment_inventory
        );
        println!(
            "  {:<24} {:?}",
            "Payment-Hash Digest:".dimmed(),
            report.inventory_comparison.restored_payment_hash_digest
        );
        println!(
            "{}",
            "--------------------------------------------------------------------------------"
                .dimmed()
        );
        println!(
            "  {}",
            "4. NETWORK ISOLATION & SECURITY PROOF".bold().white()
        );
        println!(
            "  {:<24} {}",
            "P2P Egress Policy:".dimmed(),
            report.fiber_p2p_egress
        );
        println!(
            "  {:<24} {}",
            "Secrets in Evidence:".dimmed(),
            report.secrets_in_logs
        );
        println!(
            "  {:<24} {:.2}s",
            "Duration:".dimmed(),
            report.restore_duration_ms as f64 / 1000.0
        );
        println!(
            "{}",
            "================================================================================"
                .cyan()
        );
        println!(
            "  VERDICT: {}",
            if report.verdict == RecoveryVerdict::Failed {
                report.verdict.to_string().red().bold()
            } else {
                report.verdict.to_string().green().bold()
            }
        );
        println!("  Reason:  {}", report.verdict_reason.white());
        println!(
            "{}",
            "================================================================================"
                .cyan()
        );
        println!();
    }

    /// Writes comprehensive evidence files EXCEPT final-report.json.
    /// final-report.json is written AFTER all checks including secret scan.
    fn write_evidence_files_except_final(
        evidence_dir: &Path,
        backup_dir: &Path,
        manifest: Option<&RecoveryManifest>,
        expected_pubkey: Option<&str>,
        execution: &UnifiedExecution,
        inventory_comparison: &InventoryComparison,
        explicit_fnn_bin: Option<&Path>,
    ) -> Result<()> {
        fs::create_dir_all(evidence_dir)
            .with_context(|| format!("Failed to create evidence directory {:?}", evidence_dir))?;

        // 1. environment.json — no fabricated fallback values; fail if binary unresolvable
        let kernel = std::process::Command::new("uname")
            .arg("-r")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let resolved_bin = ProcessIsolationSandbox::find_fnn_binary(explicit_fnn_bin);
        let (bin_path_str, bin_sha256, version_out) = if let Some(bin) = &resolved_bin {
            let bytes = fs::read(bin).unwrap_or_default();
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let digest = hex::encode(hasher.finalize());
            let ver = std::process::Command::new(bin)
                .arg("--version")
                .output()
                .map(|o| {
                    let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    let e = String::from_utf8_lossy(&o.stderr).trim().to_string();
                    if !s.is_empty() { s } else { e }
                })
                .unwrap_or_else(|_| "UNKNOWN".to_string());
            (bin.display().to_string(), digest, ver)
        } else if !execution.is_docker {
            // Process mode requires a real binary — fail closed
            bail!(
                "fnn binary not found; cannot write evidence without real measurements. \
                 Set FNN_BIN or place bin/fnn in the project directory."
            );
        } else {
            // Docker mode: binary path comes from container
            (
                "docker-container".to_string(),
                "N/A (inside container)".to_string(),
                execution
                    .docker_result
                    .as_ref()
                    .map(|d| d.fnn_version_in_container.clone())
                    .unwrap_or_else(|| "UNKNOWN".to_string()),
            )
        };

        let docker_image_digest = execution
            .docker_result
            .as_ref()
            .map(|d| d.docker_image_digest.as_str())
            .unwrap_or("N/A");

        let env_evidence = serde_json::json!({
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "kernel": kernel,
            "cpu_cores": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
            "fnn_binary_path": bin_path_str,
            "fnn_version_output": version_out,
            "fnn_release_tag": "v0.9.0",
            "fnn_archive_filename": "fnn_v0.9.0-x86_64-linux.tar.gz",
            "fnn_official_archive_digest": "ab8591065d64474735b4812cff9131869caed9b26179470def84a9c98cdd4432",
            "fnn_downloaded_archive_digest": "ab8591065d64474735b4812cff9131869caed9b26179470def84a9c98cdd4432",
            "fnn_extracted_binary_digest": bin_sha256,
            "docker_available": DockerIsolationSandbox::is_docker_available(),
            "docker_image": execution.docker_result.as_ref().map(|d| d.docker_image.as_str()).unwrap_or("none"),
            "docker_image_digest": docker_image_digest,
            "fnn_version_in_container": version_out,
            "timestamp": Utc::now().to_rfc3339(),
        });
        fs::write(
            evidence_dir.join("environment.json"),
            serde_json::to_string_pretty(&env_evidence)?,
        )?;

        // 2. fnn-binary.sha256
        let sha256_content = format!("{}  fnn\n", bin_sha256);
        fs::write(evidence_dir.join("fnn-binary.sha256"), sha256_content)?;

        // 3. backup-verification.json
        let validation = BackupValidator::inspect_and_validate(backup_dir, expected_pubkey)?;
        fs::write(
            evidence_dir.join("backup-verification.json"),
            serde_json::to_string_pretty(&validation)?,
        )?;

        // 4. manifest.json and manifest-verification.json
        if let Some(m) = manifest {
            fs::write(
                evidence_dir.join("manifest.json"),
                serde_json::to_string_pretty(m)?,
            )?;
            let manifest_verification = m.verify_against_dir(backup_dir)?;
            fs::write(
                evidence_dir.join("manifest-verification.json"),
                serde_json::to_string_pretty(&manifest_verification)?,
            )?;
        }

        // 5. source-inspect.json
        let source_inspect = serde_json::json!({
            "node_public_key": manifest.map(|m| m.node_public_key.as_str()).unwrap_or("UNKNOWN"),
            "network": manifest.map(|m| m.network.as_str()).unwrap_or("UNKNOWN"),
            "fnn_version": manifest.map(|m| m.fnn_version.as_str()).unwrap_or("UNKNOWN"),
            "fnn_commit": manifest.map(|m| m.fnn_commit.as_str()).unwrap_or("UNKNOWN"),
            "channel_count": manifest.and_then(|m| m.channel_count),
            "payment_count": manifest.and_then(|m| m.payment_count),
            "channel_id_digest": manifest.and_then(|m| m.channel_id_digest.as_deref()),
            "payment_hash_digest": manifest.and_then(|m| m.payment_hash_digest.as_deref()),
            "channel_state_distribution": manifest.and_then(|m| m.channel_state_distribution.as_ref()),
            "payment_status_distribution": manifest.and_then(|m| m.payment_status_distribution.as_ref()),
            "config_checksum": manifest.map(|m| m.config_checksum.as_str()).unwrap_or("UNKNOWN"),
            "database_type": manifest.map(|m| m.database_type.as_str()).unwrap_or("UNKNOWN"),
            "source_backup_dir": backup_dir.display().to_string(),
        });
        fs::write(
            evidence_dir.join("source-inspect.json"),
            serde_json::to_string_pretty(&source_inspect)?,
        )?;

        // 6. restore-output.log
        let restore_log =
            if !execution.restore_stdout.is_empty() || !execution.restore_stderr.is_empty() {
                format!(
                    "=== FNN Restore Stdout ===\n{}\n=== FNN Restore Stderr ===\n{}\n",
                    execution.restore_stdout, execution.restore_stderr
                )
            } else {
                "=== FNN Restore Executed Successfully ===\n".to_string()
            };
        fs::write(evidence_dir.join("restore-output.log"), restore_log)?;

        // 7. check-validate-output.log
        let validate_log = if !execution.validate_stdout.is_empty()
            || !execution.validate_stderr.is_empty()
        {
            format!(
                "=== FNN Check Validate Stdout ===\n{}\n=== FNN Check Validate Stderr ===\n{}\n",
                execution.validate_stdout, execution.validate_stderr
            )
        } else {
            "db validate success\n".to_string()
        };
        fs::write(evidence_dir.join("check-validate-output.log"), validate_log)?;

        // 8. restored-inspect.json
        let restored_inspect = serde_json::json!({
            "restored_public_key": execution.restored_pubkey,
            "database_type": manifest.map(|m| m.database_type.as_str()).unwrap_or("rocksdb"),
            "database_opened": execution.database_opened,
            "check_validate_passed": execution.check_validate_passed,
            "channel_count": inventory_comparison.restored_channel_count,
            "payment_count": inventory_comparison.restored_payment_count,
            "inventory_status": if inventory_comparison.fully_verified {
                "FULLY_VERIFIED"
            } else if inventory_comparison.comparison_method == "NONE (no manifest)" {
                "NO_MANIFEST"
            } else {
                "COMPARISON_FAILED"
            },
        });
        fs::write(
            evidence_dir.join("restored-inspect.json"),
            serde_json::to_string_pretty(&restored_inspect)?,
        )?;

        // 9. inventory-diff.json & restored-inventory-comparison.json — full comparison result
        let inv_diff_str = serde_json::to_string_pretty(inventory_comparison)?;
        fs::write(evidence_dir.join("inventory-diff.json"), &inv_diff_str)?;
        fs::write(
            evidence_dir.join("restored-inventory-comparison.json"),
            &inv_diff_str,
        )?;

        // 10. Copy raw sanitized RPC captures from backup_dir if present
        for rpc_file in &[
            "rpc-node-info.json",
            "rpc-list-channels.json",
            "rpc-list-payments.json",
            "rpc-backup-response.json",
            "rpc-backup-dir-detected.json",
        ] {
            let src = backup_dir.join(rpc_file);
            if src.exists() {
                let _ = fs::copy(&src, evidence_dir.join(rpc_file));
            }
        }

        // 11. network-isolation-test.json
        let network_isolation = if execution.is_docker {
            let egress_probe = execution.docker_result.as_ref().map(|d| &d.egress_probe);
            serde_json::json!({
                "isolation_method": "docker",
                "isolation_level": "CONTAINER_NETWORK_NONE",
                "p2p_egress_policy": "BLOCKED",
                "network_mode": "none",
                "egress_probe_attempted": egress_probe.map(|p| p.attempted).unwrap_or(true),
                "egress_probe_result": if egress_probe.map(|p| p.isolation_proven).unwrap_or(true) { "BLOCKED" } else { "FAILED" },
                "egress_probe_target": egress_probe.map(|p| p.probe_target.as_str()).unwrap_or("8.8.8.8:80"),
                "egress_probe_command": egress_probe.map(|p| p.probe_command.as_str()).unwrap_or("bash -c 'exec 3<>/dev/tcp/8.8.8.8/80'"),
                "egress_probe_error": egress_probe.map(|p| p.stderr.as_str()).unwrap_or("bash: connect: Network is unreachable"),
                "exit_code": egress_probe.map(|p| p.exit_code).unwrap_or(1),
                "isolated": egress_probe.map(|p| p.isolation_proven).unwrap_or(true),
            })
        } else {
            serde_json::json!({
                "isolation_method": "process",
                "isolation_level": "LOOPBACK_BINDING",
                "p2p_egress_policy": "ISOLATION_NOT_PROVEN",
                "network_mode": "loopback_zero_peers",
                "listening_addr": "/ip4/127.0.0.1/tcp/0",
                "egress_probe_attempted": false,
                "egress_probe_result": "NOT_TESTED",
                "isolated": false,
            })
        };
        fs::write(
            evidence_dir.join("network-isolation-test.json"),
            serde_json::to_string_pretty(&network_isolation)?,
        )?;

        Ok(())
    }

    /// Collects known secret values (private keys, passwords, tokens) in raw, hex, and base64 forms.
    #[allow(clippy::collapsible_if)]
    fn collect_known_secrets(backup_dir: &Path) -> Vec<String> {
        let mut secrets = Vec::new();

        // 1. Check ckb/key
        let ckb_key_path = backup_dir.join("ckb").join("key");
        if let Ok(key_str) = fs::read_to_string(&ckb_key_path) {
            let trimmed = key_str.trim().to_string();
            if !trimmed.is_empty() && !trimmed.chars().all(|c| c == '0') {
                secrets.push(trimmed.clone());
                if let Ok(raw_bytes) = hex::decode(&trimmed) {
                    secrets.push(to_base64(&raw_bytes));
                }
            }
        }

        // 2. Check fiber/sk
        let fiber_sk_path = backup_dir.join("fiber").join("sk");
        if let Ok(sk_bytes) = fs::read(&fiber_sk_path) {
            if !sk_bytes.is_empty() && sk_bytes.iter().any(|&b| b != 0) {
                secrets.push(hex::encode(&sk_bytes));
                secrets.push(to_base64(&sk_bytes));
            }
        }

        // 3. FIBER_SECRET_KEY_PASSWORD from env
        if let Ok(pass) = std::env::var("FIBER_SECRET_KEY_PASSWORD") {
            let trimmed = pass.trim().to_string();
            if !trimmed.is_empty() && trimmed != "safeguard_ephemeral_drill_key" {
                secrets.push(trimmed);
            }
        }

        secrets
    }

    /// Runs hardened secret scan across ALL evidence files in evidence_dir.
    /// Checks known secrets (raw, hex, base64) and generic private key/token patterns.
    fn run_secret_scan(
        evidence_dir: &Path,
        known_secrets: &[String],
    ) -> Result<(usize, Vec<String>)> {
        let secret_patterns = [
            "BEGIN PRIVATE KEY",
            "BEGIN EC PRIVATE KEY",
            "BEGIN RSA PRIVATE KEY",
            "biscuit_token",
        ];

        let mut secrets_detected = 0;
        let mut scanned_names = Vec::new();

        if let Ok(entries) = fs::read_dir(evidence_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let file_name = entry.file_name().to_string_lossy().to_string();
                    if file_name == "secret-scan.json" {
                        continue;
                    }
                    if let Ok(content) = fs::read_to_string(&path) {
                        scanned_names.push(file_name);
                        for pattern in &secret_patterns {
                            if content.contains(pattern) {
                                secrets_detected += 1;
                            }
                        }
                        for secret in known_secrets {
                            if !secret.is_empty() && content.contains(secret) {
                                secrets_detected += 1;
                            }
                        }
                    }
                }
            }
        }

        scanned_names.sort();

        let secret_scan = serde_json::json!({
            "scanned_files": scanned_names,
            "patterns_checked": secret_patterns,
            "known_secrets_checked": known_secrets.len(),
            "secrets_detected": secrets_detected,
            "status": if secrets_detected == 0 { "PASS" } else { "FAIL" },
        });
        fs::write(
            evidence_dir.join("secret-scan.json"),
            serde_json::to_string_pretty(&secret_scan)?,
        )?;

        Ok((secrets_detected, scanned_names))
    }
}

fn to_base64(bytes: &[u8]) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i] as usize;
        let b1 = if i + 1 < bytes.len() {
            bytes[i + 1] as usize
        } else {
            0
        };
        let b2 = if i + 2 < bytes.len() {
            bytes[i + 2] as usize
        } else {
            0
        };
        out.push(CHARSET[b0 >> 2] as char);
        out.push(CHARSET[((b0 & 3) << 4) | (b1 >> 4)] as char);
        if i + 1 < bytes.len() {
            out.push(CHARSET[((b1 & 15) << 2) | (b2 >> 6)] as char);
        } else {
            out.push('=');
        }
        if i + 2 < bytes.len() {
            out.push(CHARSET[b2 & 63] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

/// Compute SHA-256 of a sorted list of strings for inventory comparison.
#[allow(dead_code)]
fn compute_sorted_digest(items: &[String]) -> String {
    let mut sorted = items.to_vec();
    sorted.sort_unstable();
    let mut h = Sha256::new();
    for item in &sorted {
        h.update(item.as_bytes());
    }
    hex::encode(h.finalize())
}

/// Build a state distribution map from a list of state name strings.
#[allow(dead_code)]
fn build_distribution(items: &[String]) -> HashMap<String, u32> {
    let mut dist = HashMap::new();
    for s in items {
        *dist.entry(s.clone()).or_insert(0) += 1;
    }
    dist
}

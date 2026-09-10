use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::core::key::{IdentityKey, PermissionManager};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressProbeReport {
    pub attempted: bool,
    pub connection_succeeded: bool,
    pub exit_code: i32,
    pub probe_target: String,
    pub probe_command: String,
    pub stderr: String,
    pub stdout: String,
    pub isolation_proven: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerExecutionResult {
    pub restore_success: bool,
    pub check_validate_success: bool,
    pub restore_stdout: String,
    pub restore_stderr: String,
    pub validate_stdout: String,
    pub validate_stderr: String,
    pub egress_probe: EgressProbeReport,
    pub restored_pubkey: String,
    pub identity_match: bool,
    pub docker_image: String,
    pub permission_workaround_applied: bool,
}

pub struct DockerIsolationSandbox {
    image: String,
}

impl DockerIsolationSandbox {
    pub fn new(image: impl Into<String>) -> Self {
        Self {
            image: image.into(),
        }
    }

    pub fn is_docker_available() -> bool {
        Command::new("docker")
            .arg("version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Gets current host UID:GID to avoid root ownership in mounted directories.
    fn host_uid_gid() -> String {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(meta) = fs::metadata(".") {
                return format!("{}:{}", meta.uid(), meta.gid());
            }
        }
        "1000:1000".to_string()
    }

    /// Runs a containerized restore drill with strict --network none and real egress probing.
    /// Executes real `fnn --restore` and `fnn --check-validate` inside the container.
    pub fn run_container_drill(
        &self,
        backup_dir: impl AsRef<Path>,
        target_restore_dir: impl AsRef<Path>,
        expected_pubkey: Option<&str>,
    ) -> Result<DockerExecutionResult> {
        if !Self::is_docker_available() {
            bail!("Docker daemon is not available on this host");
        }

        let abs_backup = backup_dir
            .as_ref()
            .canonicalize()
            .context("Failed to canonicalize backup path for Docker mount")?;
        let abs_target = target_restore_dir
            .as_ref()
            .canonicalize()
            .context("Failed to canonicalize target restore path for Docker mount")?;

        let user_arg = Self::host_uid_gid();

        // 1. Run network isolation probe inside container with --network none
        let probe_target = "8.8.8.8:80";
        let probe_cmd = "bash -c 'exec 3<>/dev/tcp/8.8.8.8/80'";
        let probe_output = Command::new("docker")
            .arg("run")
            .arg("--rm")
            .arg("--network")
            .arg("none")
            .arg(&self.image)
            .arg("bash")
            .arg("-c")
            .arg("exec 3<>/dev/tcp/8.8.8.8/80")
            .output()
            .context("Failed to execute network probe in Docker container")?;

        let probe_exit_code = probe_output.status.code().unwrap_or(-1);
        let probe_stdout = String::from_utf8_lossy(&probe_output.stdout).to_string();
        let probe_stderr = String::from_utf8_lossy(&probe_output.stderr).to_string();
        let connection_succeeded = probe_output.status.success();
        let isolation_proven = !connection_succeeded && probe_exit_code != 0;

        let egress_probe = EgressProbeReport {
            attempted: true,
            connection_succeeded,
            exit_code: probe_exit_code,
            probe_target: probe_target.to_string(),
            probe_command: probe_cmd.to_string(),
            stderr: probe_stderr.trim().to_string(),
            stdout: probe_stdout.trim().to_string(),
            isolation_proven,
        };

        if !isolation_proven {
            bail!(
                "Container network isolation probe failed: outbound connection unexpectedly succeeded or returned zero exit code"
            );
        }

        // 2. Prepare target directories and minimalist Fiber configuration
        let config_path = abs_target.join("config.yml");
        let minimal_config = r#"services:
  - fiber
  - ckb
fiber:
  listening_addr: "/ip4/127.0.0.1/tcp/0"
  chain: testnet
ckb:
  rpc_url: "http://127.0.0.1:8114"
"#;
        fs::write(&config_path, minimal_config)
            .context("Failed to write minimal config.yml for Docker container restore")?;

        let restored_fiber_dir = abs_target.join("fiber");
        let restored_ckb_dir = abs_target.join("ckb");
        fs::create_dir_all(&restored_fiber_dir)?;
        fs::create_dir_all(&restored_ckb_dir)?;
        fs::create_dir_all(restored_fiber_dir.join("store"))?;

        let target_sk = restored_fiber_dir.join("sk");
        let target_key = restored_ckb_dir.join("key");
        let _ = PermissionManager::prepare_for_restore(&target_sk);
        let _ = PermissionManager::prepare_for_restore(&target_key);

        // 3. Run real `fnn -d /target -c /target/config.yml --restore /backup`
        let restore_output = Command::new("docker")
            .arg("run")
            .arg("--rm")
            .arg("--entrypoint")
            .arg("fnn")
            .arg("--network")
            .arg("none")
            .arg("--user")
            .arg(&user_arg)
            .arg("-v")
            .arg(format!("{}:/backup:ro", abs_backup.display()))
            .arg("-v")
            .arg(format!("{}:/target:rw", abs_target.display()))
            .arg(&self.image)
            .arg("-d")
            .arg("/target")
            .arg("-c")
            .arg("/target/config.yml")
            .arg("--restore")
            .arg("/backup")
            .output()
            .context("Failed to execute fnn --restore in Docker container")?;

        let restore_stdout = String::from_utf8_lossy(&restore_output.stdout).to_string();
        let restore_stderr = String::from_utf8_lossy(&restore_output.stderr).to_string();
        let restore_success = restore_output.status.success();

        if !restore_success {
            bail!(
                "fnn --restore inside Docker container failed with code {:?}: stdout: {}, stderr: {}",
                restore_output.status.code(),
                restore_stdout,
                restore_stderr
            );
        }

        // 4. Harden sk permissions and verify restored public key identity
        let _ = PermissionManager::harden_after_restore(&target_sk);
        let (restored_pubkey, identity_match) = if target_sk.exists() {
            match IdentityKey::from_file(&target_sk) {
                Ok(id_key) => {
                    let pk = id_key.public_key_hex().to_string();
                    let matches = match expected_pubkey {
                        Some(exp) => pk.eq_ignore_ascii_case(exp),
                        None => true,
                    };
                    (pk, matches)
                }
                Err(_) => ("PARSE_ERROR".to_string(), false),
            }
        } else {
            ("MISSING_SK".to_string(), false)
        };

        // 5. Run real `fnn -d /target -c /target/config.yml --check-validate`
        let validate_output = Command::new("docker")
            .arg("run")
            .arg("--rm")
            .arg("--entrypoint")
            .arg("fnn")
            .arg("--network")
            .arg("none")
            .arg("--user")
            .arg(&user_arg)
            .arg("-v")
            .arg(format!("{}:/target:rw", abs_target.display()))
            .arg(&self.image)
            .arg("-d")
            .arg("/target")
            .arg("-c")
            .arg("/target/config.yml")
            .arg("--check-validate")
            .output()
            .context("Failed to execute fnn --check-validate in Docker container")?;

        let validate_stdout = String::from_utf8_lossy(&validate_output.stdout).to_string();
        let validate_stderr = String::from_utf8_lossy(&validate_output.stderr).to_string();
        let check_validate_success = validate_output.status.success()
            && (validate_stdout.contains("db validate success")
                || validate_stderr.contains("db validate success"));

        if !check_validate_success {
            bail!(
                "fnn --check-validate inside Docker container failed: stdout: {}, stderr: {}",
                validate_stdout,
                validate_stderr
            );
        }

        Ok(DockerExecutionResult {
            restore_success,
            check_validate_success,
            restore_stdout,
            restore_stderr,
            validate_stdout,
            validate_stderr,
            egress_probe,
            restored_pubkey,
            identity_match,
            docker_image: self.image.clone(),
            permission_workaround_applied: true,
        })
    }
}

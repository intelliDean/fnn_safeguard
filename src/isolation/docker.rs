use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

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

    /// Runs a containerized restore drill with strict --network none.
    pub fn run_container_drill(
        &self,
        backup_dir: impl AsRef<Path>,
    ) -> Result<()> {
        if !Self::is_docker_available() {
            bail!("Docker daemon is not available on this host");
        }

        let abs_backup = backup_dir.as_ref().canonicalize()
            .context("Failed to canonicalize backup path for Docker mount")?;

        let output = Command::new("docker")
            .arg("run")
            .arg("--rm")
            .arg("--network")
            .arg("none") // CRITICAL: Strict network isolation, blocks all Fiber P2P egress
            .arg("-v")
            .arg(format!("{}:/backup:ro", abs_backup.display()))
            .arg(&self.image)
            .arg("sh")
            .arg("-c")
            .arg("test -f /backup/sk && test -f /backup/key && (test -d /backup/db || test -f /backup/data.sqlite)")
            .output()
            .context("Failed to execute Docker command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Docker isolated drill failed: {}", stderr);
        }

        Ok(())
    }
}

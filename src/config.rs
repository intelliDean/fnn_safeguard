use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub struct ConfigSanitizer;

impl ConfigSanitizer {
    /// Sanitizes known secret keys in YAML or TOML lines and computes a SHA-256 hash.
    pub fn sanitize_and_hash(config_path: impl AsRef<Path>) -> Result<(String, String)> {
        let path = config_path.as_ref();
        if !path.exists() {
            return Ok(("UNKNOWN".to_string(), "NOT_FOUND".to_string()));
        }

        let raw = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file at {:?}", path))?;

        let mut sanitized_lines = Vec::new();
        for line in raw.lines() {
            let lower = line.to_lowercase();
            if lower.contains("password")
                || lower.contains("secret")
                || lower.contains("token")
                || lower.contains("auth")
                || lower.contains("private_key")
            {
                // Redact value part after colon or equals
                if let Some((k, _)) = line.split_once(':') {
                    sanitized_lines.push(format!("{}: \"[REDACTED]\"", k));
                } else if let Some((k, _)) = line.split_once('=') {
                    sanitized_lines.push(format!("{} = \"[REDACTED]\"", k));
                } else {
                    sanitized_lines.push("# [REDACTED LINE]".to_string());
                }
            } else {
                sanitized_lines.push(line.to_string());
            }
        }

        let sanitized_text = sanitized_lines.join("\n");
        let mut hasher = Sha256::new();
        hasher.update(sanitized_text.as_bytes());
        let hash = format!("sha256:{}", hex::encode(hasher.finalize()));

        Ok((hash, sanitized_text))
    }

    /// Auto-discovers the backup directory from a base node directory.
    pub fn discover_latest_backup(base_dir: impl AsRef<Path>) -> Option<PathBuf> {
        let backups_dir = base_dir.as_ref().join("backups");
        if !backups_dir.exists() || !backups_dir.is_dir() {
            // Also check if the dir passed is already a backup or contains timestamp dirs
            return None;
        }

        let mut candidates = Vec::new();
        if let Ok(entries) = fs::read_dir(&backups_dir) {
            for entry in entries.filter_map(|e| e.ok()) {
                let path = entry.path();
                if path.is_dir() {
                    candidates.push(path);
                }
            }
        }

        // Sort descending by directory name (timestamps like 1725800000000)
        candidates.sort_by(|a, b| b.file_name().cmp(&a.file_name()));
        candidates.into_iter().next()
    }
}

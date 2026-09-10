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

        let sanitized_lines: Vec<String> = raw.lines().map(Self::sanitize_line).collect();
        let sanitized_text = sanitized_lines.join("\n");

        let mut hasher = Sha256::new();
        hasher.update(sanitized_text.as_bytes());
        let hash = format!("sha256:{}", hex::encode(hasher.finalize()));

        Ok((hash, sanitized_text))
    }

    /// Redacts sensitive key/value pairs while preserving structural configuration syntax.
    pub fn sanitize_line(line: &str) -> String {
        if !Self::contains_sensitive_term(line) {
            return line.to_string();
        }

        if let Some((k, _)) = line.split_once(':') {
            format!("{}: \"[REDACTED]\"", k)
        } else if let Some((k, _)) = line.split_once('=') {
            format!("{} = \"[REDACTED]\"", k.trim_end())
        } else {
            "# [REDACTED LINE]".to_string()
        }
    }

    /// Checks if a configuration line contains sensitive credentials or secret identifiers.
    fn contains_sensitive_term(line: &str) -> bool {
        let lower = line.to_lowercase();
        lower.contains("password")
            || lower.contains("secret")
            || lower.contains("token")
            || lower.contains("auth")
            || lower.contains("private_key")
    }

    /// Auto-discovers the backup directory from a base node directory.
    pub fn discover_latest_backup(base_dir: impl AsRef<Path>) -> Option<PathBuf> {
        let backups_dir = base_dir.as_ref().join("backups");
        if !backups_dir.exists() || !backups_dir.is_dir() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_yaml_line() {
        let line = "  auth_token: my_secret_token_123";
        assert_eq!(
            ConfigSanitizer::sanitize_line(line),
            "  auth_token: \"[REDACTED]\""
        );
    }

    #[test]
    fn test_sanitize_toml_line() {
        let line = "password = \"super_secret\"";
        assert_eq!(
            ConfigSanitizer::sanitize_line(line),
            "password = \"[REDACTED]\""
        );
    }

    #[test]
    fn test_preserve_harmless_line() {
        let line = "listening_addr = \"127.0.0.1:8228\"";
        assert_eq!(ConfigSanitizer::sanitize_line(line), line);
    }
}

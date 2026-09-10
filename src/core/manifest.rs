use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{from_str, to_string_pretty};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::fs::{read_to_string, File};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileMetadata {
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryManifest {
    pub format_version: u32,
    pub node_public_key: String,
    pub network: String,
    pub fnn_version: String,
    pub fnn_commit: String,
    pub created_at: DateTime<Utc>,
    pub database_type: String,
    pub database_present: bool,
    pub fiber_key_present: bool,
    pub ckb_key_present: bool,
    pub config_checksum: String,
    pub bundle_checksum: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_count: Option<u32>,
    pub files: BTreeMap<String, FileMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestParams {
    pub node_public_key: String,
    pub network: String,
    pub fnn_version: String,
    pub fnn_commit: String,
    pub database_type: String,
    pub config_checksum: String,
    pub channel_count: Option<u32>,
    pub payment_count: Option<u32>,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestVerificationReport {
    pub is_valid: bool,
    pub verified_files: usize,
    pub missing_files: Vec<String>,
    pub modified_files: Vec<String>,
    pub added_files: Vec<String>,
    pub bundle_checksum_match: bool,
    pub expected_bundle_checksum: String,
    pub calculated_bundle_checksum: String,
    pub errors: Vec<String>,
}

impl RecoveryManifest {
    pub fn new(params: ManifestParams) -> Self {
        Self {
            format_version: 1,
            node_public_key: params.node_public_key,
            network: params.network,
            fnn_version: params.fnn_version,
            fnn_commit: params.fnn_commit,
            created_at: params.created_at.unwrap_or_else(Utc::now),
            database_type: params.database_type,
            database_present: false,
            fiber_key_present: false,
            ckb_key_present: false,
            config_checksum: params.config_checksum,
            bundle_checksum: String::new(),
            channel_count: params.channel_count,
            payment_count: params.payment_count,
            files: BTreeMap::new(),
        }
    }

    pub fn save_to_dir(&self, dir: impl AsRef<Path>) -> Result<PathBuf> {
        let path = dir.as_ref().join("manifest.json");
        let content =
            to_string_pretty(self).context("Failed to serialize recovery manifest to JSON")?;
        fs::write(&path, content)
            .with_context(|| format!("Failed to write manifest to {:?}", path))?;
        Ok(path)
    }

    pub fn load_from_dir(dir: impl AsRef<Path>) -> Result<Self> {
        let path = dir.as_ref().join("manifest.json");
        let content = read_to_string(&path)
            .with_context(|| format!("Failed to read manifest at {:?}", path))?;
        let manifest: Self = from_str(&content)
            .with_context(|| format!("Failed to parse recovery manifest {:?}", path))?;
        Ok(manifest)
    }

    /// Recomputes all file hashes, detects missing, modified, or untracked added files,
    /// and verifies the composite bundle checksum.
    pub fn verify_against_dir(&self, dir: impl AsRef<Path>) -> Result<ManifestVerificationReport> {
        let dir = dir.as_ref();
        let mut missing_files = Vec::new();
        let mut modified_files = Vec::new();
        let mut added_files = Vec::new();
        let mut errors = Vec::new();
        let mut verified_count = 0;
        let mut bundle_hasher = Sha256::new();

        // 1. Verify every file listed in the manifest
        for (rel_path, expected_meta) in &self.files {
            let full_path = dir.join(rel_path);
            if !full_path.exists() {
                missing_files.push(rel_path.clone());
                errors.push(format!("File in manifest missing on disk: {}", rel_path));
                continue;
            }

            let actual_hash = hash_file(&full_path)?;
            let actual_size = fs::metadata(&full_path)?.len();

            if actual_hash != expected_meta.sha256 {
                modified_files.push(rel_path.clone());
                errors.push(format!(
                    "File hash mismatch for {}: expected {}, got {}",
                    rel_path, expected_meta.sha256, actual_hash
                ));
            } else if actual_size != expected_meta.size_bytes {
                modified_files.push(rel_path.clone());
                errors.push(format!(
                    "File size mismatch for {}: expected {} bytes, got {} bytes",
                    rel_path, expected_meta.size_bytes, actual_size
                ));
            } else {
                verified_count += 1;
            }
        }

        // 2. Discover all actual files on disk (excluding manifest.json)
        let mut on_disk_files = BTreeMap::new();
        for entry in WalkDir::new(dir).sort_by_file_name().into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                let rel = entry.path().strip_prefix(dir)?.to_string_lossy().to_string();
                if rel == "manifest.json" {
                    continue;
                }
                let h = hash_file(entry.path())?;
                on_disk_files.insert(rel.clone(), h);
            }
        }

        for (rel_path, hash) in &on_disk_files {
            if !self.files.contains_key(rel_path) {
                added_files.push(rel_path.clone());
                errors.push(format!("Untracked file found in backup: {}", rel_path));
            }
            bundle_hasher.update(rel_path.as_bytes());
            bundle_hasher.update(hash.as_bytes());
        }

        let calculated_bundle_checksum =
            format!("sha256:{}", hex::encode(bundle_hasher.finalize()));
        let bundle_checksum_match = calculated_bundle_checksum == self.bundle_checksum;
        if !bundle_checksum_match {
            errors.push(format!(
                "Bundle checksum mismatch: expected {}, calculated {}",
                self.bundle_checksum, calculated_bundle_checksum
            ));
        }

        let is_valid = missing_files.is_empty()
            && modified_files.is_empty()
            && added_files.is_empty()
            && bundle_checksum_match;

        Ok(ManifestVerificationReport {
            is_valid,
            verified_files: verified_count,
            missing_files,
            modified_files,
            added_files,
            bundle_checksum_match,
            expected_bundle_checksum: self.bundle_checksum.clone(),
            calculated_bundle_checksum,
            errors,
        })
    }
}

pub fn hash_file(path: impl AsRef<Path>) -> Result<String> {
    let mut file = File::open(path.as_ref())
        .with_context(|| format!("Failed to open file for hashing: {:?}", path.as_ref()))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)
        .with_context(|| format!("Failed to hash file content: {:?}", path.as_ref()))?;
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

pub fn hash_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_manifest_roundtrip_save_and_load() {
        let temp = TempDir::new().unwrap();
        let manifest = RecoveryManifest::new(ManifestParams {
            node_public_key: "03pubkey123".to_string(),
            network: "testnet".to_string(),
            fnn_version: "v0.9.0".to_string(),
            fnn_commit: "commit123".to_string(),
            database_type: "rocksdb".to_string(),
            config_checksum: "sha256:config".to_string(),
            channel_count: Some(5),
            payment_count: Some(10),
            created_at: None,
        });

        let path = manifest.save_to_dir(temp.path()).unwrap();
        assert!(path.exists());

        let loaded = RecoveryManifest::load_from_dir(temp.path()).unwrap();
        assert_eq!(loaded.node_public_key, "03pubkey123");
        assert_eq!(loaded.network, "testnet");
        assert_eq!(loaded.channel_count, Some(5));
    }

    #[test]
    fn test_manifest_verification_against_dir() {
        let temp = TempDir::new().unwrap();
        let file_a = temp.path().join("file_a.txt");
        let file_b = temp.path().join("file_b.txt");
        fs::write(&file_a, b"content A").unwrap();
        fs::write(&file_b, b"content B").unwrap();

        let hash_a = hash_file(&file_a).unwrap();
        let hash_b = hash_file(&file_b).unwrap();

        let mut manifest = RecoveryManifest::new(ManifestParams {
            node_public_key: "03pubkey".to_string(),
            network: "mainnet".to_string(),
            fnn_version: "v0.9.0".to_string(),
            fnn_commit: "commit".to_string(),
            database_type: "rocksdb".to_string(),
            config_checksum: "sha256:cfg".to_string(),
            channel_count: Some(1),
            payment_count: Some(0),
            created_at: None,
        });

        manifest.files.insert(
            "file_a.txt".to_string(),
            FileMetadata { sha256: hash_a.clone(), size_bytes: 9 },
        );
        manifest.files.insert(
            "file_b.txt".to_string(),
            FileMetadata { sha256: hash_b.clone(), size_bytes: 9 },
        );

        let mut bundle_hasher = Sha256::new();
        bundle_hasher.update(b"file_a.txt");
        bundle_hasher.update(hash_a.as_bytes());
        bundle_hasher.update(b"file_b.txt");
        bundle_hasher.update(hash_b.as_bytes());
        manifest.bundle_checksum = format!("sha256:{}", hex::encode(bundle_hasher.finalize()));

        let report = manifest.verify_against_dir(temp.path()).unwrap();
        assert!(report.is_valid, "Verification report failed: {:?}", report.errors);
        assert_eq!(report.verified_files, 2);

        // Tamper test: modify file_a
        fs::write(&file_a, b"tampered content").unwrap();
        let tampered_report = manifest.verify_against_dir(temp.path()).unwrap();
        assert!(!tampered_report.is_valid);
        assert_eq!(tampered_report.modified_files, vec!["file_a.txt"]);
    }

    #[test]
    fn test_hash_bytes() {
        let data = b"hello fnn safeguard";
        let h1 = hash_bytes(data);
        let h2 = hash_bytes(data);
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }
}

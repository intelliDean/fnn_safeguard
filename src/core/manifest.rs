use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::fs::{read_to_string, File};
use std::path::{Path, PathBuf};
use serde_json::{from_str, to_string_pretty};

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

impl RecoveryManifest {
    pub fn new(
        node_public_key: impl Into<String>,
        network: impl Into<String>,
        fnn_version: impl Into<String>,
        fnn_commit: impl Into<String>,
        database_type: impl Into<String>,
        config_checksum: impl Into<String>,
        channel_count: Option<u32>,
        payment_count: Option<u32>,
    ) -> Self {
        Self {
            format_version: 1,
            node_public_key: node_public_key.into(),
            network: network.into(),
            fnn_version: fnn_version.into(),
            fnn_commit: fnn_commit.into(),
            created_at: Utc::now(),
            database_type: database_type.into(),
            database_present: false,
            fiber_key_present: false,
            ckb_key_present: false,
            config_checksum: config_checksum.into(),
            bundle_checksum: String::new(),
            channel_count,
            payment_count,
            files: BTreeMap::new(),
        }
    }

    pub fn save_to_dir(&self, dir: impl AsRef<Path>) -> Result<PathBuf> {
        let path = dir.as_ref().join("manifest.json");
        let content = to_string_pretty(self)
            .context("Failed to serialize recovery manifest to JSON")?;
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
        let manifest = RecoveryManifest::new(
            "03pubkey123",
            "testnet",
            "v0.9.0",
            "commit123",
            "rocksdb",
            "sha256:config",
            Some(5),
            Some(10),
        );

        let path = manifest.save_to_dir(temp.path()).unwrap();
        assert!(path.exists());

        let loaded = RecoveryManifest::load_from_dir(temp.path()).unwrap();
        assert_eq!(loaded.node_public_key, "03pubkey123");
        assert_eq!(loaded.network, "testnet");
        assert_eq!(loaded.channel_count, Some(5));
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

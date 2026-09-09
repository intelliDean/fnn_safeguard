use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use super::key::IdentityKey;
use super::manifest::{hash_file, FileMetadata, RecoveryManifest};

#[derive(Debug, Clone)]
pub struct BackupValidationResult {
    pub is_valid: bool,
    pub database_type: String,
    pub database_path: PathBuf,
    pub ckb_key_path: PathBuf,
    pub fiber_key_path: PathBuf,
    pub derived_pubkey: String,
    pub total_bytes: u64,
    pub file_count: usize,
    pub errors: Vec<String>,
}

pub struct BackupValidator;

impl BackupValidator {
    pub fn inspect_and_validate(
        backup_dir: impl AsRef<Path>,
        expected_pubkey: Option<&str>,
    ) -> Result<BackupValidationResult> {
        let dir = backup_dir.as_ref();
        if !dir.exists() || !dir.is_dir() {
            bail!("Backup directory does not exist or is not a directory: {:?}", dir);
        }

        let mut errors = Vec::new();

        // 1. Check fiber identity key `sk`
        let fiber_key_path = dir.join("sk");
        let mut derived_pubkey = String::new();
        if !fiber_key_path.exists() {
            errors.push("Missing Fiber identity key file ('sk') in backup".to_string());
        } else {
            match IdentityKey::from_file(&fiber_key_path) {
                Ok(id_key) => {
                    derived_pubkey = id_key.public_key_hex().to_string();
                    if let Some(expected) = expected_pubkey {
                        if !id_key.matches_public_key(expected) {
                            errors.push(format!(
                                "Node public key mismatch: derived {} does not match expected {}",
                                derived_pubkey, expected
                            ));
                        }
                    }
                }
                Err(e) => {
                    errors.push(format!("Corrupt or unreadable Fiber identity key ('sk'): {}", e));
                }
            }
        }

        // 2. Check CKB key `key`
        let ckb_key_path = dir.join("key");
        if !ckb_key_path.exists() {
            errors.push("Missing CKB key file ('key') in backup".to_string());
        } else {
            let meta = fs::metadata(&ckb_key_path)
                .with_context(|| format!("Failed to read CKB key metadata {:?}", ckb_key_path))?;
            if meta.len() == 0 {
                errors.push("CKB key file ('key') is empty (0 bytes)".to_string());
            }
        }

        // 3. Check Database (either RocksDB `db/` directory or SQLite `data.sqlite`)
        let rocksdb_path = dir.join("db");
        let sqlite_path = dir.join("data.sqlite");

        let (database_type, database_path) = if rocksdb_path.is_dir() {
            // Verify RocksDB has CURRENT file or SST files
            let current_file = rocksdb_path.join("CURRENT");
            if !current_file.exists() {
                errors.push("RocksDB directory exists but lacks 'CURRENT' descriptor file".to_string());
            }
            ("rocksdb".to_string(), rocksdb_path)
        } else if sqlite_path.is_file() {
            let meta = fs::metadata(&sqlite_path)?;
            if meta.len() == 0 {
                errors.push("SQLite database file 'data.sqlite' is 0 bytes".to_string());
            }
            ("sqlite".to_string(), sqlite_path)
        } else {
            errors.push("No valid database checkpoint found: neither 'db/' nor 'data.sqlite' exists".to_string());
            ("unknown".to_string(), rocksdb_path)
        };

        // Calculate size & file count
        let mut total_bytes = 0u64;
        let mut file_count = 0usize;
        for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                file_count += 1;
                if let Ok(meta) = entry.metadata() {
                    total_bytes += meta.len();
                }
            }
        }

        let is_valid = errors.is_empty();

        Ok(BackupValidationResult {
            is_valid,
            database_type,
            database_path,
            ckb_key_path,
            fiber_key_path,
            derived_pubkey,
            total_bytes,
            file_count,
            errors,
        })
    }

    /// Generates a full RecoveryManifest for the validated backup directory.
    pub fn build_manifest(
        backup_dir: impl AsRef<Path>,
        network: &str,
        fnn_version: &str,
        fnn_commit: &str,
        config_checksum: &str,
        channel_count: Option<u32>,
        payment_count: Option<u32>,
        expected_pubkey: Option<&str>,
    ) -> Result<RecoveryManifest> {
        let dir = backup_dir.as_ref();
        let validation = Self::inspect_and_validate(dir, expected_pubkey)?;
        if !validation.is_valid {
            bail!("Cannot build manifest for invalid backup: {:?}", validation.errors);
        }

        let mut manifest = RecoveryManifest::new(
            &validation.derived_pubkey,
            network,
            fnn_version,
            fnn_commit,
            &validation.database_type,
            config_checksum,
            channel_count,
            payment_count,
        );

        manifest.database_present = true;
        manifest.fiber_key_present = true;
        manifest.ckb_key_present = true;

        let mut files_map = BTreeMap::new();
        let mut bundle_hasher = Sha256::new();

        for entry in WalkDir::new(dir).sort_by_file_name().into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                let file_path = entry.path();
                let file_name = file_path.file_name().unwrap_or_default().to_string_lossy();
                // Skip existing manifest.json when rehashing
                if file_name == "manifest.json" {
                    continue;
                }

                let rel_path = file_path
                    .strip_prefix(dir)
                    .unwrap_or(file_path)
                    .to_string_lossy()
                    .to_string();

                let hash = hash_file(file_path)?;
                let meta = fs::metadata(file_path)?;
                bundle_hasher.update(rel_path.as_bytes());
                bundle_hasher.update(hash.as_bytes());

                files_map.insert(
                    rel_path,
                    FileMetadata {
                        sha256: hash,
                        size_bytes: meta.len(),
                    },
                );
            }
        }

        manifest.bundle_checksum = format!("sha256:{}", hex::encode(bundle_hasher.finalize()));
        manifest.files = files_map;

        Ok(manifest)
    }
}

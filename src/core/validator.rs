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

        let (fiber_key_path, derived_pubkey) = Self::validate_fiber_key(dir, expected_pubkey, &mut errors);
        let ckb_key_path = Self::validate_ckb_key(dir, &mut errors);
        let (database_type, database_path) = Self::validate_database(dir, &mut errors);
        let (total_bytes, file_count) = Self::calculate_dir_stats(dir);

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

    /// Validates the presence, length, and secp256k1 derivation of the Fiber secret key.
    fn validate_fiber_key(
        dir: &Path,
        expected_pubkey: Option<&str>,
        errors: &mut Vec<String>,
    ) -> (PathBuf, String) {
        let fiber_key_path = dir.join("sk");
        let mut derived_pubkey = String::new();

        if !fiber_key_path.exists() {
            errors.push("Missing Fiber identity key file ('sk') in backup".to_string());
            return (fiber_key_path, derived_pubkey);
        }

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

        (fiber_key_path, derived_pubkey)
    }

    /// Validates the existence and readability of the CKB encrypted key file.
    fn validate_ckb_key(dir: &Path, errors: &mut Vec<String>) -> PathBuf {
        let ckb_key_path = dir.join("key");
        if !ckb_key_path.exists() {
            errors.push("Missing CKB key file ('key') in backup".to_string());
        } else if let Ok(meta) = fs::metadata(&ckb_key_path) {
            if meta.len() == 0 {
                errors.push("CKB key file ('key') is empty (0 bytes)".to_string());
            }
        } else {
            errors.push("Failed to read CKB key metadata".to_string());
        }
        ckb_key_path
    }

    /// Identifies and validates the database backend (RocksDB `db/` or SQLite `data.sqlite`).
    fn validate_database(dir: &Path, errors: &mut Vec<String>) -> (String, PathBuf) {
        let rocksdb_path = dir.join("db");
        let sqlite_path = dir.join("data.sqlite");

        if rocksdb_path.is_dir() {
            let current_file = rocksdb_path.join("CURRENT");
            if !current_file.exists() {
                errors.push("RocksDB directory exists but lacks 'CURRENT' descriptor file".to_string());
            }
            ("rocksdb".to_string(), rocksdb_path)
        } else if sqlite_path.is_file() {
            if let Ok(meta) = fs::metadata(&sqlite_path) {
                if meta.len() == 0 {
                    errors.push("SQLite database file 'data.sqlite' is 0 bytes".to_string());
                }
            } else {
                errors.push("Failed to read SQLite database metadata".to_string());
            }
            ("sqlite".to_string(), sqlite_path)
        } else {
            errors.push("No valid database checkpoint found: neither 'db/' nor 'data.sqlite' exists".to_string());
            ("unknown".to_string(), rocksdb_path)
        }
    }

    /// Counts total files and aggregates cumulative byte size in the backup directory.
    fn calculate_dir_stats(dir: &Path) -> (u64, usize) {
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

        (total_bytes, file_count)
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

        let (files_map, bundle_checksum) = Self::collect_file_hashes(dir)?;
        manifest.files = files_map;
        manifest.bundle_checksum = bundle_checksum;

        Ok(manifest)
    }

    /// Collects SHA-256 hashes for all constituent files and computes the composite bundle checksum.
    fn collect_file_hashes(dir: &Path) -> Result<(BTreeMap<String, FileMetadata>, String)> {
        let mut files_map = BTreeMap::new();
        let mut bundle_hasher = Sha256::new();

        for entry in WalkDir::new(dir).sort_by_file_name().into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                let file_path = entry.path();
                let file_name = file_path.file_name().unwrap_or_default().to_string_lossy();
                // Exclude manifest.json itself when computing constituent hashes
                if file_name == "manifest.json" {
                    continue;
                }

                let rel_path = file_path
                    .strip_prefix(dir)
                    .unwrap_or(file_path)
                    .to_string_lossy()
                    .to_string();

                let hash = hash_file(file_path)?;
                let meta = fs::metadata(file_path)
                    .with_context(|| format!("Failed to read metadata for {:?}", file_path))?;

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

        let bundle_checksum = format!("sha256:{}", hex::encode(bundle_hasher.finalize()));
        Ok((files_map, bundle_checksum))
    }
}

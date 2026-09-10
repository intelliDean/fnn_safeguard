use fnn_safeguard::core::manifest::RecoveryManifest;
use fnn_safeguard::core::validator::{BackupValidator, BuildManifestParams};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::fs;
use tempfile::TempDir;

pub fn create_mock_valid_backup(dir: &TempDir) -> (String, String) {
    let backup_dir = dir.path().join("backups").join("1725800000000");
    fs::create_dir_all(&backup_dir).unwrap();

    // 1. Valid 32-byte secp256k1 secret key
    let secp = Secp256k1::new();
    let sk_bytes = [7u8; 32];
    let sk = SecretKey::from_slice(&sk_bytes).unwrap();
    let pk = PublicKey::from_secret_key(&secp, &sk);
    let expected_pubkey = hex::encode(pk.serialize());

    fs::write(backup_dir.join("sk"), sk_bytes).unwrap();

    // 2. Dummy encrypted CKB key (108 bytes)
    let ckb_key_bytes = vec![0x42u8; 108];
    fs::write(backup_dir.join("key"), &ckb_key_bytes).unwrap();

    // 3. Dummy RocksDB checkpoint directory
    let db_dir = backup_dir.join("db");
    fs::create_dir_all(&db_dir).unwrap();
    fs::write(db_dir.join("CURRENT"), "MANIFEST-000001\n").unwrap();
    fs::write(db_dir.join("MANIFEST-000001"), "dummy-manifest-bytes").unwrap();
    fs::write(db_dir.join("000002.sst"), "dummy-sst-bytes").unwrap();

    (backup_dir.display().to_string(), expected_pubkey)
}

#[test]
fn test_backup_validation_and_manifest_generation() {
    let temp_dir = TempDir::new().unwrap();
    let (backup_path, expected_pubkey) = create_mock_valid_backup(&temp_dir);

    // 1. Inspect and validate
    let validation =
        BackupValidator::inspect_and_validate(&backup_path, Some(&expected_pubkey)).unwrap();
    assert!(validation.is_valid, "Validation failed: {:?}", validation.errors);
    assert_eq!(validation.database_type, "rocksdb");
    assert_eq!(validation.derived_pubkey, expected_pubkey);
    assert_eq!(validation.file_count, 5); // sk, key, CURRENT, MANIFEST-000001, 000002.sst

    // 2. Build manifest
    let manifest_params = BuildManifestParams {
        network: "testnet",
        fnn_version: "v0.9.0",
        fnn_commit: "e6cb7ac7770b1798a1ad5dfb9a8f4ae5db52036f",
        config_checksum: "sha256:dummy_config_hash",
        channel_count: Some(12),
        payment_count: Some(45),
        created_at: None,
        expected_pubkey: Some(&expected_pubkey),
    };
    let manifest = BackupValidator::build_manifest(&backup_path, &manifest_params).unwrap();

    assert_eq!(manifest.format_version, 1);
    assert_eq!(manifest.node_public_key, expected_pubkey);
    assert!(manifest.database_present);
    assert!(manifest.fiber_key_present);
    assert!(manifest.ckb_key_present);
    assert!(manifest.bundle_checksum.starts_with("sha256:"));
    assert_eq!(manifest.files.len(), 5);

    // 3. Save and reload manifest
    let manifest_path = manifest.save_to_dir(&backup_path).unwrap();
    assert!(manifest_path.exists());

    let loaded = RecoveryManifest::load_from_dir(&backup_path).unwrap();
    assert_eq!(loaded.node_public_key, expected_pubkey);
    assert_eq!(loaded.bundle_checksum, manifest.bundle_checksum);
}

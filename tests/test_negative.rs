use fnn_safeguard::core::validator::{BackupValidator, BuildManifestParams};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::fs;
use tempfile::TempDir;

#[test]
fn test_negative_missing_sk() {
    let temp_dir = TempDir::new().unwrap();
    let backup_dir = temp_dir.path().join("backup");
    fs::create_dir_all(&backup_dir).unwrap();

    fs::write(backup_dir.join("key"), vec![0x11; 64]).unwrap();
    fs::write(backup_dir.join("data.sqlite"), "SQLite format 3\0test").unwrap();

    let res = BackupValidator::inspect_and_validate(&backup_dir, None).unwrap();
    assert!(!res.is_valid);
    assert!(
        res.errors
            .iter()
            .any(|e| e.contains("Missing Fiber identity key"))
    );
}

#[test]
fn test_negative_missing_ckb_key() {
    let temp_dir = TempDir::new().unwrap();
    let backup_dir = temp_dir.path().join("backup");
    fs::create_dir_all(&backup_dir).unwrap();

    fs::write(backup_dir.join("sk"), [3u8; 32]).unwrap();
    fs::write(backup_dir.join("data.sqlite"), "SQLite format 3\0test").unwrap();

    let res = BackupValidator::inspect_and_validate(&backup_dir, None).unwrap();
    assert!(!res.is_valid);
    assert!(
        res.errors
            .iter()
            .any(|e| e.contains("Missing CKB key file"))
    );
}

#[test]
fn test_negative_missing_database() {
    let temp_dir = TempDir::new().unwrap();
    let backup_dir = temp_dir.path().join("backup");
    fs::create_dir_all(&backup_dir).unwrap();

    fs::write(backup_dir.join("sk"), [3u8; 32]).unwrap();
    fs::write(backup_dir.join("key"), vec![0x11; 64]).unwrap();

    let res = BackupValidator::inspect_and_validate(&backup_dir, None).unwrap();
    assert!(!res.is_valid);
    assert!(
        res.errors
            .iter()
            .any(|e| e.contains("No valid database checkpoint found"))
    );
}

#[test]
fn test_negative_identity_mismatch() {
    let temp_dir = TempDir::new().unwrap();
    let backup_dir = temp_dir.path().join("backup");
    fs::create_dir_all(&backup_dir).unwrap();

    // Node 1 key
    let secp = Secp256k1::new();
    let sk1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
    let pk1 = PublicKey::from_secret_key(&secp, &sk1);
    let pubkey1 = hex::encode(pk1.serialize());

    // Node 2 key
    let sk2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
    let pk2 = PublicKey::from_secret_key(&secp, &sk2);
    let pubkey2 = hex::encode(pk2.serialize());

    fs::write(backup_dir.join("sk"), [1u8; 32]).unwrap();
    fs::write(backup_dir.join("key"), vec![0x11; 64]).unwrap();
    fs::write(backup_dir.join("data.sqlite"), "SQLite format 3\0test").unwrap();

    // Validate with expected pubkey of Node 2 while backup has Node 1
    let res = BackupValidator::inspect_and_validate(&backup_dir, Some(&pubkey2)).unwrap();
    assert!(!res.is_valid);
    assert!(
        res.errors
            .iter()
            .any(|e| e.contains("Node public key mismatch"))
    );

    // Validate with expected pubkey of Node 1
    let res_ok = BackupValidator::inspect_and_validate(&backup_dir, Some(&pubkey1)).unwrap();
    assert!(res_ok.is_valid);
}

#[test]
fn test_zero_secrets_in_manifest() {
    let temp_dir = TempDir::new().unwrap();
    let backup_dir = temp_dir.path().join("backup");
    fs::create_dir_all(&backup_dir).unwrap();

    let raw_secret_bytes = [0x55u8; 32];
    fs::write(backup_dir.join("sk"), raw_secret_bytes).unwrap();
    fs::write(backup_dir.join("key"), vec![0xaa; 64]).unwrap();
    fs::write(backup_dir.join("data.sqlite"), "SQLite format 3\0test").unwrap();

    let params = BuildManifestParams {
        network: "testnet",
        fnn_version: "v0.9.0",
        fnn_commit: "commit",
        config_checksum: "sha256:config",
        channel_count: None,
        payment_count: None,
        created_at: None,
        expected_pubkey: None,
    };
    let manifest = BackupValidator::build_manifest(&backup_dir, &params).unwrap();

    let json_str = serde_json::to_string(&manifest).unwrap();

    // Verify secret key raw hex is NOT present in the manifest JSON
    let secret_hex = hex::encode(raw_secret_bytes);
    assert!(
        !json_str.contains(&secret_hex),
        "Raw private key was leaked into manifest JSON!"
    );
}

#[test]
fn test_negative_corrupted_rocksdb_restore_fails() {
    use fnn_safeguard::isolation::process::ProcessIsolationSandbox;

    let temp_dir = TempDir::new().unwrap();
    let backup_dir = temp_dir.path().join("backup");
    fs::create_dir_all(&backup_dir).unwrap();

    // Copy fixture
    let fixture_db = std::path::Path::new("tests/fixtures/valid_backup/db");
    let dest_db = backup_dir.join("db");
    fs::create_dir_all(&dest_db).unwrap();
    for entry in fs::read_dir(fixture_db).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), dest_db.join(entry.file_name())).unwrap();
    }
    fs::copy("tests/fixtures/valid_backup/sk", backup_dir.join("sk")).unwrap();
    fs::copy("tests/fixtures/valid_backup/key", backup_dir.join("key")).unwrap();

    // Intentionally corrupt CURRENT pointer
    fs::write(dest_db.join("CURRENT"), "CORRUPTED_POINTER\n").unwrap();

    let sandbox = ProcessIsolationSandbox::new().unwrap();
    let result = sandbox.run_restore_drill(&backup_dir, None, None);

    // Fail-closed verification: must return Err or report database_opened == false
    assert!(
        result.is_err(),
        "Restore drill must fail on corrupted RocksDB checkpoint"
    );
}

#[test]
fn test_negative_wrong_key_identity_drill_fails() {
    use fnn_safeguard::isolation::process::ProcessIsolationSandbox;

    let temp_dir = TempDir::new().unwrap();
    let backup_dir = temp_dir.path().join("backup");
    fs::create_dir_all(&backup_dir).unwrap();

    let fixture_db = std::path::Path::new("tests/fixtures/valid_backup/db");
    let dest_db = backup_dir.join("db");
    fs::create_dir_all(&dest_db).unwrap();
    for entry in fs::read_dir(fixture_db).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), dest_db.join(entry.file_name())).unwrap();
    }
    fs::copy("tests/fixtures/valid_backup/sk", backup_dir.join("sk")).unwrap();
    fs::copy("tests/fixtures/valid_backup/key", backup_dir.join("key")).unwrap();

    let sandbox = ProcessIsolationSandbox::new().unwrap();
    let wrong_pubkey = "020000000000000000000000000000000000000000000000000000000000000001";
    let result = sandbox.run_restore_drill(&backup_dir, None, Some(wrong_pubkey));

    assert!(
        result.is_err(),
        "Restore drill must fail-closed when expected public key does not match restored key"
    );
}

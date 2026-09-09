use fnn_safeguard::core::key::PermissionManager;
use fnn_safeguard::isolation::process::ProcessIsolationSandbox;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::fs;
use tempfile::TempDir;

#[test]
fn test_restore_drill_with_readonly_key_permission_bug() {
    let temp_dir = TempDir::new().unwrap();
    let backup_dir = temp_dir.path().join("backup");
    fs::create_dir_all(&backup_dir).unwrap();

    // 1. Create valid secret key
    let secp = Secp256k1::new();
    let sk_bytes = [9u8; 32];
    let sk = SecretKey::from_slice(&sk_bytes).unwrap();
    let pk = PublicKey::from_secret_key(&secp, &sk);
    let expected_pubkey = hex::encode(pk.serialize());

    fs::write(backup_dir.join("sk"), &sk_bytes).unwrap();
    fs::write(backup_dir.join("key"), vec![0x11; 64]).unwrap();

    // 2. Create mock SQLite database
    fs::write(backup_dir.join("data.sqlite"), "SQLite format 3\0dummy-sql-data").unwrap();

    // 3. Initialize ProcessIsolationSandbox
    let sandbox = ProcessIsolationSandbox::new().unwrap();

    // 4. Intentionally pre-create a destination `fiber/sk` file with 0o400 (read-only)
    // to simulate the exact FNN v0.9.0 restore crash bug!
    let target_fiber_dir = sandbox.path().join("restored_node").join("fiber");
    fs::create_dir_all(&target_fiber_dir).unwrap();
    let pre_existing_sk = target_fiber_dir.join("sk");
    fs::write(&pre_existing_sk, [0u8; 32]).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&pre_existing_sk).unwrap().permissions();
        perms.set_mode(0o400); // READ-ONLY!
        fs::set_permissions(&pre_existing_sk, perms).unwrap();
        assert_eq!(PermissionManager::check_permission_mode(&pre_existing_sk).unwrap(), 0o400);
    }

    // 5. Run restore drill
    // Safeguard's PermissionManager should safely set mode 0o600 before copy,
    // execute restore, and set back to 0o400 without crashing!
    let report = sandbox.run_restore_drill(&backup_dir, None, Some(&expected_pubkey)).unwrap();

    assert!(report.backup_valid);
    assert!(report.database_opened);
    assert!(report.identity_match);
    assert!(report.p2p_egress_blocked);
    assert!(report.permission_workaround_applied);
    assert_eq!(report.restored_pubkey, expected_pubkey);

    // Verify final permission on restored sk is hardened to 0o400
    #[cfg(unix)]
    {
        assert_eq!(PermissionManager::check_permission_mode(&pre_existing_sk).unwrap(), 0o400);
    }
}

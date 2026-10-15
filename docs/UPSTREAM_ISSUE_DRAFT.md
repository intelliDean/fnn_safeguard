# Upstream Issue Draft for nervosnetwork/fiber

**Target Repository**: [nervosnetwork/fiber](https://github.com/nervosnetwork/fiber/issues)  
**Suggested Title**: `FNN v0.9.0: repeatable restore failure with missing SST files after successful backup`

---

### Description

During automated disaster recovery validation across two independent local Fiber devnet nodes running official FNN v0.9.0, we observed a repeatable failure when executing `fnn --restore` on newly created backups generated via the native administrative backup RPC.

We reproduced this failure twice under controlled, isolated conditions and are reporting our observations and reproduction logs for maintainer investigation.

---

### Environment

- **FNN Version**: `fnn 0.9.0 (17173b2 2026-09-08)` / official release binary
- **Host OS**: Linux (Ubuntu 24.04 LTS / x86_64, Linux kernel 6.8.0)
- **Deployment**: Standalone binary and containerized (Docker)
- **Chain**: Local CKB devnet (`dev.toml`)
- **Storage**: RocksDB online checkpoint backup created via admin JSON-RPC

---

### Steps to Reproduce

1. Start an FNN v0.9.0 node with open payment channels and settled payments.
2. Call the native administrative backup RPC:
   ```json
   {
     "jsonrpc": "2.0",
     "method": "backup",
     "params": [{ "backup_path": "/path/to/backup_dir" }],
     "id": 1
   }
   ```
   The RPC returns `{"jsonrpc": "2.0", "result": null, "id": 1}` and creates a timestamped backup directory containing `db/`, `sk`, and `key`.
3. In a separate, clean target directory `/tmp/restore_target`, prepare a minimal `config.yml`.
4. Attempt to restore the backup using the official binary:
   ```bash
   fnn -d /tmp/restore_target -c /tmp/restore_target/config.yml --restore /path/to/backup_dir
   ```

---

### Expected Result

`fnn --restore` restores the RocksDB database and key files into `/tmp/restore_target` and exits with code 0, allowing subsequent `fnn --check-validate` to validate the database.

---

### Actual Result

The command fails with non-zero exit code (exit code 1) and outputs an IO error indicating missing SST files:

```
Error: Corruption: Corruption: IO error: While open a file for random read: /tmp/restore_target/fiber/store/00000X.sst: No such file or directory
```

#### Detailed Observations:
- In both independent node runs, the checkpoint files in `backup_dir/db` are complete and intact.
- When the checkpoint files from `backup_dir/db` are copied directly into the target `fiber/store` directory without running the native restore routine, running `fnn --check-validate` passes cleanly with `db validate success`, and the daemon starts up normally with all channels and payments preserved.

---

### Independent Reproductions & Evidence

We captured full stdout/stderr and audit logs across two distinct node runs:

1. **Reproduction 1 (Node 1)**:
   - Restore log: [`evidence/devnet-node1/restore-output.log`](../../evidence/devnet-node1/restore-output.log)
   - Database validation log: [`evidence/devnet-node1/check-validate-output.log`](../../evidence/devnet-node1/check-validate-output.log)
2. **Reproduction 2 (Node 2)**:
   - Restore log: [`evidence/devnet-node2/restore-output.log`](../../evidence/devnet-node2/restore-output.log)
   - Database validation log: [`evidence/devnet-node2/check-validate-output.log`](../../evidence/devnet-node2/check-validate-output.log)

---

### Second Related Observation (Read-Only Key File Mode)

In addition to the missing SST behavior, we also observed that when restoring over an existing node directory where `sk` was previously created with mode `0o400`, `fnn --restore` fails with `PermissionDenied` (`EACCES`) during file copy. Setting the file permission to `0o600` prior to restore allows file copying to succeed.

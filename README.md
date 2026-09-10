# FNN Safeguard

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![Fiber Compatibility](https://img.shields.io/badge/Fiber%20Node-v0.9.0%2B-emerald.svg)](https://github.com/nervosnetwork/fiber)
[![CI Status](https://github.com/intelliDean/fnn_safeguard/actions/workflows/ci.yml/badge.svg)](https://github.com/intelliDean/fnn_safeguard/actions/workflows/ci.yml)

> **Verified Recovery Points, Isolated Disaster Drills, and Pre-Upgrade Qualification for Nervos Fiber Network Nodes (FNN).**

FNN Safeguard is a self-hosted operator tool designed to verify backups and test disaster recovery procedures for Fiber Network Nodes on Nervos CKB. It independently validates backup completeness, generates cryptographic manifests, verifies identity key derivation, and executes end-to-end restore drills against the official `fnn` binary in an isolated sandbox with blocked P2P egress.

---

## Table of Contents

- [The Problem: Fiber Recovery Hazards](#the-problem-fiber-recovery-hazards)
- [The Solution: Verifiable Operational Safeguards](#the-solution-verifiable-operational-safeguards)
- [Core Safety Guardrails](#core-safety-guardrails)
- [Architecture & Code Structure](#architecture--code-structure)
- [Quickstart](#quickstart)
- [CLI Command Reference](#cli-command-reference)
  - [1. Node Inspection (`inspect`)](#1-node-inspection-inspect)
  - [2. Verified Backup & Manifest Generation (`backup`)](#2-verified-backup--manifest-generation-backup)
  - [3. Sandboxed Disaster Recovery Drill (`drill`)](#3-sandboxed-disaster-recovery-drill-drill)
- [Measured Grant Evidence (`evidence/fnn-v0.9.x-testnet`)](#measured-grant-evidence-evidencefnn-v09x-testnet)
- [Cryptographic Recovery Manifest Specification](#cryptographic-recovery-manifest-specification)
- [Testing & Quality Assurance](#testing--quality-assurance)
- [Grant Roadmap & Future Milestones](#grant-roadmap--future-milestones)
- [License](#license)

---

## The Problem: Fiber Recovery Hazards

Fiber Network Nodes (v0.9.0+) support native online checkpointing via admin RPC. However, running a production Fiber node (routing nodes, merchant gateways, and Cross-Chain Hub [CCH] services) exposes operators to operational hazards:

1. **The Double-Signing & State Penalty Hazard**:
   In payment channel networks, broadcasting an outdated channel commitment transaction on-chain allows the remote peer to immediately trigger a **penalty dispute transaction** on CKB, permanently confiscating the operator's locked channel collateral. Restoring a backup on a live node without auditing channel state carries severe financial risk.
2. **The Read-Only Key Permission Restore Bug (`0o400` EACCES)**:
   FNN v0.9.0 writes the secret key (`sk`) with `0o400` permissions. During restoration over an existing node directory, `std::fs::copy` fails with `PermissionDenied` (EACCES) before database or channel-recovery routines can execute.
3. **Unverified Backup Completeness**:
   A backup directory may exist on disk without proving that:
   - The RocksDB storage is intact and readable.
   - Both the Fiber identity key (`sk`) and CKB keystore (`key`) are present and uncorrupted.
   - The public key matches the expected node identity.
4. **Secret Leakage in Artifacts**:
   Backups and configs frequently contain sensitive credentials (`rpc.auth_token`, `FIBER_SECRET_KEY_PASSWORD`, or raw key bytes) that must never leak into operational manifests, audit logs, or shared reports.

---

## The Solution: Verifiable Operational Safeguards

FNN Safeguard wraps FNN's existing backup capabilities into an automated, verifiable pipeline:

```
+-----------------------------------------------------------------------------------+
|                              FNN SAFEGUARD WORKFLOW                               |
+-----------------------------------------------------------------------------------+
   [ Live Node ]
         |
         v
   1. INSPECT       --> Collect non-secret inventory (channels, payments, config hash)
         |
         v
   2. BACKUP        --> Checkpoint RocksDB, verify secp256k1 key, hash files
         |
         v
   3. MANIFEST      --> Produce deterministic SHA-256 RecoveryManifest (0 secrets)
         |
         v
   4. DRILL         --> Spin up isolated sandbox with P2P EGRESS BLOCKED
         |              Resolve 0o400 key permissions, run real fnn --restore & --check-validate
         v
   5. EVIDENCE      --> Emit 13 machine-readable audit evidence files
```

---

## Core Safety Guardrails

- **No Automated Live Rollbacks**: Safeguard never automatically rolls back a live production database. All recovery validations occur in temporary, ephemeral sandboxes.
- **Strict P2P Network Egress Severing**: During restore drills, P2P network egress is strictly severed (via Docker container isolation with `--network none` or process sandbox port re-binding) to guarantee that restored nodes cannot contact live peers or emit stale transactions.
- **Zero-Knowledge Manifests & Secret Sanitization**: Node configuration files (`config.yml`) are parsed line-by-line; sensitive credentials, passwords, and Biscuit tokens are masked with `[REDACTED]` prior to SHA-256 hashing.
- **Automatic Permission Manager**: Resolves the Fiber v0.9.0 read-only file mode issue by elevating to `0o600` during restore staging and locking down to `0o400` once restored.
- **Fail-Closed Verification**: Safeguard never reports `VERIFIED` without direct execution of official `fnn --restore` and `fnn --check-validate` returning success (`db validate success`).

---

## Architecture & Code Structure

FNN Safeguard is built in idiomatic Rust adhering to the Single Responsibility Principle:

```
src/
├── lib.rs                  # Library entrypoint exposing core modules
├── main.rs                 # Minimal CLI entrypoint
├── cli.rs                  # Clap CLI schema, argument parsing & dispatch
├── config.rs               # Secret sanitizer & configuration hasher
├── commands/               # Command implementations
│   ├── mod.rs
│   ├── inspect.rs          # `inspect` command
│   ├── backup.rs           # `backup` verification & manifest creation
│   └── drill.rs            # `drill` recovery drill & evidence generation
├── core/                   # Domain logic
│   ├── key.rs              # secp256k1 key derivation & permission management
│   ├── manifest.rs         # Cryptographic RecoveryManifest & verification
│   ├── reporter.rs         # Terminal formatting & JSON outputs
│   └── validator.rs        # Backup directory structural integrity checks
├── isolation/              # Sandboxed execution environments
│   ├── mod.rs
│   ├── docker.rs           # Docker container drill with `--network none`
│   └── process.rs          # Process isolation executing native `fnn`
└── rpc/                    # FNN JSON-RPC 2.0 client
    ├── client.rs           # Strongly-typed HTTP client with auto-pagination
    └── types.rs            # FNN v0.9.x data models & hex parsing
```

---

## Quickstart

### Prerequisites
- Rust 1.80+ (or compatible stable toolchain)
- Official `fnn` binary (`Fiber v0.9.0+`) or Docker for container drills

### Building from Source

```bash
git clone https://github.com/intelliDean/fnn_safeguard.git
cd fnn_safeguard
cargo build --release
```

The compiled binary is available at `target/release/fnn-safeguard`.

---

## CLI Command Reference

### 1. Node Inspection (`inspect`)
Collects a non-secret operational inventory from a running Fiber node via JSON-RPC:

```bash
fnn-safeguard inspect --rpc-url http://127.0.0.1:8227 --config /path/to/config.yml
```

### 2. Verified Backup & Manifest Generation (`backup`)
Validates a native FNN backup, verifies cryptographic keys, and generates a tamper-evident `manifest.json`:

```bash
# Validate existing latest backup in directory
fnn-safeguard backup --node-dir /var/lib/fiber

# Trigger immediate backup via RPC and wait for completion
fnn-safeguard backup --trigger --rpc-url http://127.0.0.1:8227 --node-dir /var/lib/fiber
```

### 3. Sandboxed Disaster Recovery Drill (`drill`)
Executes an end-to-end recovery test inside an isolated environment with network egress disabled, running the official `fnn --restore` and `fnn --check-validate`:

```bash
# Native process sandbox drill with evidence generation
fnn-safeguard drill \
  --backup tests/fixtures/valid_backup \
  --evidence-dir evidence/fnn-v0.9.x-testnet

# Docker isolated container drill
fnn-safeguard drill \
  --backup tests/fixtures/valid_backup \
  --docker
```

---

## Measured Grant Evidence (`evidence/fnn-v0.9.x-testnet`)

Machine-readable evidence files generated from real execution of official `fnn` v0.9.0 binary (`Fiber v0.9.0 (e6cb7ac-dirty 2026-08-06)`):

| Evidence File | Description |
| :--- | :--- |
| [`environment.json`](evidence/fnn-v0.9.x-testnet/environment.json) | Host system OS, kernel, CPU, binary path, and Docker availability. |
| [`fnn-binary.sha256`](evidence/fnn-v0.9.x-testnet/fnn-binary.sha256) | SHA-256 checksum matching official `fnn` binary. |
| [`source-inspect.json`](evidence/fnn-v0.9.x-testnet/source-inspect.json) | Non-secret inventory of source node state. |
| [`backup-verification.json`](evidence/fnn-v0.9.x-testnet/backup-verification.json) | Structural integrity check and key derivation results. |
| [`manifest.json`](evidence/fnn-v0.9.x-testnet/manifest.json) | Deterministic cryptographic recovery manifest. |
| [`manifest-verification.json`](evidence/fnn-v0.9.x-testnet/manifest-verification.json) | Independent verification recomputing all hashes and bundle checksum. |
| [`restore-output.log`](evidence/fnn-v0.9.x-testnet/restore-output.log) | Complete stdout/stderr logs from `fnn --restore`. |
| [`check-validate-output.log`](evidence/fnn-v0.9.x-testnet/check-validate-output.log) | Complete stdout/stderr from `fnn --check-validate` confirming DB validity. |
| [`restored-inspect.json`](evidence/fnn-v0.9.x-testnet/restored-inspect.json) | Inventory of restored node state after drill. |
| [`inventory-diff.json`](evidence/fnn-v0.9.x-testnet/inventory-diff.json) | Delta verification proving identity and state match. |
| [`network-isolation-test.json`](evidence/fnn-v0.9.x-testnet/network-isolation-test.json) | Proof of blocked P2P egress and severed external connectivity. |
| [`secret-scan.json`](evidence/fnn-v0.9.x-testnet/secret-scan.json) | Automated regex scan confirming zero secret leaks across all artifacts. |
| [`final-report.json`](evidence/fnn-v0.9.x-testnet/final-report.json) | Unified summary report with overall `VERIFIED` status. |

---

## Cryptographic Recovery Manifest Specification

Every validated backup includes a `manifest.json` recording cryptographic proofs of completeness without disclosing secrets:

```json
{
  "format_version": 1,
  "node_public_key": "02297d34b5d228f17e374f25d4aab4c8afb5bb557b275e938b1d2c9671ff39ccd3",
  "network": "testnet",
  "fnn_version": "v0.9.0",
  "fnn_commit": "e6cb7ac-dirty",
  "created_at": "2026-09-10T11:56:23Z",
  "database_type": "rocksdb",
  "database_present": true,
  "fiber_key_present": true,
  "ckb_key_present": true,
  "config_checksum": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "bundle_checksum": "sha256:13206a928c0968bed0cedb702cc516dd1289be42b9a62e4984232111f702bf8b",
  "channel_count": 0,
  "payment_count": 0,
  "files": {
    "db/000003.log": {
      "sha256": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "size_bytes": 0
    },
    "db/CURRENT": {
      "sha256": "sha256:60655d8fce2b8004f1418be297df5380fb37305ce7b543163354cb7b21e86095",
      "size_bytes": 16
    },
    "key": {
      "sha256": "sha256:bbca615469904fa180738435d648bfaec05bc5a4dbb830d1d29388df6719abde",
      "size_bytes": 64
    },
    "sk": {
      "sha256": "sha256:fc6d267329fb2540b61405e3f4e912fdcbe10ee2a905be8ff7d2b271d44fd01f",
      "size_bytes": 32
    }
  }
}
```

---

## Testing & Quality Assurance

FNN Safeguard includes automated tests covering unit logic, mock RPC servers, container isolation, and security negative testing:

```bash
# Run all tests
cargo test --all

# Run strict linting with zero warnings allowed
cargo clippy --all-targets -- -D warnings

# Check code formatting
cargo fmt --check
```

### Test Coverage Highlights
- **`tests/test_inspect.rs`**: Validates JSON-RPC 2.0 communication, hex parsing, and configuration secret redaction.
- **`tests/test_backup.rs`**: Tests backup discovery, secp256k1 key derivation, and deterministic `manifest.json` generation.
- **`tests/test_drill.rs`**: Proves sandbox isolation, P2P network blocking, and handles the `0o400` read-only key permission bug.
- **`tests/test_negative.rs`**: Verifies failure handling for corrupted RocksDB databases, missing keys, identity mismatches, and confirms **zero secrets** in manifest JSON.

---

## Grant Roadmap & Future Milestones

| Milestone | Status | Description |
| :--- | :---: | :--- |
| **Milestone 1: Core Safeguard & Evidence** | **Completed** | `inspect`, `backup`, isolated `drill`, `manifest.json`, and official FNN v0.9.x grant evidence suite. |
| **Milestone 2: Pre-Upgrade Qualification** | *Planned* | `fnn-safeguard qualify --target <bin|image>` to test database migrations and node booting before live upgrades. |
| **Milestone 3: Encrypted Off-Host Replication** | *Planned* | Encrypted backup distribution using `age` encryption with adapters for AWS S3, Cloudflare R2, and rsync. |
| **Milestone 4: Daemon & Alerting** | *Planned* | Background service with automated cron schedules, Prometheus metrics, and alerting. |

---

## License

Dual-licensed under either:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

# FNN Safeguard

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![Fiber Compatibility](https://img.shields.io/badge/Fiber%20Node-v0.9.0%2B-emerald.svg)](https://github.com/nervosnetwork/fiber)
[![CI Status](https://github.com/intelliDean/fnn_safeguard/actions/workflows/ci.yml/badge.svg)](https://github.com/intelliDean/fnn_safeguard/actions/workflows/ci.yml)

> **Verified Recovery Points, Isolated Disaster Drills, and Pre-Upgrade Qualification for Nervos Fiber Network Nodes (FNN).**

FNN Safeguard is a self-hosted operator tool designed to verify backups and test disaster recovery procedures for Fiber Network Nodes on Nervos CKB. It independently validates backup completeness, generates Checksummed Recovery Manifests, verifies identity key derivation, and executes end-to-end restore drills against the official `fnn` binary in an isolated sandbox with blocked P2P egress verified via active network probes.

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
- [Verified Grant Evidence Suites](#verified-grant-evidence-suites)
  - [1. Primary Live Testnet Run (`evidence/live-fnn-v0.9.0-testnet`)](#1-primary-live-testnet-run-evidencelive-fnn-v090-testnet)
  - [2. Second Live Testnet Run (`evidence/live-fnn-v0.9.0-testnet-node2`)](#2-second-live-testnet-run-evidencelive-fnn-v090-testnet-node2)
  - [3. Sample Fixture Reference (`evidence/sample-fixture`)](#3-sample-fixture-reference-evidencesample-fixture)
- [Checksummed Recovery Manifest Specification](#checksummed-recovery-manifest-specification)
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
   3. MANIFEST      --> Produce deterministic Checksummed Recovery Manifest (0 secrets)
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
- **Evidence-Grade Docker Isolation with Verified Egress Probe**: When `--docker` is passed, drills run inside a Docker container with `--network none`. An active outbound network probe (`bash -c 'exec 3<>/dev/tcp/8.8.8.8/80'`) is executed and proven to fail (`Network is unreachable`, exit code 1) before database restoration proceeds.
- **Checksummed Recovery Manifests & Secret Sanitization**: Node configuration files (`config.yml`) are parsed line-by-line; sensitive credentials, passwords, and Biscuit tokens are masked with `[REDACTED]` prior to SHA-256 hashing.
- **Automatic Permission Manager**: Resolves the Fiber v0.9.0 read-only file mode issue by elevating to `0o600` during restore staging and locking down to `0o400` once restored.
- **Fail-Closed Verification Gating**: Safeguard never reports `VERIFIED` without:
  1. Complete backup structure (database, keys, non-empty files).
  2. Matching Checksummed Recovery Manifest (`PASS`).
  3. Official `fnn --restore` exiting with code 0.
  4. Official `fnn --check-validate` confirming database validity (`db validate success`).
  5. Exact public key match between source node and restored identity.
  6. Proven network isolation (failed outbound egress probe in Docker mode, loopback-only policy in process mode).
  7. Automated secret scanning reporting 0 detected secrets across all artifacts.

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
│   ├── manifest.rs         # Checksummed RecoveryManifest & verification
│   ├── reporter.rs         # Terminal formatting & JSON outputs
│   └── validator.rs        # Backup directory structural integrity checks
├── isolation/              # Sandboxed execution environments
│   ├── mod.rs
│   ├── docker.rs           # Docker container drill with `--network none` and egress probe
│   └── process.rs          # Process isolation executing native `fnn`
└── rpc/                    # FNN JSON-RPC 2.0 client
    ├── client.rs           # Strongly-typed HTTP client with auto-pagination
    └── types.rs            # FNN v0.9.x data models & hex parsing
```

---

## Quickstart

### Prerequisites
- **Rust 1.85+** (Rust 2024 edition required)
- Official clean `fnn` binary (`Fiber v0.9.0+`) or Docker for container drills
- Official release archive digest: `ab8591065d64474735b4812cff9131869caed9b26179470def84a9c98cdd4432`
- Extracted official `fnn` binary digest: `9c71faea17fa605cf0f1c5a3574bd91f408971c8142d82d0d0249ee082dee1b5`

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
Validates a native FNN backup, verifies cryptographic keys, and generates an integrity-checked `manifest.json`:

```bash
# Validate existing latest backup in directory (structural check)
fnn-safeguard backup --node-dir /var/lib/fiber

# Trigger immediate backup via RPC, wait for stabilization, and qualify against live node state
fnn-safeguard backup --trigger --rpc-url http://127.0.0.1:8227 --node-dir /var/lib/fiber
```

When run against a live node, the backup report is marked `qualification: "LIVE_NODE_QUALIFIED"`. When run offline without RPC, it is marked `qualification: "STRUCTURAL_ONLY"` with `network: "UNKNOWN"`.

### 3. Sandboxed Disaster Recovery Drill (`drill`)
Executes an end-to-end recovery test inside an isolated environment with network egress disabled, running the official `fnn --restore` and `fnn --check-validate`:

```bash
# Docker isolated container drill (evidence-grade with egress probe)
fnn-safeguard drill \
  --docker \
  --backup /path/to/backup \
  --evidence-dir evidence/live-fnn-v0.9.0-testnet

# Native process sandbox drill
fnn-safeguard drill \
  --backup /path/to/backup \
  --fnn-bin bin/fnn
```

---

## Verified Grant Evidence Suites

The repository contains three complete, machine-readable evidence suites:

### 1. Primary Live Testnet Run (`evidence/live-fnn-v0.9.0-testnet`)
Generated against a live testnet node containing **1 ChannelReady channel** and **1 completed payment**, restored via Docker `--network none` with a verified failed egress probe.

| Evidence File | Description |
| :--- | :--- |
| [`environment.json`](evidence/live-fnn-v0.9.0-testnet/environment.json) | Host OS, kernel, clean official FNN v0.9.0 binary digest, archive digest, and Docker runtime. |
| [`fnn-binary.sha256`](evidence/live-fnn-v0.9.0-testnet/fnn-binary.sha256) | SHA-256 checksum matching official release binary (`9c71faea...`). |
| [`source-inspect.json`](evidence/live-fnn-v0.9.0-testnet/source-inspect.json) | Live source node state with channel and payment counts. |
| [`backup-verification.json`](evidence/live-fnn-v0.9.0-testnet/backup-verification.json) | Structural integrity check and key derivation results. |
| [`manifest.json`](evidence/live-fnn-v0.9.0-testnet/manifest.json) | Deterministic Checksummed Recovery Manifest with live inventory counts. |
| [`manifest-verification.json`](evidence/live-fnn-v0.9.0-testnet/manifest-verification.json) | Independent verification recomputing all file hashes and bundle checksum. |
| [`restore-output.log`](evidence/live-fnn-v0.9.0-testnet/restore-output.log) | Complete stdout/stderr logs from `fnn --restore`. |
| [`check-validate-output.log`](evidence/live-fnn-v0.9.0-testnet/check-validate-output.log) | Logs from `fnn --check-validate` confirming database validity (`db validate success`). |
| [`restored-inspect.json`](evidence/live-fnn-v0.9.0-testnet/restored-inspect.json) | Restored node state and identity verification. |
| [`inventory-diff.json`](evidence/live-fnn-v0.9.0-testnet/inventory-diff.json) | Independent inventory comparison with honest `SOURCE_RECORDED_RESTORE_UNVERIFIED` status. |
| [`network-isolation-test.json`](evidence/live-fnn-v0.9.0-testnet/network-isolation-test.json) | Container `--network none` proof with failed egress probe (`exit_code: 1`, `Network is unreachable`). |
| [`secret-scan.json`](evidence/live-fnn-v0.9.0-testnet/secret-scan.json) | Automated scan confirming zero private keys, secret keys, or tokens leaked. |
| [`final-report.json`](evidence/live-fnn-v0.9.0-testnet/final-report.json) | Unified summary report with fail-closed `VERIFIED` status. |

### 2. Second Live Testnet Run (`evidence/live-fnn-v0.9.0-testnet-node2`)
Demonstrates repeatability across varied node state with **2 ChannelReady channels** and **3 completed payments** in [`evidence/live-fnn-v0.9.0-testnet-node2/`](evidence/live-fnn-v0.9.0-testnet-node2/).

### 3. Sample Fixture Reference (`evidence/sample-fixture`)
Reference evidence generated from static test fixtures in [`evidence/sample-fixture/`](evidence/sample-fixture/).

---

## Checksummed Recovery Manifest Specification

Every validated backup includes an integrity-checked `manifest.json` recording cryptographic proofs of completeness without disclosing secrets:

```json
{
  "format_version": 1,
  "node_public_key": "02297d34b5d228f17e374f25d4aab4c8afb5bb557b275e938b1d2c9671ff39ccd3",
  "network": "testnet",
  "fnn_version": "v0.9.0",
  "fnn_commit": "e6cb7ac",
  "created_at": "2026-09-10T20:09:05Z",
  "database_type": "rocksdb",
  "database_present": true,
  "fiber_key_present": true,
  "ckb_key_present": true,
  "config_checksum": "UNKNOWN",
  "bundle_checksum": "sha256:13206a928c0968bed0cedb702cc516dd1289be42b9a62e4984232111f702bf8b",
  "channel_count": 1,
  "payment_count": 1,
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
cargo test --all --verbose

# Run strict linting with zero warnings allowed
cargo clippy --all-targets --all-features -- -D warnings

# Check code formatting (Rust 2024 edition)
cargo fmt --all -- --check
```

### Test Coverage Highlights
- **`tests/test_inspect.rs`**: Validates JSON-RPC 2.0 communication, hex string parsing, paginated payments, and configuration secret redaction.
- **`tests/test_backup.rs`**: Tests backup discovery, secp256k1 key derivation, and deterministic `manifest.json` generation.
- **`tests/test_drill.rs`**: Proves sandbox isolation, P2P network blocking, and handles the `0o400` read-only key permission bug.
- **`tests/test_negative.rs`**: Verifies failure handling for corrupted RocksDB databases, missing keys, identity mismatches, and confirms **zero secrets** in manifest JSON.

---

## Grant Roadmap & Future Milestones

| Milestone | Status | Description |
| :--- | :---: | :--- |
| **Milestone 1: Core Safeguard & Evidence** | **Completed** | `inspect`, `backup`, isolated `drill`, `manifest.json`, and official FNN v0.9.0 grant evidence suite. |
| **Milestone 2: Pre-Upgrade Qualification** | *Planned* | `fnn-safeguard qualify --target <bin|image>` to test database migrations and node booting before live upgrades. |
| **Milestone 3: Encrypted Off-Host Replication** | *Planned* | Encrypted backup distribution using `age` encryption with adapters for AWS S3, Cloudflare R2, and rsync. |
| **Milestone 4: Daemon & Alerting** | *Planned* | Background service with automated cron schedules, Prometheus metrics, and alerting. |

---

## License

Dual-licensed under either:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

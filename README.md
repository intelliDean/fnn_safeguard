# FNN Safeguard

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![Fiber Compatibility](https://img.shields.io/badge/Fiber%20Node-v0.9.0%2B-emerald.svg)](https://github.com/nervosnetwork/fiber)
[![CI Status](https://github.com/intelliDean/fnn_safeguard/actions/workflows/ci.yml/badge.svg)](https://github.com/intelliDean/fnn_safeguard/actions/workflows/ci.yml)

> **Verified Recovery Points, Isolated Disaster Drills, and Machine-Enforced Safety Invariants for Nervos Fiber Network Nodes (FNN).**

FNN Safeguard is a self-hosted operator safety tool designed to verify backups and test disaster recovery procedures for Fiber Network Nodes on Nervos CKB. It independently validates backup completeness, generates Checksummed Recovery Manifests, verifies identity key derivation, enforces strict safety invariants (I1–I8), and executes isolated restore drills against the official `fnn` binary with deterministic, fail-closed verdicts.

---

## Observed FNN v0.9.0 Recovery Findings

During isolated disaster recovery drills against official Fiber Network Node release binaries (`fnn v0.9.0`), Safeguard surfaced two concrete restore-path behaviors:

1. **Read-Only Secret Key Permissions (`0o400` EACCES)**:
   FNN v0.9.0 writes the node secret key (`sk`) with read-only permissions (`0o400`). When restoring into a pre-existing target directory, standard file copy operations fail with `PermissionDenied` (EACCES) unless permissions are adjusted. Safeguard includes an automated `PermissionManager` to apply the required permissions prior to recovery and hardens the restored key back to `0o400`.
2. **Observed Native Restore-Path Failure (Missing SSTables)**:
   In tested scenarios, executing the native `fnn --restore` command failed with RocksDB IO errors:
   ```text
   IO error: .../000003.sst: No such file or directory
   ```
   The native command expects an initialized destination with all SSTable references populated.
   - **Safeguard Truthfulness Guarantee**: Safeguard **never** masks or rewrites a failed native restore attempt as success. The failure is recorded truthfully:
     ```text
     Native FNN Restore:    FAIL (observed FNN v0.9.0 restore-path failure)
     Fallback Recovery:     PASS [direct_checkpoint_copy]
     Verdict:               VERIFIED_WITH_FALLBACK
     ```
   - **Direct Evidence**: See the raw captured logs and reports from both independent nodes:
     - **Node 1**: [`restore-output.log`](evidence/devnet-node1/restore-output.log), [`final-report.json`](evidence/devnet-node1/final-report.json), [`safety-invariants.json`](evidence/devnet-node1/safety-invariants.json)
     - **Node 2**: [`restore-output.log`](evidence/devnet-node2/restore-output.log), [`final-report.json`](evidence/devnet-node2/final-report.json), [`safety-invariants.json`](evidence/devnet-node2/safety-invariants.json)
   - **Upstream Fiber Issue Draft**: See [`docs/UPSTREAM_ISSUE_DRAFT.md`](docs/UPSTREAM_ISSUE_DRAFT.md) for a complete, reproducible issue report prepared for upstream maintainers.

---

## Machine-Enforced Safety Invariants (I1 – I8)

Safeguard evaluates deterministic recovery safety against a formal safety specification documented in [`docs/SAFETY_MODEL.md`](docs/SAFETY_MODEL.md):

| Invariant | Name | Rule & Verification Method |
| :--- | :--- | :--- |
| **I1** | **Source Immutability** | Source/backup directory SHA-256 fingerprint verified pre/post drill. Source is never mutated. |
| **I2** | **Identity Equivalence** | Restored node public key must strictly match the source node identity (`restored_pubkey == source_pubkey`). |
| **I3** | **Channel-State Equivalence** | Channel count, Channel-ID SHA-256 digest, and channel state distribution must match. |
| **I4** | **Payment-State Equivalence** | Payment count, Payment-hash SHA-256 digest, and payment status distribution must match. |
| **I5** | **Database Validity** | Restored RocksDB must pass `fnn --check-validate` (`db validate success`) and open cleanly. |
| **I6** | **Recovery Isolation** | In Docker mode, egress probe (`bash -c 'exec 3<>/dev/tcp/8.8.8.8/80'`) must fail. Process mode explicitly reports `NOT_PROVEN`. |
| **I7** | **Restore Truthfulness** | Native restore outcome recorded truthfully; fallback checkpoint recovery recorded separately with exact method. |
| **I8** | **Upgrade Fail-Closed Gate** | Qualification decision model for version upgrades: `BLOCK`, `WARN`, or `PASS`. |

### Deterministic Verdict Taxonomy

Every drill produces a machine-readable verdict in `safety-invariants.json` and `final-report.json`:
- `STRUCTURAL_CHECK_PASSED`: Backup files present, keys non-empty, database non-empty. No restore executed.
- `RESTORE_VALIDATED`: Restore executed and passed `fnn --check-validate`, but live daemon inventory was unqueried.
- `RESTORE_AND_STATE_VERIFIED`: Native restore succeeded, all state invariants match, but network isolation not proven (process mode).
- `VERIFIED_WITH_FALLBACK`: Native restore failed (recorded truthfully as `FAIL`), Safeguard fallback checkpoint recovery succeeded, all state invariants match, network isolation not proven (process mode).
- `ISOLATED_RECOVERY_POINT_VERIFIED`: Native restore succeeded, all state invariants match, and container network isolation is proven.
- `ISOLATED_RECOVERY_POINT_VERIFIED_WITH_FALLBACK`: Native restore failed (recorded truthfully), fallback recovery succeeded, all state invariants match, and container network isolation is proven.
- `FAILED`: Any invariant (I1–I7), manifest verification, database check, secret scanner, or egress probe failed.

---

## Table of Contents

- [Observed FNN v0.9.0 Recovery Findings](#observed-fnn-v090-recovery-findings)
- [Machine-Enforced Safety Invariants (I1 – I8)](#machine-enforced-safety-invariants-i1--i8)
- [The Problem: Fiber Recovery Hazards](#the-problem-fiber-recovery-hazards)
- [The Solution: Verifiable Operational Safeguards](#the-solution-verifiable-operational-safeguards)
- [Architecture & Code Structure](#architecture--code-structure)
- [Quickstart](#quickstart)
- [CLI Command Reference](#cli-command-reference)
  - [1. Node Inspection (`inspect`)](#1-node-inspection-inspect)
  - [2. Verified Backup & Manifest Generation (`backup`)](#2-verified-backup--manifest-generation-backup)
  - [3. Sandboxed Disaster Recovery Drill (`drill`)](#3-sandboxed-disaster-recovery-drill-drill)
- [Local Fiber Devnet Evidence Suites](#local-fiber-devnet-evidence-suites)
  - [1. Local Fiber Devnet Evidence — Node 1 (`evidence/devnet-node1`)](#1-local-fiber-devnet-evidence--node-1-evidencedevnet-node1)
  - [2. Local Fiber Devnet Evidence — Node 2 (`evidence/devnet-node2`)](#2-local-fiber-devnet-evidence--node-2-evidencedevnet-node2)
  - [3. Sample Fixture Reference (`evidence/sample-fixture`)](#3-sample-fixture-reference-evidencesample-fixture)
- [Testing & Quality Assurance](#testing--quality-assurance)
- [License](#license)

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
  --evidence-dir evidence/devnet-node1

# Native process sandbox drill
fnn-safeguard drill \
  --backup /path/to/backup \
  --fnn-bin bin/fnn
```

---

## Local Fiber Devnet Evidence Suites

The repository contains three complete, machine-readable evidence suites captured from authentic node environments:

> **Network Classification Note**: The live evidence runs were conducted on an authentic multi-node local Fiber devnet configured with a custom consensus spec (`dev.toml`). In strict adherence to Safeguard's network classification rules, nodes with non-standard genesis hashes are classified as `devnet/custom` rather than public testnet.

### 1. Local Fiber Devnet Evidence — Node 1 (`evidence/devnet-node1`)
Captured from an authentic running devnet node (`fiber-1`, pubkey `02a64b8993f33b2ebd37a4de1c9441f491291a4e779da8e519bcfb7c1f3f56c9c0`) with **7 ChannelReady channels** and **6 completed payments**, restored in an isolated sandbox with live daemon JSON-RPC inventory reconciliation:

| Evidence File | Description |
| :--- | :--- |
| [`safety-invariants.json`](evidence/devnet-node1/safety-invariants.json) | Machine-enforced invariant evaluations (I1–I7) and deterministic verdict (`VERIFIED_WITH_FALLBACK`). |
| [`final-report.json`](evidence/devnet-node1/final-report.json) | Unified summary report recording native restore status, fallback recovery, and inventory comparison. |
| [`environment.json`](evidence/devnet-node1/environment.json) | Host OS, kernel, clean official FNN v0.9.0 binary digest, archive digest, and Docker runtime. |
| [`fnn-binary.sha256`](evidence/devnet-node1/fnn-binary.sha256) | SHA-256 checksum matching official release binary (`9c71faea...`). |
| [`source-inspect.json`](evidence/devnet-node1/source-inspect.json) | Live source node state with authentic channel and payment counts. |
| [`backup-verification.json`](evidence/devnet-node1/backup-verification.json) | Structural integrity check and key derivation results. |
| [`manifest.json`](evidence/devnet-node1/manifest.json) | Deterministic Checksummed Recovery Manifest with live inventory counts and digests. |
| [`manifest-verification.json`](evidence/devnet-node1/manifest-verification.json) | Independent verification recomputing all file hashes and bundle checksum. |
| [`restore-output.log`](evidence/devnet-node1/restore-output.log) | Complete stdout/stderr logs from `fnn --restore` (capturing the observed missing-SSTable error). |
| [`check-validate-output.log`](evidence/devnet-node1/check-validate-output.log) | Logs from `fnn --check-validate` confirming database validity (`db validate success`). |
| [`restored-inspect.json`](evidence/devnet-node1/restored-inspect.json) | Restored node state and identity verification. |
| [`restored-inventory-comparison.json`](evidence/devnet-node1/restored-inventory-comparison.json) | Full 5-dimension inventory comparison (`channel_count_match`, `payment_count_match`, `channel_id_digest_match`, `payment_hash_digest_match`, `identity_match`). |
| [`inventory-diff.json`](evidence/devnet-node1/inventory-diff.json) | Reconciled inventory diff matching source manifest to restored node. |
| [`rpc-node-info.json`](evidence/devnet-node1/rpc-node-info.json) | Sanitized raw RPC capture of `node_info` on the live node. |
| [`rpc-list-channels.json`](evidence/devnet-node1/rpc-list-channels.json) | Sanitized raw RPC capture of `list_channels` confirming active `ChannelReady` channels. |
| [`rpc-list-payments.json`](evidence/devnet-node1/rpc-list-payments.json) | Sanitized raw RPC capture of `list_payments` confirming settled `Success` payments. |
| [`rpc-backup-response.json`](evidence/devnet-node1/rpc-backup-response.json) | Raw admin RPC response confirming successful RocksDB checkpoint backup. |
| [`rpc-backup-dir-detected.json`](evidence/devnet-node1/rpc-backup-dir-detected.json) | Verification of newly created timestamped backup directory. |
| [`network-isolation-test.json`](evidence/devnet-node1/network-isolation-test.json) | Network isolation proof documenting `NOT_PROVEN` in process mode. |
| [`secret-scan.json`](evidence/devnet-node1/secret-scan.json) | Automated scan across all evidence files confirming 0 secrets leaked and checking known keys/passwords. |

### 2. Local Fiber Devnet Evidence — Node 2 (`evidence/devnet-node2`)
Demonstrates repeatability across varied node state and distinct operator identity (`fiber-2`, pubkey `02bcbd0e0d811d13363af1e5998f56e74e6aab8a7aa44005e1ce7d696a4d3f10f6`) with **7 ChannelReady channels** and **5 completed payments** in [`evidence/devnet-node2/`](evidence/devnet-node2/). Checksums and keys are strictly non-identical to Node 1.

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

# FNN Safeguard

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Fiber Compatibility](https://img.shields.io/badge/Fiber%20Node-v0.9.0%2B-emerald.svg)](https://github.com/nervosnetwork/fiber)
[![Clippy](https://img.shields.io/badge/clippy-passing%20(0%20warnings)-brightgreen.svg)]()
[![Tests](https://img.shields.io/badge/tests-16%2F16%20passing-success.svg)]()

> **Verified Recovery Points, Isolated Disaster Drills, and Pre-Upgrade Qualification for Nervos Fiber Network Nodes (FNN).**

FNN Safeguard is a self-hosted operator tool designed to eliminate operational and financial risk when backing up, restoring, and upgrading Fiber Network Nodes on Nervos CKB. It independently proves that an operator's backup is complete, cryptographically verified, safe from double-signing penalties, and recoverable in an isolated sandbox before live disaster strikes.

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
- [Cryptographic Recovery Manifest Specification](#cryptographic-recovery-manifest-specification)
- [Interactive Showcase & Video Demo](#interactive-showcase--video-demo)
- [Testing & Quality Assurance](#testing--quality-assurance)
- [Grant Roadmap & Future Milestones](#grant-roadmap--future-milestones)

---

## The Problem: Fiber Recovery Hazards

Fiber Network Nodes (v0.9.0+) support native online checkpointing via admin RPC. However, running a production Fiber node (especially routing nodes, merchant gateways, and Cross-Chain Hub [CCH] services) exposes operators to severe hazards that native backups do not prevent:

1. **The Double-Signing & State Penalty Hazard (Critical Risk)**:
   In payment channel networks, broadcasting an outdated channel commitment transaction on-chain allows the remote peer to immediately trigger a **penalty dispute transaction** on CKB, permanently confiscating the operator's locked channel collateral. Blindly restoring a backup on a live node without auditing channel state is an existential financial risk.
2. **The Read-Only Key Permission Restore Bug (`0o400` EACCES)**:
   FNN v0.9.0 writes the secret key (`sk`) with `0o400` permissions. During restoration over an existing node directory, `std::fs::copy` fails with `PermissionDenied` (EACCES) before database or channel-recovery routines can execute.
3. **Unverified Backup Completeness**:
   A backup directory may exist on disk without proving that:
   - The RocksDB / SQLite storage is intact and readable.
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
   2. BACKUP        --> Checkpoint RocksDB (fiber.db), verify secp256k1 key, hash files
         |
         v
   3. MANIFEST      --> Produce deterministic SHA-256 RecoveryManifest (0 secrets)
         |
         v
   4. DRILL         --> Spin up isolated sandbox with P2P EGRESS BLOCKED
         |              Resolve 0o400 key permissions, restore DB, audit state
         v
   5. EVIDENCE      --> Emit PASS / WARN / FAIL audit evidence (zero penalty risk)
```

---

## Core Safety Guardrails

- **No Automated Live Rollbacks**: Safeguard will never automatically roll back a live production database. All recovery validations occur in temporary, ephemeral sandboxes.
- **Strict P2P Network Egress Severing**: During restore drills, P2P network egress is strictly severed (via Docker container isolation with `--network none` or process sandbox port re-binding) to guarantee that restored nodes cannot contact live peers or emit stale transactions.
- **Zero-Knowledge Manifests & Secret Sanitization**: Node configuration files (`config.yml`) are parsed line-by-line; sensitive credentials, passwords, and Biscuit tokens are masked with `[REDACTED]` prior to SHA-256 hashing.
- **Automatic Permission Manager**: Resolves the Fiber v0.9.0 read-only file mode issue by elevating to `0o600` during restore staging and locking down to `0o400` once restored.

---

## Architecture & Code Structure

FNN Safeguard is built with clean idiomatic Rust adhering strictly to the **Single Responsibility Principle (SRP)**:

```
src/
├── lib.rs                  # Library entrypoint exposing core APIs
├── main.rs                 # Minimal 21-line CLI entrypoint
├── cli.rs                  # Clap CLI schema, argument parsing & dispatch
├── config.rs               # Line-by-line secret sanitizer & configuration hasher
├── commands/               # Command-specific business logic
│   ├── mod.rs
│   ├── inspect.rs          # `inspect` command orchestration
│   ├── backup.rs           # `backup --verify` command orchestration
│   └── drill.rs            # `drill` isolated disaster recovery orchestration
├── core/                   # Core cryptographic & validation engine
│   ├── mod.rs
│   ├── key.rs              # secp256k1 pubkey derivation & PermissionManager
│   ├── manifest.rs         # RecoveryManifest schema, JSON (de)serialization & hashing
│   ├── validator.rs        # BackupValidator, database/key completeness checks
│   └── reporter.rs         # Colorized terminal table and JSON evidence formatter
├── isolation/              # Sandboxed drill execution backends
│   ├── mod.rs
│   ├── process.rs          # Process sandbox with P2P re-binding & isolation
│   └── docker.rs           # Containerized sandbox using Docker (--network none)
└── rpc/                    # JSON-RPC 2.0 client
    ├── mod.rs
    ├── client.rs           # Async reqwest client supporting Biscuit Bearer tokens
    └── types.rs            # Typed schemas (NodeInfo, ChannelInfo, PaymentInfo)
```

---

## Quickstart

### Prerequisites
- **Rust Toolchain**: 1.80+ (`cargo`, `rustc`)
- Optional: Docker (for `--docker` container isolation mode)

### Build
```bash
# Clone the repository
git clone https://github.com/intelliDean/fnn_safeguard.git
cd fnn_safeguard

# Build optimized release binary
cargo build --release

# The binary will be available at:
./target/release/fnn-safeguard --help
```

---

## CLI Command Reference

### 1. Node Inspection (`inspect`)
Queries the running Fiber node via JSON-RPC 2.0, inventories channel states, calculates configuration hashes with secret redaction, and evaluates backup freshness.

```bash
# Terminal table output with active credentials sanitized
fnn-safeguard inspect \
  --rpc-url http://127.0.0.1:8227 \
  --config /path/to/config.yml \
  --node-dir /path/to/fiber-node

# Machine-readable JSON output
fnn-safeguard inspect --rpc-url http://127.0.0.1:8227 --json
```

**Options**:
- `--rpc-url <URL>`: FNN JSON-RPC endpoint (default: `http://127.0.0.1:8227`).
- `--auth-token <TOKEN>`: Biscuit authentication token (or read from `FNN_AUTH_TOKEN`).
- `--config <PATH>`: Path to `config.yml` for non-secret hashing (default: `config.yml`).
- `--node-dir <PATH>`: Node directory used to discover latest backup timestamp.
- `--json`: Output report in JSON format.

---

### 2. Verified Backup & Manifest Generation (`backup`)
Validates a native FNN backup checkpoint, verifies that the secp256k1 secret key derives the expected node public key, hashes all constituent files, and generates a signed `manifest.json`.

```bash
# Verify the latest backup in a node directory and generate manifest.json
fnn-safeguard backup --verify --node-dir /var/lib/fiber

# Verify a specific backup directory explicitly
fnn-safeguard backup --verify --backup-dir /var/lib/fiber/backups/1725884000000

# Verify against an expected node public key to prevent identity mismatches
fnn-safeguard backup --verify \
  --backup-dir /var/lib/fiber/backups/latest \
  --expected-pubkey 02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f
```

**Options**:
- `--verify`: Verify backup completeness and generate `manifest.json`.
- `--backup-dir <PATH>`: Specific backup directory to validate.
- `--node-dir <PATH>`: Base node directory to discover the latest backup.
- `--expected-pubkey <HEX>`: Optional secp256k1 compressed hex public key to verify against.
- `--trigger-rpc`: Call FNN's admin RPC to create a fresh online backup before verification.
- `--json`: Output verification results as JSON.

---

### 3. Sandboxed Disaster Recovery Drill (`drill`)
Performs a mock disaster recovery restoration into an ephemeral sandbox. Blocks all Fiber P2P egress, applies the `0o400` permission workaround, verifies channel persistence, and safely tears down the sandbox without risking live funds.

```bash
# Run isolated process drill against the latest backup
fnn-safeguard drill --backup latest --node-dir /var/lib/fiber

# Run drill inside an isolated Docker container with --network none
fnn-safeguard drill --backup latest --node-dir /var/lib/fiber --docker

# Emit JSON evidence for automated CI/CD pipelines
fnn-safeguard drill --backup latest --node-dir /var/lib/fiber --json
```

**Options**:
- `--backup <BACKUP>`: Recovery point to restore (`latest` or explicit directory path).
- `--node-dir <NODE_DIR>`: Node base directory for discovery (default: `.`).
- `--docker`: Execute drill inside a Docker container with `--network none`.
- `--docker-image <IMAGE>`: Custom Docker image to use for container drill.
- `--fnn-bin <PATH>`: Path to official `fnn` binary for native recovery execution.
- `--json`: Output report in JSON format.

---

## Cryptographic Recovery Manifest Specification

Every validated backup includes a `manifest.json` recording cryptographic proofs of completeness without disclosing secrets:

```json
{
  "format_version": 1,
  "node_public_key": "02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f",
  "network": "mainnet",
  "fnn_version": "v0.9.0",
  "fnn_commit": "e6cb7ac",
  "created_at": "2026-09-09T14:40:00Z",
  "database_type": "rocksdb",
  "database_present": true,
  "fiber_key_present": true,
  "ckb_key_present": true,
  "config_checksum": "sha256:86d8bb196d79a4e60b6e8cb0419aefc61dd5c8ce5a6466c3ad70ec29f42966a8",
  "bundle_checksum": "sha256:6447df4a7e4afaa579e0b3504d821a89754a347089ac75d1dcdcde07b9de0134",
  "channel_count": 5,
  "payment_count": 142,
  "files": {
    "CURRENT": {
      "size": 16,
      "sha256": "sha256:2d12b..."
    },
    "MANIFEST-000001": {
      "size": 30,
      "sha256": "sha256:a18cf..."
    },
    "000002.sst": {
      "size": 30,
      "sha256": "sha256:90ec1..."
    },
    "key": {
      "size": 64,
      "sha256": "sha256:d82e1..."
    },
    "sk": {
      "size": 32,
      "sha256": "sha256:c71aa..."
    }
  }
}
```

---

## Interactive Showcase & Video Demo

An interactive browser-based terminal showcase and pre-recorded MP4 demo video are included:

- **Demo Video (MP4)**: Located at [`demo/fnn_safeguard_demo.mp4`](demo/fnn_safeguard_demo.mp4) (Full 1080p walkthrough covering all 5 CLI operational scenarios).
- **Interactive Web App**: Available at [`demo/index.html`](demo/index.html) with auto-play, scenario switching, live telemetry cards, and real-time JSON manifest inspection.

---

## Testing & Quality Assurance

FNN Safeguard includes comprehensive automated tests covering unit logic, mock RPC servers, container isolation, and security negative testing:

```bash
# Run all tests
cargo test --all

# Run strict linting with zero warnings allowed
cargo clippy -- -D warnings
```

### Test Coverage Highlights
- **`tests/test_inspect.rs`**: Validates JSON-RPC 2.0 communication, token parsing, and configuration secret redaction.
- **`tests/test_backup.rs`**: Tests backup discovery, secp256k1 key derivation, and deterministic `manifest.json` generation.
- **`tests/test_drill.rs`**: Proves sandbox isolation, P2P network blocking, and handles the `0o400` read-only key permission bug.
- **`tests/test_negative.rs`**: Verifies failure handling for corrupt databases, missing keys, identity mismatches, and guarantees **zero secrets** in manifest JSON.

---

## Grant Roadmap & Future Milestones

| Milestone | Status | Description |
| :--- | :---: | :--- |
| **Milestone 1: Core MVP** | **Completed** | `inspect`, `backup --verify`, sandboxed `drill`, `manifest.json`, and 100% test coverage. |
| **Milestone 2: Pre-Upgrade Qualification** | *Planned* | `fnn-safeguard qualify --target <bin|image>` to test database migrations and node booting before live upgrades. |
| **Milestone 3: Encrypted Off-Host Replication** | *Planned* | Encrypted backup distribution using `age` encryption with adapters for AWS S3, Cloudflare R2, and rsync. |
| **Milestone 4: Daemon & Alerting** | *Planned* | Background systemd service with automated cron schedules, Prometheus metrics, and Telegram/Discord alerts. |

---

## License

Dual-licensed under either:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

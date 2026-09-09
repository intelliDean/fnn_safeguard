# FNN Safeguard

**Verified Recovery Points and Pre-Upgrade Qualification for Fiber Network Nodes**

FNN Safeguard is an operator tool that verifies Fiber Network Node backups, tests restores inside isolated environments, and qualifies target FNN versions against cloned state before live upgrades.

---

## Capabilities

- **Node Inspection (`fnn-safeguard inspect`)**: Collects non-secret inventories (node identity, channel counts, payment counts, backup age) and hashes active configuration files with automatic secret redaction.
- **Verified Backup (`fnn-safeguard backup --verify`)**: Validates backup completeness (`db/` or `data.sqlite`, `key`, `sk`), verifies secp256k1 public key derivation, and creates a cryptographic `manifest.json`.
- **Isolated Restore Drill (`fnn-safeguard drill --backup latest`)**: Restores state in an ephemeral sandbox with **strict Fiber P2P egress blocking**, proactively resolves the documented `0o400` read-only key permission restore bug, and outputs PASS/WARN/FAIL evidence.

---

## Building & Testing

```bash
# Build the production CLI binary
cargo build --release

# Run the test suite (unit tests, integration tests, security & negative tests)
cargo test --all
```

---

## CLI Usage

### 1. Inspect Running Node
```bash
# Human-readable terminal output
./target/release/fnn-safeguard inspect --rpc-url http://127.0.0.1:8227

# JSON output
./target/release/fnn-safeguard inspect --json
```

### 2. Verify Backup & Generate Manifest
```bash
# Verify latest backup in node directory
./target/release/fnn-safeguard backup --verify --node-dir ./fiber-node

# Or verify a specific backup directory
./target/release/fnn-safeguard backup --verify --backup-dir ./fiber-node/backups/1725800000000
```

### 3. Isolated Restore Drill
```bash
# Run isolated drill with blocked Fiber P2P networking
./target/release/fnn-safeguard drill --backup latest --node-dir ./fiber-node

# Docker container isolation (--network none)
./target/release/fnn-safeguard drill --backup latest --docker
```

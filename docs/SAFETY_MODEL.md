# FNN Safeguard — Safety Model & Invariant Specification

This document formally specifies the assets protected, failure modes considered, safety invariants machine-enforced by FNN Safeguard, and explicit operational non-goals.

---

## 1. Assets Being Protected

FNN Safeguard protects the operational integrity and financial security of Fiber Network Node (FNN) operators by safeguarding the following critical assets:

1. **FNN Node Identity (`sk`)**:
   The secp256k1 private identity key. If corrupted or replaced with an incorrect key, the node loses its public identity, open channels become unrecognizable, and peer routing fails.
2. **Channel State (Commitment State)**:
   The latest agreed commitment transactions and HTLC/TLC state recorded in RocksDB. Restoring an obsolete channel state risks peer-triggered on-chain penalty transactions confiscating locked CKB collateral.
3. **Payment History and Invoices**:
   The database of incoming, outgoing, and routed payments, invoices, and payment preimages required for state accounting and auditability.
4. **Recovery-Point Integrity**:
   The structural and cryptographic consistency of the backup bundle (RocksDB checkpoint, CKB keystore, and Fiber identity key).
5. **Operator Secrets**:
   Sensitive credentials including `FIBER_SECRET_KEY_PASSWORD`, `rpc.auth_token`, Biscuit tokens, and raw private key material, which must never leak into operational manifests, audit logs, or shared evidence.
6. **Live Node State**:
   The active production node directory, runtime processes, and peer network connections, which must never be mutated or disrupted during backup qualification or disaster recovery drills.

---

## 2. Failure Model

FNN Safeguard explicitly detects, isolates, and fails closed against the following failure modes:

| Failure Mode | Impact | Safeguard Detection & Mitigation |
| :--- | :--- | :--- |
| **Incomplete Backup** | Missing database files, missing `sk`, or missing CKB `key`. | Pre-flight structural validation rejects backups missing any required file. |
| **Corrupted RocksDB Storage** | Truncated logs, corrupted SSTables, or missing manifests. | Tested via native `fnn --check-validate` inside an isolated sandbox. |
| **Missing Key Material** | Missing or 0-byte key files. | Cryptographic key parser verifies secp256k1 curve validity and key length. |
| **Wrong Node Identity** | Restored key derives a different public key than the source node. | Strict identity equivalence check (`restored_pubkey == source_pubkey`). |
| **Stale or Divergent Channel State** | Channel count or channel-ID digest differs between source and restored state. | Restored daemon queried via JSON-RPC; channel counts and sorted channel-ID SHA-256 digests must match. |
| **Stale or Divergent Payment State** | Payment count or payment-hash digest differs between source and restored state. | Restored daemon queried via JSON-RPC; payment counts and sorted payment-hash SHA-256 digests must match. |
| **Native Restore Failure** | `fnn --restore` fails (e.g. read-only `0o400` permission or missing SSTables). | Real native exit code and stderr recorded as `FAIL`; fallback checkpoint recovery executed and reported separately. |
| **Accidental Cloned-Node Network Access** | Cloned node connects to live Fiber peers, risking double-signing or penalties. | Docker `--network none` isolation enforced with active outbound egress probe; process mode defaults to `NOT_PROVEN`. |
| **Leaked Secrets in Artifacts** | Private keys, tokens, or passwords appearing in evidence logs or manifests. | Multi-representation secret scanner checks raw, hex, base64, and config tokens across all precursor evidence files. |
| **Recovery-Point Directory Mutation** | A disaster recovery drill inadvertently writes to or alters the backup directory. | Backup recovery-point directory fingerprinted before and after drill; any mutation triggers invariant failure. |
| **Target-Version Migration Failure** | Future FNN version fails to open or migrate cloned database. | Target binary evaluated against cloned state; migration failure blocks upgrade. |

---

## 3. Safety Invariants (I1 – I8)

The core verification engine enforces eight machine-checkable invariants:

### I1 — Recovery-Point Immutability
A recovery drill must never modify the backup/recovery-point directory.
- **Specification**: $\text{Digest}(\text{BackupDirectory})_{\text{before}} == \text{Digest}(\text{BackupDirectory})_{\text{after}}$.
- **Result**: `recovery_point_immutable = PASS | FAIL` (also reported as `source_state_immutable = PASS | FAIL`). Any modification immediately fails the drill.

### I2 — Identity Equivalence
The public key derived from the restored secret key must exactly match the source node public key.
- **Specification**: $\text{PubKey}(\text{Restored } sk) == \text{PubKey}(\text{Source } sk)$.
- **Result**: `identity_equivalence = PASS | FAIL`.

### I3 — Channel-State Equivalence
The restored node channel inventory must match the source node manifest across counts, channel IDs, channel-ID digest, and state distribution.
- **Specification**: $\text{Channels}(\text{Restored}) \equiv \text{Channels}(\text{Source})$.
- **Result**: `channel_state_equivalence = PASS | FAIL | NOT_AVAILABLE`.

### I4 — Payment-State Equivalence
The restored node payment inventory must match the source node manifest across counts, payment hashes, payment-hash digest, and status distribution.
- **Specification**: $\text{Payments}(\text{Restored}) \equiv \text{Payments}(\text{Source})$.
- **Result**: `payment_state_equivalence = PASS | FAIL | NOT_AVAILABLE`.

### I5 — Database Validity
The restored database must pass official FNN structural validation.
- **Specification**: `fnn --check-validate` exits with code 0 and reports `db validate success`.
- **Result**: `database_valid = PASS | FAIL`.

### I6 — Recovery Isolation
The restored cloned node must not be able to establish outbound connections to live Fiber peers or external endpoints during an evidence-grade drill.
- **Specification**: Active outbound probe (`bash -c 'exec 3<>/dev/tcp/8.8.8.8/80'`) inside the restore environment must fail (`Network is unreachable`, exit code $\ne 0$). Loopback binding alone does not prove egress isolation.
- **Result**: `network_isolation = PASS | FAIL | NOT_PROVEN`.

### I7 — Restore Truthfulness
Native FNN restore attempts and Safeguard fallback recovery procedures must always remain distinct, immutable facts in all reports.
- **Specification**: If native `fnn --restore` exits with non-zero code or error output, `native_restore` must permanently record `FAIL`. Fallback success must be separately recorded under `fallback_recovery`.
- **Result**: `restore_result_truthful = PASS | FAIL`. There is no code path permitted to overwrite a native restore failure into a success.

### I8 — Upgrade Fail-Closed Semantics
The pre-upgrade qualification engine must enforce fail-closed decision logic:
- Migration failure $\rightarrow$ `BLOCK`
- Startup failure $\rightarrow$ `BLOCK`
- Identity mismatch $\rightarrow$ `BLOCK`
- Channel inventory mismatch $\rightarrow$ `BLOCK`
- Payment inventory mismatch $\rightarrow$ `BLOCK`
- Database validation failure $\rightarrow$ `BLOCK`
- Documented non-fatal difference $\rightarrow$ `WARN`
- All required invariants pass $\rightarrow$ `PASS`

---

## 4. Explicit Non-Goals

To maintain clear operational boundaries and avoid introducing new hazards, FNN Safeguard explicitly excludes:

1. **No Automatic Production Rollback**:
   Safeguard will never automatically overwrite a live production node database with a historical backup. Because payment channel networks penalize broadcasting revoked states, rollback decisions require explicit operator authority.
2. **No Automatic Production Upgrades**:
   Safeguard tests target binaries in temporary clones, but never replaces production binaries or service definitions automatically.
3. **No Automatic Force-Closure**:
   Safeguard does not automatically broadcast unilateral commitment transactions on CKB.
4. **No Guarantee of Historic Channel Safety**:
   Safeguard proves that a backup is structurally sound and reproduces the snapshot state; it cannot guarantee that an obsolete historical state is safe to broadcast if subsequent channel updates occurred off-chain.
5. **No Universal Release Certification**:
   Qualifying a target FNN binary against an operator's cloned state certifies compatibility with that specific state, not universal protocol correctness.
6. **No Custody of Keys or Backups**:
   Safeguard is a self-hosted tool; it never holds custody of operator credentials, private keys, or backup storage.

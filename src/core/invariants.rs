use serde::{Deserialize, Serialize};

/// Explicit verdict taxonomy for recovery drill results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryVerdict {
    /// Offline or structural check passed only (database/keys present).
    StructuralCheckPassed,
    /// Restore executed and validated against check-validate only.
    RestoreValidated,
    /// Restore succeeded and state inventories match, but network isolation not proven.
    RestoreAndStateVerified,
    /// Native restore failed, fallback recovery succeeded, state matches, isolation not proven.
    VerifiedWithFallback,
    /// Native restore succeeded, all state invariants match, and network isolation is proven.
    IsolatedRecoveryPointVerified,
    /// Native restore failed, fallback succeeded, all state invariants match, and isolation is proven.
    IsolatedRecoveryPointVerifiedWithFallback,
    /// Any required identity, state, database, or isolation invariant failed.
    Failed,
}

impl std::fmt::Display for RecoveryVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StructuralCheckPassed => write!(f, "STRUCTURAL_CHECK_PASSED"),
            Self::RestoreValidated => write!(f, "RESTORE_VALIDATED"),
            Self::RestoreAndStateVerified => write!(f, "RESTORE_AND_STATE_VERIFIED"),
            Self::VerifiedWithFallback => write!(f, "VERIFIED_WITH_FALLBACK"),
            Self::IsolatedRecoveryPointVerified => write!(f, "ISOLATED_RECOVERY_POINT_VERIFIED"),
            Self::IsolatedRecoveryPointVerifiedWithFallback => {
                write!(f, "ISOLATED_RECOVERY_POINT_VERIFIED_WITH_FALLBACK")
            }
            Self::Failed => write!(f, "FAILED"),
        }
    }
}

/// Invariant outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InvariantStatus {
    Pass,
    Fail,
    NotProven,
    NotAvailable,
}

impl std::fmt::Display for InvariantStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail => write!(f, "FAIL"),
            Self::NotProven => write!(f, "NOT_PROVEN"),
            Self::NotAvailable => write!(f, "NOT_AVAILABLE"),
        }
    }
}

/// Machine-readable report of all machine-enforced safety invariants (I1 - I8).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyInvariantsReport {
    /// I1: Source immutability — live/source directory must never be modified by a drill.
    pub source_state_immutable: InvariantStatus,

    /// Backup structure validity — complete database, CKB key, Fiber key, non-empty.
    pub backup_structure_valid: InvariantStatus,

    /// Manifest integrity — hashes recomputed and matching.
    pub manifest_integrity: InvariantStatus,

    /// I7: Restore truthfulness (part A): Native restore outcome.
    pub native_restore: InvariantStatus,

    /// I7: Restore truthfulness (part B): Fallback recovery outcome.
    pub fallback_recovery: InvariantStatus,

    /// I5: Database validity — fnn --check-validate passed.
    pub database_valid: InvariantStatus,

    /// I2: Identity equivalence — restored_pubkey == source_pubkey.
    pub identity_equivalence: InvariantStatus,

    /// I3: Channel-state equivalence — counts, digests, and distributions match.
    pub channel_state_equivalence: InvariantStatus,

    /// I4: Payment-state equivalence — counts, digests, and distributions match.
    pub payment_state_equivalence: InvariantStatus,

    /// I6: Recovery isolation — clone cannot reach external network during isolated drill.
    pub network_isolation: InvariantStatus,

    /// Secret leakage scan — zero secrets in reports, logs, or evidence.
    pub secret_leakage: InvariantStatus,

    /// Final deterministic verdict.
    pub final_verdict: RecoveryVerdict,

    /// Human-readable explanation of verdict.
    pub verdict_reason: String,
}

impl SafetyInvariantsReport {
    /// Evaluates all machine-enforced safety invariants (I1 - I7) and produces
    /// a deterministic RecoveryVerdict.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate(
        source_immutable: bool,
        backup_valid: bool,
        manifest_valid: bool,
        native_restore_status: InvariantStatus,
        fallback_recovery_status: InvariantStatus,
        db_valid: bool,
        identity_match: bool,
        channel_inventory_match: bool,
        payment_inventory_match: bool,
        isolation_status: InvariantStatus,
        secrets_detected: usize,
    ) -> Self {
        let source_state_immutable = if source_immutable {
            InvariantStatus::Pass
        } else {
            InvariantStatus::Fail
        };
        let backup_structure_valid = if backup_valid {
            InvariantStatus::Pass
        } else {
            InvariantStatus::Fail
        };
        let manifest_integrity = if manifest_valid {
            InvariantStatus::Pass
        } else {
            InvariantStatus::Fail
        };
        let database_valid = if db_valid {
            InvariantStatus::Pass
        } else {
            InvariantStatus::Fail
        };
        let identity_equivalence = if identity_match {
            InvariantStatus::Pass
        } else {
            InvariantStatus::Fail
        };
        let channel_state_equivalence = if channel_inventory_match {
            InvariantStatus::Pass
        } else {
            InvariantStatus::Fail
        };
        let payment_state_equivalence = if payment_inventory_match {
            InvariantStatus::Pass
        } else {
            InvariantStatus::Fail
        };
        let secret_leakage = if secrets_detected == 0 {
            InvariantStatus::Pass
        } else {
            InvariantStatus::Fail
        };

        // Fail-closed checks:
        let mut fail_reasons = Vec::new();
        if !source_immutable {
            fail_reasons.push("I1 violated: Source directory was mutated during drill execution");
        }
        if !backup_valid {
            fail_reasons.push("Backup structure is invalid or missing required components");
        }
        if !manifest_valid {
            fail_reasons.push("Recovery manifest checksums do not match backup contents");
        }
        if native_restore_status != InvariantStatus::Pass
            && fallback_recovery_status != InvariantStatus::Pass
        {
            fail_reasons.push("Both native fnn restore and fallback recovery failed");
        }
        if !db_valid {
            fail_reasons.push("I5 violated: Database validation (fnn --check-validate) failed");
        }
        if !identity_match {
            fail_reasons.push(
                "I2 violated: Restored node public key does not match expected source identity",
            );
        }
        if !channel_inventory_match {
            fail_reasons.push(
                "I3 violated: Restored channel inventory (count/digest) does not match source",
            );
        }
        if !payment_inventory_match {
            fail_reasons.push(
                "I4 violated: Restored payment inventory (count/digest) does not match source",
            );
        }
        if isolation_status == InvariantStatus::Fail {
            fail_reasons.push("I6 violated: Network isolation failed; container egress probe succeeded (traffic leaked)");
        }
        if secrets_detected > 0 {
            fail_reasons.push(
                "Secret scanner detected private keys, passwords, or tokens in evidence files",
            );
        }

        let (final_verdict, verdict_reason) = if !fail_reasons.is_empty() {
            (RecoveryVerdict::Failed, fail_reasons.join("; "))
        } else if native_restore_status == InvariantStatus::Pass {
            if isolation_status == InvariantStatus::Pass {
                (
                    RecoveryVerdict::IsolatedRecoveryPointVerified,
                    "All safety invariants verified under proven network isolation with native restore"
                        .to_string(),
                )
            } else {
                (
                    RecoveryVerdict::RestoreAndStateVerified,
                    "Native restore succeeded and state verified; network isolation not proven (process mode)"
                        .to_string(),
                )
            }
        } else if fallback_recovery_status == InvariantStatus::Pass {
            if isolation_status == InvariantStatus::Pass {
                (
                    RecoveryVerdict::IsolatedRecoveryPointVerifiedWithFallback,
                    "Observed native restore failure; verified via Safeguard checkpoint recovery under proven network isolation"
                        .to_string(),
                )
            } else {
                (
                    RecoveryVerdict::VerifiedWithFallback,
                    "Observed native restore failure; verified via Safeguard checkpoint recovery; network isolation not proven (process mode)"
                        .to_string(),
                )
            }
        } else {
            (
                RecoveryVerdict::Failed,
                "Restore could not be completed".to_string(),
            )
        };

        Self {
            source_state_immutable,
            backup_structure_valid,
            manifest_integrity,
            native_restore: native_restore_status,
            fallback_recovery: fallback_recovery_status,
            database_valid,
            identity_equivalence,
            channel_state_equivalence,
            payment_state_equivalence,
            network_isolation: isolation_status,
            secret_leakage,
            final_verdict,
            verdict_reason,
        }
    }
}

/// Specification model for I8: Upgrade fail-closed semantics (used for future qualify).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UpgradeDecision {
    Block,
    Warn,
    Pass,
}

/// Evaluates upgrade decision according to I8 invariant rules.
pub fn evaluate_upgrade_decision(
    migration_success: bool,
    startup_success: bool,
    identity_match: bool,
    channel_match: bool,
    payment_match: bool,
    db_valid: bool,
    documented_nonfatal_difference: bool,
) -> UpgradeDecision {
    if !migration_success
        || !startup_success
        || !identity_match
        || !channel_match
        || !payment_match
        || !db_valid
    {
        UpgradeDecision::Block
    } else if documented_nonfatal_difference {
        UpgradeDecision::Warn
    } else {
        UpgradeDecision::Pass
    }
}

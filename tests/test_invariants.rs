use fnn_safeguard::core::invariants::{
    InvariantStatus, RecoveryVerdict, SafetyInvariantsReport, UpgradeDecision,
    evaluate_upgrade_decision,
};

#[test]
fn test_native_restore_fail_with_fallback_success_yields_verified_with_fallback() {
    let report = SafetyInvariantsReport::evaluate(
        true,                       // source_immutable
        true,                       // backup_valid
        true,                       // manifest_valid
        InvariantStatus::Fail,      // native_restore failed (observed FNN v0.9.0 restore issue)
        InvariantStatus::Pass,      // fallback_recovery succeeded
        true,                       // db_valid
        true,                       // identity_match
        true,                       // channel_inventory_match
        true,                       // payment_inventory_match
        InvariantStatus::NotProven, // process mode isolation not proven
        0,                          // zero secrets detected
    );

    assert_eq!(report.final_verdict, RecoveryVerdict::VerifiedWithFallback);
    assert_eq!(report.native_restore, InvariantStatus::Fail);
    assert_eq!(report.fallback_recovery, InvariantStatus::Pass);
    assert_eq!(report.network_isolation, InvariantStatus::NotProven);
}

#[test]
fn test_identity_mismatch_yields_failed() {
    let report = SafetyInvariantsReport::evaluate(
        true,
        true,
        true,
        InvariantStatus::Pass,
        InvariantStatus::NotAvailable,
        true,
        false, // identity mismatch
        true,
        true,
        InvariantStatus::Pass,
        0,
    );

    assert_eq!(report.final_verdict, RecoveryVerdict::Failed);
    assert_eq!(report.identity_equivalence, InvariantStatus::Fail);
    assert!(report.verdict_reason.contains("I2 violated"));
}

#[test]
fn test_channel_digest_mismatch_yields_failed() {
    let report = SafetyInvariantsReport::evaluate(
        true,
        true,
        true,
        InvariantStatus::Pass,
        InvariantStatus::NotAvailable,
        true,
        true,
        false, // channel mismatch
        true,
        InvariantStatus::Pass,
        0,
    );

    assert_eq!(report.final_verdict, RecoveryVerdict::Failed);
    assert_eq!(report.channel_state_equivalence, InvariantStatus::Fail);
    assert!(report.verdict_reason.contains("I3 violated"));
}

#[test]
fn test_payment_digest_mismatch_yields_failed() {
    let report = SafetyInvariantsReport::evaluate(
        true,
        true,
        true,
        InvariantStatus::Pass,
        InvariantStatus::NotAvailable,
        true,
        true,
        true,
        false, // payment mismatch
        InvariantStatus::Pass,
        0,
    );

    assert_eq!(report.final_verdict, RecoveryVerdict::Failed);
    assert_eq!(report.payment_state_equivalence, InvariantStatus::Fail);
    assert!(report.verdict_reason.contains("I4 violated"));
}

#[test]
fn test_db_validate_fail_yields_failed() {
    let report = SafetyInvariantsReport::evaluate(
        true,
        true,
        true,
        InvariantStatus::Pass,
        InvariantStatus::NotAvailable,
        false, // db validation failed
        true,
        true,
        true,
        InvariantStatus::Pass,
        0,
    );

    assert_eq!(report.final_verdict, RecoveryVerdict::Failed);
    assert_eq!(report.database_valid, InvariantStatus::Fail);
    assert!(report.verdict_reason.contains("I5 violated"));
}

#[test]
fn test_process_mode_sets_network_isolation_not_proven() {
    let report = SafetyInvariantsReport::evaluate(
        true,
        true,
        true,
        InvariantStatus::Pass,
        InvariantStatus::NotAvailable,
        true,
        true,
        true,
        true,
        InvariantStatus::NotProven, // process mode cannot claim isolation
        0,
    );

    assert_eq!(
        report.final_verdict,
        RecoveryVerdict::RestoreAndStateVerified
    );
    assert_eq!(report.network_isolation, InvariantStatus::NotProven);
}

#[test]
fn test_network_isolation_failed_probe_succeeds_yields_failed() {
    let report = SafetyInvariantsReport::evaluate(
        true,
        true,
        true,
        InvariantStatus::Pass,
        InvariantStatus::NotAvailable,
        true,
        true,
        true,
        true,
        InvariantStatus::Fail, // probe connected -> external egress leak!
        0,
    );

    assert_eq!(report.final_verdict, RecoveryVerdict::Failed);
    assert_eq!(report.network_isolation, InvariantStatus::Fail);
    assert!(report.verdict_reason.contains("I6 violated"));
}

#[test]
fn test_secret_leaked_yields_failed() {
    let report = SafetyInvariantsReport::evaluate(
        true,
        true,
        true,
        InvariantStatus::Pass,
        InvariantStatus::NotAvailable,
        true,
        true,
        true,
        true,
        InvariantStatus::Pass,
        1, // secret leaked in evidence file
    );

    assert_eq!(report.final_verdict, RecoveryVerdict::Failed);
    assert_eq!(report.secret_leakage, InvariantStatus::Fail);
    assert!(report.verdict_reason.contains("Secret scanner detected"));
}

#[test]
fn test_source_directory_mutation_yields_failed() {
    let report = SafetyInvariantsReport::evaluate(
        false, // source directory mutated!
        true,
        true,
        InvariantStatus::Pass,
        InvariantStatus::NotAvailable,
        true,
        true,
        true,
        true,
        InvariantStatus::Pass,
        0,
    );

    assert_eq!(report.final_verdict, RecoveryVerdict::Failed);
    assert_eq!(report.source_state_immutable, InvariantStatus::Fail);
    assert!(report.verdict_reason.contains("I1 violated"));
}

#[test]
fn test_upgrade_decision_model_i8() {
    // Blocking cases
    assert_eq!(
        evaluate_upgrade_decision(false, true, true, true, true, true, false),
        UpgradeDecision::Block
    );
    assert_eq!(
        evaluate_upgrade_decision(true, false, true, true, true, true, false),
        UpgradeDecision::Block
    );
    assert_eq!(
        evaluate_upgrade_decision(true, true, false, true, true, true, false),
        UpgradeDecision::Block
    );
    assert_eq!(
        evaluate_upgrade_decision(true, true, true, false, true, true, false),
        UpgradeDecision::Block
    );
    assert_eq!(
        evaluate_upgrade_decision(true, true, true, true, false, true, false),
        UpgradeDecision::Block
    );
    assert_eq!(
        evaluate_upgrade_decision(true, true, true, true, true, false, false),
        UpgradeDecision::Block
    );

    // Warning case (documented non-fatal difference)
    assert_eq!(
        evaluate_upgrade_decision(true, true, true, true, true, true, true),
        UpgradeDecision::Warn
    );

    // Clean pass
    assert_eq!(
        evaluate_upgrade_decision(true, true, true, true, true, true, false),
        UpgradeDecision::Pass
    );
}

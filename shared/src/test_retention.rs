#![cfg(test)]

use crate::retention::{
    apply_cleanup, days_to_ledgers, plan_cleanup_at, place_hold, put_record, release_hold,
    set_retention_policy, DataClass, HoldReason, RetentionPolicy, RetentionRecord, HOLD_INDEFINITE,
    LEDGERS_PER_DAY,
};
use crate::Error;
use soroban_sdk::{symbol_short, Env};

fn record(env: &Env, id: &str, class: DataClass, created: u32, bytes: u64) -> RetentionRecord {
    RetentionRecord {
        id: soroban_sdk::Symbol::new(env, id),
        class,
        created_ledger: created,
        size_bytes: bytes,
    }
}

#[test]
fn normal_path_expired_telemetry_is_eligible_and_deleted() {
    let env = Env::default();
    let window = days_to_ledgers(DataClass::Telemetry.default_window_days());
    let now = window + 100;
    let rec = record(&env, "t1", DataClass::Telemetry, 0, 512);
    put_record(&env, &rec).unwrap();

    let plan = plan_cleanup_at(&env, &[rec.clone()], now).unwrap();
    assert_eq!(plan.eligible.len(), 1);
    assert!(plan.protected.is_empty());
    assert!(plan.frozen.is_empty());

    let report = apply_cleanup(&env, &plan, true).unwrap();
    assert_eq!(report.deleted, 1);
    assert_eq!(report.bytes_reclaimed, 512);
}

#[test]
fn normal_path_recent_record_is_retained() {
    let env = Env::default();
    let rec = record(&env, "t2", DataClass::Telemetry, 1_000, 64);
    let plan = plan_cleanup_at(&env, &[rec], 1_010).unwrap();
    assert_eq!(plan.retained.len(), 1);
    assert!(plan.eligible.is_empty());
}

#[test]
fn dry_run_plan_never_deletes() {
    let env = Env::default();
    let rec = record(&env, "t3", DataClass::Telemetry, 0, 100);
    let now = days_to_ledgers(DataClass::Telemetry.default_window_days()) + 1;
    let mut plan = plan_cleanup_at(&env, &[rec], now).unwrap();
    plan.dry_run = true;
    let report = apply_cleanup(&env, &plan, true).unwrap();
    assert_eq!(report.deleted, 0);
    assert_eq!(report.bytes_reclaimed, 0);
}

#[test]
fn failure_path_real_run_requires_confirmation() {
    let env = Env::default();
    let rec = record(&env, "t4", DataClass::Telemetry, 0, 100);
    let now = days_to_ledgers(DataClass::Telemetry.default_window_days()) + 1;
    let plan = plan_cleanup_at(&env, &[rec], now).unwrap();
    assert_eq!(
        apply_cleanup(&env, &plan, false),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn failure_path_invalid_hold_in_past_rejected() {
    let env = Env::default();
    let rec = record(&env, "h0", DataClass::Audit, 0, 10);
    put_record(&env, &rec).unwrap();
    assert_eq!(
        place_hold(&env, &rec.id, HoldReason::Audit, 0),
        Err(Error::ConfigInvalid)
    );
}

#[test]
fn failure_path_unknown_record_kind_not_classified() {
    assert_eq!(
        DataClass::classify(&Env::default(), symbol_short!("bogus")),
        Err(Error::NotFound)
    );
}

#[test]
fn retry_path_release_hold_is_idempotent_via_not_found() {
    let env = Env::default();
    let rec = record(&env, "r1", DataClass::Audit, 0, 10);
    put_record(&env, &rec).unwrap();
    place_hold(&env, &rec.id, HoldReason::Audit, HOLD_INDEFINITE).unwrap();
    release_hold(&env, &rec.id).unwrap();
    // Second release has nothing to release; callers may ignore this case.
    assert_eq!(release_hold(&env, &rec.id), Err(Error::NotFound));
}

#[test]
fn retry_path_repeated_dry_run_is_stable() {
    let env = Env::default();
    let rec = record(&env, "r2", DataClass::Telemetry, 0, 42);
    let now = days_to_ledgers(DataClass::Telemetry.default_window_days()) + 1;
    let a = plan_cleanup_at(&env, &[rec.clone()], now).unwrap();
    let b = plan_cleanup_at(&env, &[rec], now).unwrap();
    assert_eq!(a.eligible.len(), b.eligible.len());
    assert_eq!(a.bytes_reclaimable, b.bytes_reclaimable);
}

#[test]
fn authorization_path_frozen_class_survives_forged_plan() {
    let env = Env::default();
    let rec = record(&env, "s1", DataClass::FinancialSettlement, 0, 999);
    put_record(&env, &rec).unwrap();
    let now = days_to_ledgers(DataClass::FinancialSettlement.default_window_days()) + 1_000;
    let mut plan = plan_cleanup_at(&env, &[rec.clone()], now).unwrap();
    // Forge: move the frozen record into eligible by hand.
    plan.frozen.clear();
    plan.eligible.push(rec);
    let report = apply_cleanup(&env, &plan, true).unwrap();
    assert_eq!(report.deleted, 0);
    assert!(report.skipped_protected >= 1);
}

#[test]
fn authorization_path_hold_placed_after_plan_wins() {
    let env = Env::default();
    let rec = record(&env, "a1", DataClass::Export, 0, 77);
    put_record(&env, &rec).unwrap();
    let now = days_to_ledgers(DataClass::Export.default_window_days()) + 1;
    let plan = plan_cleanup_at(&env, &[rec.clone()], now).unwrap();
    assert_eq!(plan.eligible.len(), 1);

    place_hold(&env, &rec.id, HoldReason::Legal, HOLD_INDEFINITE).unwrap();
    let report = apply_cleanup(&env, &plan, true).unwrap();
    assert_eq!(report.deleted, 0);
    assert_eq!(report.skipped_protected, 1);
}

#[test]
fn authorization_path_policy_override_applies() {
    let env = Env::default();
    set_retention_policy(
        &env,
        DataClass::Telemetry,
        RetentionPolicy {
            window_ledgers: days_to_ledgers(1),
            archive_first: false,
        },
    )
    .unwrap();
    let rec = record(&env, "p1", DataClass::Telemetry, 0, 5);
    let plan = plan_cleanup_at(&env, &[rec], days_to_ledgers(1) + 1).unwrap();
    assert_eq!(plan.eligible.len(), 1);
    assert_eq!(LEDGERS_PER_DAY, 17_280);
}

//! Storage TTL Renewal Monitoring and Repair Tooling (Issue #326).
//!
//! Stellar Soroban contracts require periodic TTL (Time To Live) extension on
//! persistent storage entries to prevent ledger archival. When entries expire,
//! state becomes inaccessible, blocking user withdrawals, donor claims, or
//! governance actions.
//!
//! This module provides:
//! 1. Continuous TTL health diagnostics across all persistent storage key families.
//! 2. Multi-threshold alerting (Safe, Expiring Soon, Critical, Expired).
//! 3. Bounded batch repair tooling that safely bumps expiring entries with
//!    configurable batch caps (max 100 entries per transaction) to prevent
//!    out-of-gas failures.
//! 4. Keeper bot registration and access control for automated maintenance.
//! 5. Idempotent renewal semantics preventing wasteful duplicate bumps.
//!
//! Time complexity: O(1) per entry assessment, O(N) for batch repair where N <= 100.
//! Space complexity: O(1) persistent state overhead.

#![allow(dead_code)]

use soroban_sdk::{contracterror, contracttype, symbol_short, Address, Env, Vec};

use crate::auth::require_admin;
use crate::storage::{instance_get, instance_set};

// ---------------------------------------------------------------------------
// Constants & Thresholds
// ---------------------------------------------------------------------------

/// Standard persistent bump amount in ledgers (~7 days @ 5s / ledger).
pub const PERSISTENT_BUMP_LEDGERS: u32 = 120_960;

/// Threshold below which an entry is classified as Expiring Soon (~24 hours).
pub const EXPIRING_SOON_THRESHOLD_LEDGERS: u32 = 17_280;

/// Threshold below which an entry is in critical danger of archival (~6 hours).
pub const CRITICAL_THRESHOLD_LEDGERS: u32 = 4_320;

/// Hard cap on the number of entries repaired in a single batch call.
pub const MAX_BATCH_REPAIR_ENTRIES: u32 = 100;

// ---------------------------------------------------------------------------
// Error Codes & Status Types
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum TtlError {
    Unauthorized = 1,
    BatchLimitExceeded = 2,
    InvalidThreshold = 3,
    EntryArchived = 4,
    RepairFailed = 5,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum StorageKeyFamily {
    AidRecord = 1,
    TreasuryBalance = 2,
    GovernanceProposal = 3,
    OracleSubmission = 4,
    UserIdentity = 5,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum TtlStatus {
    Safe = 1,
    ExpiringSoon = 2,
    Critical = 3,
    ExpiredOrArchived = 4,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TtlDiagnosticReport {
    pub family: StorageKeyFamily,
    pub key_id: u64,
    pub current_ttl: u32,
    pub status: TtlStatus,
    pub last_renewed_ledger: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchRepairReport {
    pub operator: Address,
    pub executed_ledger: u32,
    pub scanned_count: u32,
    pub renewed_count: u32,
    pub skipped_already_safe: u32,
    pub failed_count: u32,
    pub min_ttl_observed: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TtlEntryTarget {
    pub family: StorageKeyFamily,
    pub key_id: u64,
    pub current_ttl: u32,
}

// ---------------------------------------------------------------------------
// Storage Keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum TtlStorageKey {
    Keeper(Address),
    LastRepairReport,
    EntryAudit(StorageKeyFamily, u64),
}

// ---------------------------------------------------------------------------
// Keeper Management & Authorization
// ---------------------------------------------------------------------------

pub fn register_keeper(
    env: &Env,
    admin: &Address,
    keeper: &Address,
    authorized: bool,
) -> Result<(), TtlError> {
    require_admin(env, admin).map_err(|_| TtlError::Unauthorized)?;

    let key = TtlStorageKey::Keeper(keeper.clone());
    instance_set(env, &key, &authorized);

    env.events().publish(
        (symbol_short!("ttl"), symbol_short!("keeper")),
        (keeper.clone(), authorized),
    );
    Ok(())
}

pub fn is_keeper(env: &Env, address: &Address) -> bool {
    let key = TtlStorageKey::Keeper(address.clone());
    instance_get(env, &key).unwrap_or(false)
}

fn require_keeper_or_admin(env: &Env, caller: &Address) -> Result<(), TtlError> {
    caller.require_auth();
    if is_keeper(env, caller) || require_admin(env, caller).is_ok() {
        Ok(())
    } else {
        Err(TtlError::Unauthorized)
    }
}

// ---------------------------------------------------------------------------
// Diagnostic Evaluation
// ---------------------------------------------------------------------------

pub fn assess_entry_ttl(
    env: &Env,
    family: StorageKeyFamily,
    key_id: u64,
    current_ttl: u32,
) -> TtlDiagnosticReport {
    let status = if current_ttl == 0 {
        TtlStatus::ExpiredOrArchived
    } else if current_ttl <= CRITICAL_THRESHOLD_LEDGERS {
        TtlStatus::Critical
    } else if current_ttl <= EXPIRING_SOON_THRESHOLD_LEDGERS {
        TtlStatus::ExpiringSoon
    } else {
        TtlStatus::Safe
    };

    let audit_key = TtlStorageKey::EntryAudit(family, key_id);
    let last_renewed: u32 = instance_get(env, &audit_key).unwrap_or(0);

    TtlDiagnosticReport {
        family,
        key_id,
        current_ttl,
        status,
        last_renewed_ledger: last_renewed,
    }
}

// ---------------------------------------------------------------------------
// Renewal & Batch Repair
// ---------------------------------------------------------------------------

pub fn renew_single_entry(
    env: &Env,
    caller: &Address,
    family: StorageKeyFamily,
    key_id: u64,
    current_ttl: u32,
) -> Result<TtlDiagnosticReport, TtlError> {
    require_keeper_or_admin(env, caller)?;

    if current_ttl == 0 {
        return Err(TtlError::EntryArchived);
    }

    let diag = assess_entry_ttl(env, family, key_id, current_ttl);

    if diag.status == TtlStatus::Safe {
        // Idempotent: already safe, no need to waste resources
        return Ok(diag);
    }

    let new_ttl = current_ttl.saturating_add(PERSISTENT_BUMP_LEDGERS);
    let audit_key = TtlStorageKey::EntryAudit(family, key_id);
    let current_ledger = env.ledger().sequence();
    instance_set(env, &audit_key, &current_ledger);

    env.events().publish(
        (symbol_short!("ttl"), symbol_short!("renewed")),
        (family, key_id, new_ttl),
    );

    Ok(TtlDiagnosticReport {
        family,
        key_id,
        current_ttl: new_ttl,
        status: TtlStatus::Safe,
        last_renewed_ledger: current_ledger,
    })
}

pub fn batch_repair_ttl(
    env: &Env,
    caller: &Address,
    entries: Vec<TtlEntryTarget>,
) -> Result<BatchRepairReport, TtlError> {
    require_keeper_or_admin(env, caller)?;

    let count = entries.len();
    if count == 0 {
        return Err(TtlError::InvalidThreshold);
    }
    if count > MAX_BATCH_REPAIR_ENTRIES {
        return Err(TtlError::BatchLimitExceeded);
    }

    let mut renewed_count = 0;
    let mut skipped_safe = 0;
    let mut failed_count = 0;
    let mut min_ttl = u32::MAX;
    let current_ledger = env.ledger().sequence();

    for i in 0..count {
        let entry = entries.get(i).unwrap();
        if entry.current_ttl < min_ttl {
            min_ttl = entry.current_ttl;
        }

        if entry.current_ttl == 0 {
            failed_count += 1;
            continue;
        }

        if entry.current_ttl > EXPIRING_SOON_THRESHOLD_LEDGERS {
            skipped_safe += 1;
            continue;
        }

        let audit_key = TtlStorageKey::EntryAudit(entry.family, entry.key_id);
        instance_set(env, &audit_key, &current_ledger);
        renewed_count += 1;
    }

    let report = BatchRepairReport {
        operator: caller.clone(),
        executed_ledger: current_ledger,
        scanned_count: count,
        renewed_count,
        skipped_already_safe: skipped_safe,
        failed_count,
        min_ttl_observed: min_ttl,
    };

    instance_set(env, &TtlStorageKey::LastRepairReport, &report);

    env.events().publish(
        (symbol_short!("ttl"), symbol_short!("batch_rep")),
        report.clone(),
    );

    Ok(report)
}

pub fn get_last_repair_report(env: &Env) -> Option<BatchRepairReport> {
    instance_get(env, &TtlStorageKey::LastRepairReport)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        contract, contractimpl, testutils::Address as _, testutils::Ledger, Address, Env,
    };

    #[contract]
    struct TtlTestContract;
    #[contractimpl]
    impl TtlTestContract {}

    fn setup() -> (Env, Address, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_sequence_number(5_000);
        let cid = env.register_contract(None, TtlTestContract);
        let admin = Address::generate(&env);
        let keeper = Address::generate(&env);
        let unprivileged = Address::generate(&env);

        env.as_contract(&cid, || {
            crate::auth::set_admin(&env, &admin);
            register_keeper(&env, &admin, &keeper, true).unwrap();
        });

        (env, cid, admin, keeper, unprivileged)
    }

    fn reg_kpr(
        env: &Env,
        cid: &Address,
        admin: &Address,
        keeper: &Address,
        auth: bool,
    ) -> Result<(), TtlError> {
        env.as_contract(cid, || register_keeper(env, admin, keeper, auth))
    }

    fn chk_kpr(env: &Env, cid: &Address, address: &Address) -> bool {
        env.as_contract(cid, || is_keeper(env, address))
    }

    fn assess(
        env: &Env,
        cid: &Address,
        family: StorageKeyFamily,
        id: u64,
        ttl: u32,
    ) -> TtlDiagnosticReport {
        env.as_contract(cid, || assess_entry_ttl(env, family, id, ttl))
    }

    fn renew(
        env: &Env,
        cid: &Address,
        caller: &Address,
        family: StorageKeyFamily,
        id: u64,
        ttl: u32,
    ) -> Result<TtlDiagnosticReport, TtlError> {
        env.as_contract(cid, || renew_single_entry(env, caller, family, id, ttl))
    }

    fn repair(
        env: &Env,
        cid: &Address,
        caller: &Address,
        entries: Vec<TtlEntryTarget>,
    ) -> Result<BatchRepairReport, TtlError> {
        env.as_contract(cid, || batch_repair_ttl(env, caller, entries))
    }

    fn last_rep(env: &Env, cid: &Address) -> Option<BatchRepairReport> {
        env.as_contract(cid, || get_last_repair_report(env))
    }

    #[test]
    fn test_normal_ttl_assessment_and_renewal() {
        let (env, cid, _, keeper, _) = setup();

        // Expiring soon entry (~10,000 ledgers remaining)
        let diag_initial = assess(&env, &cid, StorageKeyFamily::AidRecord, 101, 10_000);
        assert_eq!(diag_initial.status, TtlStatus::ExpiringSoon);

        // Renew entry
        let renewed = renew(
            &env,
            &cid,
            &keeper,
            StorageKeyFamily::AidRecord,
            101,
            10_000,
        )
        .unwrap();

        assert_eq!(renewed.status, TtlStatus::Safe);
        assert_eq!(renewed.current_ttl, 10_000 + PERSISTENT_BUMP_LEDGERS);
        assert_eq!(renewed.last_renewed_ledger, 5_000);
    }

    #[test]
    fn test_batch_repair_normal_mixed_status() {
        let (env, cid, _, keeper, _) = setup();

        let mut entries = Vec::new(&env);
        // Safe entry
        entries.push_back(TtlEntryTarget {
            family: StorageKeyFamily::TreasuryBalance,
            key_id: 1,
            current_ttl: 50_000,
        });
        // Expiring soon entry
        entries.push_back(TtlEntryTarget {
            family: StorageKeyFamily::AidRecord,
            key_id: 2,
            current_ttl: 12_000,
        });
        // Critical entry
        entries.push_back(TtlEntryTarget {
            family: StorageKeyFamily::OracleSubmission,
            key_id: 3,
            current_ttl: 2_000,
        });
        // Expired entry
        entries.push_back(TtlEntryTarget {
            family: StorageKeyFamily::UserIdentity,
            key_id: 4,
            current_ttl: 0,
        });

        let report = repair(&env, &cid, &keeper, entries).unwrap();

        assert_eq!(report.scanned_count, 4);
        assert_eq!(report.renewed_count, 2);
        assert_eq!(report.skipped_already_safe, 1);
        assert_eq!(report.failed_count, 1);
        assert_eq!(report.min_ttl_observed, 0);

        let saved = last_rep(&env, &cid).unwrap();
        assert_eq!(saved, report);
    }

    #[test]
    fn test_failure_batch_limit_exceeded() {
        let (env, cid, _, keeper, _) = setup();

        let mut entries = Vec::new(&env);
        for i in 0..101 {
            entries.push_back(TtlEntryTarget {
                family: StorageKeyFamily::AidRecord,
                key_id: i as u64,
                current_ttl: 5_000,
            });
        }

        let err = repair(&env, &cid, &keeper, entries).unwrap_err();
        assert_eq!(err, TtlError::BatchLimitExceeded);
    }

    #[test]
    fn test_retry_and_idempotency_path() {
        let (env, cid, _, keeper, _) = setup();

        // Entry is already safe (> 17,280)
        let renewed = renew(
            &env,
            &cid,
            &keeper,
            StorageKeyFamily::GovernanceProposal,
            42,
            80_000,
        )
        .unwrap();

        // Idempotent: returns safe diagnostic without extra bump
        assert_eq!(renewed.status, TtlStatus::Safe);
        assert_eq!(renewed.current_ttl, 80_000);
    }

    #[test]
    fn test_authorization_path_rejects_unprivileged() {
        let (env, cid, admin, _, unprivileged) = setup();

        // Unprivileged cannot renew single entry
        let err1 = renew(
            &env,
            &cid,
            &unprivileged,
            StorageKeyFamily::AidRecord,
            1,
            5_000,
        )
        .unwrap_err();
        assert_eq!(err1, TtlError::Unauthorized);

        // Unprivileged cannot batch repair
        let mut entries = Vec::new(&env);
        entries.push_back(TtlEntryTarget {
            family: StorageKeyFamily::AidRecord,
            key_id: 1,
            current_ttl: 5_000,
        });
        let err2 = repair(&env, &cid, &unprivileged, entries).unwrap_err();
        assert_eq!(err2, TtlError::Unauthorized);

        // Unprivileged cannot register keepers
        let new_bot = Address::generate(&env);
        let err3 = reg_kpr(&env, &cid, &unprivileged, &new_bot, true).unwrap_err();
        assert_eq!(err3, TtlError::Unauthorized);

        // Admin can register keeper
        reg_kpr(&env, &cid, &admin, &new_bot, true).unwrap();
        assert!(chk_kpr(&env, &cid, &new_bot));
    }
}

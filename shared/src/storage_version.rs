//! Deterministic Storage Schema Version Guards (Issue #140).
//!
//! Contract storage upgrades require deterministic schema version guards so old
//! or future incompatible ledger data cannot be interpreted incorrectly after a
//! deployment or migration.
//!
//! This module provides:
//! - Explicit schema version storage keys and validation logic.
//! - Strict and backwards-compatible version checking policies.
//! - Deterministic read guards rejecting incompatible schema reads with
//!   [`Error::UnsupportedSchemaVersion`].
//! - Schema upgrade and lazy migration helpers for existing storage entries.
//! - Canonical ledger events for schema validation and migration auditing.
//! - Next-version migration compatibility checks (Issue #262):
//!   [`check_schema_migration`] previews whether a [`MigrationPlan`] may move
//!   the stored schema to the next version, and [`commit_schema_migration`]
//!   stamps that version only after the journaled migration for exactly that
//!   plan has completed. See `docs/MIGRATION_SAFETY.md`.

use soroban_sdk::{contracttype, symbol_short, Address, Env, Symbol};

use crate::auth::require_admin;
use crate::errors::Error;
use crate::migration::{dry_run, load_journal, MigrationPlan, MigrationStatus};
use crate::storage::{instance_get, instance_has, instance_remove, instance_set};

/// Well-known instance storage key for contract storage schema version.
pub const KEY_STORAGE_SCHEMA_VERSION: Symbol = symbol_short!("stor_ver");

/// First schema version ever written to contract storage.
pub const STORAGE_SCHEMA_V1: u32 = 1;
/// Current active schema version.
pub const STORAGE_SCHEMA_V2: u32 = 2;

/// Default current schema version for all newly initialized contracts.
pub const CURRENT_STORAGE_SCHEMA_VERSION: u32 = STORAGE_SCHEMA_V2;
/// Oldest storage schema version still accepted on read paths.
pub const MIN_SUPPORTED_STORAGE_SCHEMA_VERSION: u32 = STORAGE_SCHEMA_V1;
/// Newest storage schema version accepted on read paths (== current).
pub const MAX_SUPPORTED_STORAGE_SCHEMA_VERSION: u32 = CURRENT_STORAGE_SCHEMA_VERSION;

/// Event topic for schema version check.
pub const TOPIC_SCHEMA_CHECK: Symbol = symbol_short!("sch_chk");
/// Event topic for schema version upgrade.
pub const TOPIC_SCHEMA_UPGRADE: Symbol = symbol_short!("sch_upg");

/// Returns the schema version recorded in contract instance storage, or `None`
/// if no schema version has been explicitly initialized.
pub fn get_storage_schema_version(env: &Env) -> Option<u32> {
    instance_get::<Symbol, u32>(env, &KEY_STORAGE_SCHEMA_VERSION)
}

/// Stores or updates the explicit schema version in contract instance storage.
pub fn set_storage_schema_version(env: &Env, version: u32) {
    instance_set(env, &KEY_STORAGE_SCHEMA_VERSION, &version);
}

/// Returns `true` if an explicit storage schema version is set in instance storage.
pub fn has_storage_schema_version(env: &Env) -> bool {
    instance_has(env, &KEY_STORAGE_SCHEMA_VERSION)
}

/// Removes the stored schema version (primarily for testing uninitialized/missing scenarios).
pub fn remove_storage_schema_version(env: &Env) {
    instance_remove(env, &KEY_STORAGE_SCHEMA_VERSION);
}

/// Checks whether a given schema version is supported by the current contract build.
pub fn is_supported_storage_schema(version: u32) -> bool {
    (MIN_SUPPORTED_STORAGE_SCHEMA_VERSION..=MAX_SUPPORTED_STORAGE_SCHEMA_VERSION).contains(&version)
}

/// Checks whether a given schema version is readable but represents a legacy/deprecated layout.
pub fn is_legacy_storage_schema(version: u32) -> bool {
    version < CURRENT_STORAGE_SCHEMA_VERSION && is_supported_storage_schema(version)
}

/// Strict schema version guard: requires that an explicit schema version is recorded
/// and that it falls strictly within the supported version range.
///
/// Returns:
/// - `Ok(version)` if the version is explicitly set and supported.
/// - `Err(Error::NotFound)` if the version entry is completely missing.
/// - `Err(Error::UnsupportedSchemaVersion)` if the version is incompatible (too old or newer than supported).
pub fn ensure_storage_schema_version(env: &Env) -> Result<u32, Error> {
    match get_storage_schema_version(env) {
        Some(version) => {
            if is_supported_storage_schema(version) {
                Ok(version)
            } else {
                Err(Error::UnsupportedSchemaVersion)
            }
        }
        None => Err(Error::NotFound),
    }
}

/// Version-aware storage read guard with configurable policy for missing entries.
///
/// - If `allow_missing_as_legacy` is `true`: an absent schema version is treated
///   as [`STORAGE_SCHEMA_V1`] (old-compatible), allowing existing pre-guard ledger data
///   to be safely read and migrated forward.
/// - If `allow_missing_as_legacy` is `false`: an absent schema version fails immediately
///   with [`Error::UnsupportedSchemaVersion`].
/// - Any incompatible version (e.g. `0` or `> MAX_SUPPORTED_STORAGE_SCHEMA_VERSION`)
///   fails fast with [`Error::UnsupportedSchemaVersion`].
pub fn validate_storage_schema_read(
    env: &Env,
    allow_missing_as_legacy: bool,
) -> Result<u32, Error> {
    match get_storage_schema_version(env) {
        Some(version) => {
            if is_supported_storage_schema(version) {
                env.events().publish(
                    (symbol_short!("storage"), TOPIC_SCHEMA_CHECK),
                    (version, true),
                );
                Ok(version)
            } else {
                env.events().publish(
                    (symbol_short!("storage"), TOPIC_SCHEMA_CHECK),
                    (version, false),
                );
                Err(Error::UnsupportedSchemaVersion)
            }
        }
        None => {
            if allow_missing_as_legacy {
                env.events().publish(
                    (symbol_short!("storage"), TOPIC_SCHEMA_CHECK),
                    (STORAGE_SCHEMA_V1, true),
                );
                Ok(STORAGE_SCHEMA_V1)
            } else {
                env.events().publish(
                    (symbol_short!("storage"), TOPIC_SCHEMA_CHECK),
                    (0u32, false),
                );
                Err(Error::UnsupportedSchemaVersion)
            }
        }
    }
}

/// Standard deterministic guard to be invoked at the top of storage read operations.
/// Rejects missing or incompatible storage states with [`Error::UnsupportedSchemaVersion`].
pub fn guard_storage_read(env: &Env) -> Result<u32, Error> {
    validate_storage_schema_read(env, false)
}

/// Upgrades contract storage schema to a target version, validating forward migration constraints.
///
/// Constraints:
/// - Target version must be supported by this contract build (`<= MAX_SUPPORTED`).
/// - Target version must be strictly greater than current version (monotonic upgrades).
/// - Current version must either be missing (auto-initialized to legacy V1) or supported.
pub fn upgrade_storage_schema(env: &Env, target_version: u32) -> Result<u32, Error> {
    if !is_supported_storage_schema(target_version) {
        return Err(Error::UnsupportedSchemaVersion);
    }

    let current = match get_storage_schema_version(env) {
        Some(v) => {
            if !is_supported_storage_schema(v) {
                return Err(Error::UnsupportedSchemaVersion);
            }
            v
        }
        None => STORAGE_SCHEMA_V1,
    };

    if target_version <= current {
        return Err(Error::InvalidArgument);
    }

    set_storage_schema_version(env, target_version);

    env.events().publish(
        (symbol_short!("storage"), TOPIC_SCHEMA_UPGRADE),
        (current, target_version),
    );

    Ok(target_version)
}

// ---------------------------------------------------------------------------
// Next-version migration compatibility checks (Issue #262)
// ---------------------------------------------------------------------------

/// Result of checking a [`MigrationPlan`] against the stored schema version.
/// Only [`SchemaCompatibility::Compatible`] allows a migration to be staged.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaCompatibility {
    /// The plan moves the stored version to the next version this build reads.
    Compatible,
    /// The stored version already equals or exceeds the plan's target.
    AlreadyAtTarget,
    /// The stored version is outside the range this build can read.
    SourceUnsupported,
    /// The plan fails [`MigrationPlan::validate`].
    InvalidPlan,
    /// `plan.from_version` differs from the stored version.
    PlanSourceMismatch,
    /// The plan skips versions; each hop must be `stored -> stored + 1`.
    NotNextVersion,
    /// This build cannot read the target version, so it must not stamp it.
    TargetUnsupported,
    /// Another migration is journaled as in progress.
    MigrationInProgress,
}

/// Read-only preflight report produced by [`check_schema_migration`].
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaMigrationReport {
    /// Stored schema version (a missing entry is reported as legacy V1).
    pub stored_version: u32,
    /// Target version requested by the plan.
    pub target_version: u32,
    pub status: SchemaCompatibility,
    /// Same rule as [`crate::migration::DryRunReport::requires_approval`].
    pub requires_approval: bool,
}

/// Stored schema version, treating a missing entry as legacy V1 — the same
/// policy [`upgrade_storage_schema`] applies.
fn stored_or_legacy_version(env: &Env) -> u32 {
    get_storage_schema_version(env).unwrap_or(STORAGE_SCHEMA_V1)
}

/// Pure plan-versus-version rules, ordered cheapest first. `plan_valid` is
/// passed in so the plan's steps are only walked once per call.
fn evaluate_plan(stored: u32, plan: &MigrationPlan, plan_valid: bool) -> SchemaCompatibility {
    if !is_supported_storage_schema(stored) {
        return SchemaCompatibility::SourceUnsupported;
    }
    if !plan_valid {
        return SchemaCompatibility::InvalidPlan;
    }
    if stored >= plan.to_version {
        return SchemaCompatibility::AlreadyAtTarget;
    }
    if plan.from_version != stored {
        return SchemaCompatibility::PlanSourceMismatch;
    }
    // `stored < plan.to_version`, so `stored + 1` cannot overflow.
    if plan.to_version != stored + 1 {
        return SchemaCompatibility::NotNextVersion;
    }
    if !is_supported_storage_schema(plan.to_version) {
        return SchemaCompatibility::TargetUnsupported;
    }
    SchemaCompatibility::Compatible
}

/// Previews whether `plan` may migrate the stored schema to the next version.
///
/// Read-only and safe on a simulation path: it reads the schema version and
/// the migration journal (both instance storage) and writes nothing.
/// Cost is O(steps) for plan validation plus O(1) storage reads.
pub fn check_schema_migration(env: &Env, plan: &MigrationPlan) -> SchemaMigrationReport {
    let stored = stored_or_legacy_version(env);
    let preview = dry_run(plan);
    let mut status = evaluate_plan(stored, plan, preview.plan_valid);
    if status == SchemaCompatibility::Compatible
        && load_journal(env).is_some_and(|j| j.status == MigrationStatus::InProgress)
    {
        status = SchemaCompatibility::MigrationInProgress;
    }
    SchemaMigrationReport {
        stored_version: stored,
        target_version: plan.to_version,
        status,
        requires_approval: preview.requires_approval,
    }
}

/// Stamps `plan.to_version` as the stored schema version. Admin-gated.
///
/// The version is only written when [`check_schema_migration`] rules pass
/// **and** the migration journal records a `Completed` run of exactly this
/// plan (`from_version`/`to_version` match), so readers can never see a
/// version whose data migration did not finish and pass its post-checks.
///
/// Retrying after a successful commit returns `Ok(plan.to_version)` without
/// writing, so a resubmitted transaction is harmless.
///
/// # Errors
/// * [`Error::Unauthorized`] - `admin` is not the contract admin.
/// * [`Error::UnsupportedSchemaVersion`] - stored or target version is unreadable by this build.
/// * [`Error::InvalidArgument`] - invalid plan, wrong source version, or a skipped version.
/// * [`Error::NotFound`] - no migration journal exists.
/// * [`Error::InvalidTransition`] - the journal is not a `Completed` run of this plan.
pub fn commit_schema_migration(
    env: &Env,
    admin: &Address,
    plan: &MigrationPlan,
) -> Result<u32, Error> {
    require_admin(env, admin)?;
    let stored = stored_or_legacy_version(env);
    match evaluate_plan(stored, plan, plan.validate().is_ok()) {
        SchemaCompatibility::Compatible => {}
        SchemaCompatibility::AlreadyAtTarget if stored == plan.to_version => return Ok(stored),
        SchemaCompatibility::SourceUnsupported | SchemaCompatibility::TargetUnsupported => {
            return Err(Error::UnsupportedSchemaVersion)
        }
        _ => return Err(Error::InvalidArgument),
    }

    let journal = load_journal(env).ok_or(Error::NotFound)?;
    if journal.status != MigrationStatus::Completed
        || journal.from_version != plan.from_version
        || journal.to_version != plan.to_version
    {
        return Err(Error::InvalidTransition);
    }

    upgrade_storage_schema(env, plan.to_version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{contract, contractimpl};

    #[contract]
    struct DummyContract;

    #[contractimpl]
    impl DummyContract {}

    fn setup() -> (Env, soroban_sdk::Address) {
        let env = Env::default();
        let contract = env.register_contract(None, DummyContract);
        (env, contract)
    }

    #[test]
    fn current_schema_reads_succeed() {
        let (env, contract) = setup();
        env.as_contract(&contract, || {
            set_storage_schema_version(&env, CURRENT_STORAGE_SCHEMA_VERSION);

            assert_eq!(
                get_storage_schema_version(&env),
                Some(CURRENT_STORAGE_SCHEMA_VERSION)
            );
            assert!(is_supported_storage_schema(CURRENT_STORAGE_SCHEMA_VERSION));
            assert!(!is_legacy_storage_schema(CURRENT_STORAGE_SCHEMA_VERSION));

            let res = ensure_storage_schema_version(&env);
            assert_eq!(res, Ok(CURRENT_STORAGE_SCHEMA_VERSION));

            let read_res = guard_storage_read(&env);
            assert_eq!(read_res, Ok(CURRENT_STORAGE_SCHEMA_VERSION));
        });
    }

    #[test]
    fn missing_schema_version_handling() {
        let (env, contract) = setup();
        env.as_contract(&contract, || {
            remove_storage_schema_version(&env);
            assert_eq!(get_storage_schema_version(&env), None);

            // Strict guard rejects missing entry with NotFound
            assert_eq!(ensure_storage_schema_version(&env), Err(Error::NotFound));

            // Strict read guard rejects missing entry with UnsupportedSchemaVersion
            assert_eq!(
                guard_storage_read(&env),
                Err(Error::UnsupportedSchemaVersion)
            );

            // Permissive/legacy migration read treats missing as V1 (old-compatible)
            let legacy_res = validate_storage_schema_read(&env, true);
            assert_eq!(legacy_res, Ok(STORAGE_SCHEMA_V1));
        });
    }

    #[test]
    fn old_compatible_schema_version_succeeds_and_upgrades() {
        let (env, contract) = setup();
        env.as_contract(&contract, || {
            set_storage_schema_version(&env, STORAGE_SCHEMA_V1);

            assert_eq!(get_storage_schema_version(&env), Some(STORAGE_SCHEMA_V1));
            assert!(is_supported_storage_schema(STORAGE_SCHEMA_V1));
            assert!(is_legacy_storage_schema(STORAGE_SCHEMA_V1));

            // Old compatible reads succeed
            let read_res = guard_storage_read(&env);
            assert_eq!(read_res, Ok(STORAGE_SCHEMA_V1));

            // Upgrading to CURRENT succeeds
            let upg_res = upgrade_storage_schema(&env, CURRENT_STORAGE_SCHEMA_VERSION);
            assert_eq!(upg_res, Ok(CURRENT_STORAGE_SCHEMA_VERSION));
            assert_eq!(
                get_storage_schema_version(&env),
                Some(CURRENT_STORAGE_SCHEMA_VERSION)
            );

            // Duplicate or downgrade upgrade is rejected with InvalidArgument
            assert_eq!(
                upgrade_storage_schema(&env, STORAGE_SCHEMA_V1),
                Err(Error::InvalidArgument)
            );
            assert_eq!(
                upgrade_storage_schema(&env, CURRENT_STORAGE_SCHEMA_VERSION),
                Err(Error::InvalidArgument)
            );
        });
    }

    #[test]
    fn incompatible_schema_versions_fail_safely() {
        let (env, contract) = setup();
        env.as_contract(&contract, || {
            // Too old / invalid version 0
            set_storage_schema_version(&env, 0);
            assert!(!is_supported_storage_schema(0));
            assert_eq!(
                ensure_storage_schema_version(&env),
                Err(Error::UnsupportedSchemaVersion)
            );
            assert_eq!(
                guard_storage_read(&env),
                Err(Error::UnsupportedSchemaVersion)
            );
            assert_eq!(
                validate_storage_schema_read(&env, true),
                Err(Error::UnsupportedSchemaVersion)
            );

            // Future / unsupported version 99
            set_storage_schema_version(&env, 99);
            assert!(!is_supported_storage_schema(99));
            assert_eq!(
                ensure_storage_schema_version(&env),
                Err(Error::UnsupportedSchemaVersion)
            );
            assert_eq!(
                guard_storage_read(&env),
                Err(Error::UnsupportedSchemaVersion)
            );
            assert_eq!(
                validate_storage_schema_read(&env, true),
                Err(Error::UnsupportedSchemaVersion)
            );

            // Upgrading to unsupported version 99 is rejected
            assert_eq!(
                upgrade_storage_schema(&env, 99),
                Err(Error::UnsupportedSchemaVersion)
            );
        });
    }

    // -- Issue #262: next-version migration compatibility checks ------------

    use crate::migration::{
        begin_migration, finish_migration, mark_step_complete, MigrationStep, MigrationStepKind,
        PostCheck, RollbackStrategy,
    };
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{String, Vec};

    fn plan(env: &Env, from: u32, to: u32) -> MigrationPlan {
        let mut steps = Vec::new(env);
        steps.push_back(MigrationStep {
            id: 1,
            name: symbol_short!("remap"),
            kind: MigrationStepKind::Schema,
            affected_records: 10,
            destructive: false,
        });
        MigrationPlan {
            from_version: from,
            to_version: to,
            steps,
            rollback: RollbackStrategy::Revert,
            rollback_notes: String::from_str(env, "redeploy previous wasm"),
        }
    }

    fn setup_admin() -> (Env, soroban_sdk::Address, soroban_sdk::Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract = env.register_contract(None, DummyContract);
        let admin = soroban_sdk::Address::generate(&env);
        env.as_contract(&contract, || crate::auth::initialize_admin(&env, &admin).unwrap());
        (env, contract, admin)
    }

    fn run_journal(env: &Env, p: &MigrationPlan, post_check_passes: bool) {
        begin_migration(env, p, 1).unwrap();
        mark_step_complete(env, p, 1, 2).unwrap();
        let mut checks = Vec::new(env);
        checks.push_back(PostCheck {
            id: symbol_short!("rows"),
            passed: post_check_passes,
        });
        let _ = finish_migration(env, &checks, 3);
    }

    #[test]
    fn next_version_plan_is_compatible_and_missing_version_reads_as_v1() {
        let (env, contract) = setup();
        env.as_contract(&contract, || {
            let report = check_schema_migration(&env, &plan(&env, 1, 2));
            assert_eq!(report.stored_version, STORAGE_SCHEMA_V1);
            assert_eq!(report.target_version, 2);
            assert_eq!(report.status, SchemaCompatibility::Compatible);
            assert!(!report.requires_approval);
            // Preflight is read-only.
            assert_eq!(get_storage_schema_version(&env), None);
        });
    }

    #[test]
    fn incompatible_plans_are_classified() {
        let (env, contract) = setup();
        env.as_contract(&contract, || {
            set_storage_schema_version(&env, STORAGE_SCHEMA_V1);
            let status = |p: MigrationPlan| check_schema_migration(&env, &p).status;

            assert_eq!(status(plan(&env, 1, 3)), SchemaCompatibility::NotNextVersion);
            assert_eq!(status(plan(&env, 1, 1)), SchemaCompatibility::InvalidPlan);
            assert_eq!(status(plan(&env, 0, 1)), SchemaCompatibility::AlreadyAtTarget);

            set_storage_schema_version(&env, CURRENT_STORAGE_SCHEMA_VERSION);
            // The next version is not readable by this build yet.
            assert_eq!(
                status(plan(&env, CURRENT_STORAGE_SCHEMA_VERSION, CURRENT_STORAGE_SCHEMA_VERSION + 1)),
                SchemaCompatibility::TargetUnsupported
            );
            assert_eq!(status(plan(&env, 1, 3)), SchemaCompatibility::PlanSourceMismatch);

            set_storage_schema_version(&env, 99);
            assert_eq!(status(plan(&env, 99, 100)), SchemaCompatibility::SourceUnsupported);
        });
    }

    #[test]
    fn in_progress_journal_blocks_staging() {
        let (env, contract, _admin) = setup_admin();
        env.as_contract(&contract, || {
            let p = plan(&env, 1, 2);
            begin_migration(&env, &p, 1).unwrap();
            assert_eq!(
                check_schema_migration(&env, &p).status,
                SchemaCompatibility::MigrationInProgress
            );
        });
    }

    #[test]
    fn commit_requires_completed_journal_for_the_same_plan() {
        let (env, contract, admin) = setup_admin();
        env.as_contract(&contract, || {
            let p = plan(&env, 1, 2);
            set_storage_schema_version(&env, STORAGE_SCHEMA_V1);

            assert_eq!(commit_schema_migration(&env, &admin, &p), Err(Error::NotFound));

            begin_migration(&env, &p, 1).unwrap();
            assert_eq!(
                commit_schema_migration(&env, &admin, &p),
                Err(Error::InvalidTransition)
            );
            assert_eq!(get_storage_schema_version(&env), Some(STORAGE_SCHEMA_V1));
        });
    }

    #[test]
    fn failed_post_check_never_stamps_the_new_version() {
        let (env, contract, admin) = setup_admin();
        env.as_contract(&contract, || {
            let p = plan(&env, 1, 2);
            set_storage_schema_version(&env, STORAGE_SCHEMA_V1);
            run_journal(&env, &p, false);

            assert_eq!(
                commit_schema_migration(&env, &admin, &p),
                Err(Error::InvalidTransition)
            );
            assert_eq!(get_storage_schema_version(&env), Some(STORAGE_SCHEMA_V1));
        });
    }

    #[test]
    fn commit_stamps_next_version_and_retry_is_idempotent() {
        let (env, contract, admin) = setup_admin();
        env.as_contract(&contract, || {
            let p = plan(&env, 1, 2);
            set_storage_schema_version(&env, STORAGE_SCHEMA_V1);
            run_journal(&env, &p, true);

            assert_eq!(commit_schema_migration(&env, &admin, &p), Ok(2));
            assert_eq!(get_storage_schema_version(&env), Some(2));

            // Resubmitting the same commit succeeds without another write.
            assert_eq!(commit_schema_migration(&env, &admin, &p), Ok(2));
            assert_eq!(
                check_schema_migration(&env, &p).status,
                SchemaCompatibility::AlreadyAtTarget
            );
        });
    }

    #[test]
    fn commit_rejects_unauthorized_and_mismatched_journal() {
        let (env, contract, admin) = setup_admin();
        env.as_contract(&contract, || {
            let p = plan(&env, 1, 2);
            set_storage_schema_version(&env, STORAGE_SCHEMA_V1);
            // A completed journal for a different plan does not authorize this one.
            run_journal(&env, &plan(&env, 0, 1), true);
            assert_eq!(
                commit_schema_migration(&env, &admin, &p),
                Err(Error::InvalidTransition)
            );

            let intruder = soroban_sdk::Address::generate(&env);
            assert_eq!(
                commit_schema_migration(&env, &intruder, &p),
                Err(Error::Unauthorized)
            );
            assert_eq!(get_storage_schema_version(&env), Some(STORAGE_SCHEMA_V1));

            // A build cannot commit a version it cannot read.
            set_storage_schema_version(&env, CURRENT_STORAGE_SCHEMA_VERSION);
            let next = plan(&env, CURRENT_STORAGE_SCHEMA_VERSION, CURRENT_STORAGE_SCHEMA_VERSION + 1);
            assert_eq!(
                commit_schema_migration(&env, &admin, &next),
                Err(Error::UnsupportedSchemaVersion)
            );
            assert_eq!(
                get_storage_schema_version(&env),
                Some(CURRENT_STORAGE_SCHEMA_VERSION)
            );
        });
    }
}

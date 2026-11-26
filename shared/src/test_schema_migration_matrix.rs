//! Schema migration compatibility matrix (Issue #470).
//!
//! Every row of the fixtures in `fixtures/schema_migration_matrix/` is one cell
//! of the matrix: a stored state, an operation, and the outcome this build must
//! produce. The tests below replay each row against the real code, so the
//! fixtures, `docs/SCHEMA_MIGRATION_MATRIX.md`, and the code cannot drift apart
//! silently.
//!
//! - `storage_read.csv`: the three storage read guards for every stored version.
//! - `schema_migration.csv`: `check_schema_migration` and `commit_schema_migration`
//!   across stored version x plan x journal state x caller.
//! - `record_read.csv`: `shared::compat` read, downgrade and write paths for each
//!   record envelope and version.
//!
//! The lifecycle tests at the bottom walk the normal, failure, retry and
//! authorization paths end to end with the real journal functions.

use soroban_sdk::{
    contract, contractimpl, symbol_short, testutils::Address as _, Address, Env, String, Vec,
};

use crate::auth::set_admin;
use crate::compat::{
    downgrade_v2_to_v1, from_latest, to_latest, CompatAidStatus, CurrentAidRecord, LegacyAidRecord,
    VersionedAidRecord, CURRENT_RECORD_SCHEMA_VERSION,
};
use crate::errors::Error;
use crate::migration::{
    begin_migration, fail_migration, finish_migration, load_journal, mark_step_complete,
    save_journal, MigrationError, MigrationJournal, MigrationPlan, MigrationStatus, MigrationStep,
    MigrationStepKind, PostCheck, RollbackStrategy,
};
use crate::storage_version::{
    check_schema_migration, commit_schema_migration, ensure_storage_schema_version,
    get_storage_schema_version, guard_storage_read, set_storage_schema_version,
    validate_storage_schema_read, SchemaCompatibility, CURRENT_STORAGE_SCHEMA_VERSION,
    MAX_SUPPORTED_STORAGE_SCHEMA_VERSION, MIN_SUPPORTED_STORAGE_SCHEMA_VERSION,
};

const STORAGE_READ: &str = include_str!("../../fixtures/schema_migration_matrix/storage_read.csv");
const SCHEMA_MIGRATION: &str =
    include_str!("../../fixtures/schema_migration_matrix/schema_migration.csv");
const RECORD_READ: &str = include_str!("../../fixtures/schema_migration_matrix/record_read.csv");

/// Storage schema versions the fixtures were written for. When a build changes
/// these, `matrix_matches_this_builds_supported_versions` fails until the
/// fixtures are updated (see `fixtures/schema_migration_matrix/README.md`).
const MATRIX_MIN_STORAGE_VERSION: u32 = 1;
const MATRIX_MAX_STORAGE_VERSION: u32 = 2;
/// Record schema version the fixtures were written for.
const MATRIX_RECORD_VERSION: u32 = 2;

/// Every `check_schema_migration` outcome; the matrix must cover each one.
const ALL_OUTCOMES: [SchemaCompatibility; 8] = [
    SchemaCompatibility::Compatible,
    SchemaCompatibility::AlreadyAtTarget,
    SchemaCompatibility::SourceUnsupported,
    SchemaCompatibility::InvalidPlan,
    SchemaCompatibility::PlanSourceMismatch,
    SchemaCompatibility::NotNextVersion,
    SchemaCompatibility::TargetUnsupported,
    SchemaCompatibility::MigrationInProgress,
];

#[contract]
struct SchemaMatrixTestContract;

#[contractimpl]
impl SchemaMatrixTestContract {}

// ---------------------------------------------------------------------------
// Fixture parsing (no_std: plain `str` splitting, no allocation)
// ---------------------------------------------------------------------------

/// Splits one data row into exactly `N` trimmed cells.
fn cells<const N: usize>(line: &'static str) -> [&'static str; N] {
    let mut out = [""; N];
    let mut parts = line.split(',');
    for cell in out.iter_mut() {
        *cell = parts
            .next()
            .unwrap_or_else(|| panic!("fixture row has too few columns: {line}"))
            .trim();
    }
    assert!(
        parts.next().is_none(),
        "fixture row has too many columns: {line}"
    );
    out
}

/// Data rows of a fixture, skipping blank lines, `#` comments and the header.
fn rows<const N: usize>(fixture: &'static str) -> impl Iterator<Item = [&'static str; N]> {
    fixture
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with("id,"))
        .map(cells::<N>)
}

fn number(cell: &str) -> u32 {
    cell.parse()
        .unwrap_or_else(|_| panic!("expected a u32 in fixture, got {cell:?}"))
}

/// `missing` means no `stor_ver` entry at all.
fn version(cell: &str) -> Option<u32> {
    if cell == "missing" {
        None
    } else {
        Some(number(cell))
    }
}

fn error(name: &str) -> Error {
    match name {
        "Unauthorized" => Error::Unauthorized,
        "NotFound" => Error::NotFound,
        "InvalidArgument" => Error::InvalidArgument,
        "InvalidTransition" => Error::InvalidTransition,
        "UnsupportedSchemaVersion" => Error::UnsupportedSchemaVersion,
        "SchemaMigrationFailed" => Error::SchemaMigrationFailed,
        other => panic!("unknown error name in fixture: {other:?}"),
    }
}

/// `ok:<n>` or an error name.
fn expected_version(cell: &str) -> Result<u32, Error> {
    match cell.strip_prefix("ok:") {
        Some(value) => Ok(number(value)),
        None => Err(error(cell)),
    }
}

/// `ok` or an error name.
fn expected_outcome(cell: &str) -> Result<(), Error> {
    if cell == "ok" {
        Ok(())
    } else {
        Err(error(cell))
    }
}

fn compatibility(name: &str) -> SchemaCompatibility {
    match name {
        "Compatible" => SchemaCompatibility::Compatible,
        "AlreadyAtTarget" => SchemaCompatibility::AlreadyAtTarget,
        "SourceUnsupported" => SchemaCompatibility::SourceUnsupported,
        "InvalidPlan" => SchemaCompatibility::InvalidPlan,
        "PlanSourceMismatch" => SchemaCompatibility::PlanSourceMismatch,
        "NotNextVersion" => SchemaCompatibility::NotNextVersion,
        "TargetUnsupported" => SchemaCompatibility::TargetUnsupported,
        "MigrationInProgress" => SchemaCompatibility::MigrationInProgress,
        other => panic!("unknown SchemaCompatibility in fixture: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Test setup
// ---------------------------------------------------------------------------

/// A fresh contract with an admin, so each matrix row starts from clean storage.
fn setup() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract = env.register_contract(None, SchemaMatrixTestContract);
    let admin = Address::generate(&env);
    env.as_contract(&contract, || set_admin(&env, &admin));
    (env, contract, admin)
}

fn plan(env: &Env, from_version: u32, to_version: u32, steps: u32) -> MigrationPlan {
    let mut list = Vec::new(env);
    for id in 1..=steps {
        list.push_back(MigrationStep {
            id,
            name: symbol_short!("remap"),
            kind: MigrationStepKind::Storage,
            affected_records: 1,
            destructive: false,
        });
    }
    MigrationPlan {
        from_version,
        to_version,
        steps: list,
        rollback: RollbackStrategy::Revert,
        rollback_notes: String::from_str(env, "redeploy the previous WASM; stor_ver is unchanged"),
    }
}

/// Writes the journal state a matrix row names, as a previous run would have left it.
fn seed_journal(env: &Env, state: &str, plan: &MigrationPlan) {
    let (status, to_version) = match state {
        "none" => return,
        "in_progress" => (MigrationStatus::InProgress, plan.to_version),
        "failed" => (MigrationStatus::Failed, plan.to_version),
        "completed" => (MigrationStatus::Completed, plan.to_version),
        "completed_other" => (MigrationStatus::Completed, plan.to_version + 1),
        other => panic!("unknown journal state in fixture: {other:?}"),
    };
    let completed_steps = if status == MigrationStatus::Completed {
        plan.steps.len()
    } else {
        0
    };
    save_journal(
        env,
        &MigrationJournal {
            status,
            from_version: plan.from_version,
            to_version,
            completed_steps,
            total_steps: plan.steps.len(),
            started_at: 0,
            updated_at: 0,
            failed_step: None,
            last_error: 0,
        },
    );
}

fn post_checks(env: &Env, passed: bool) -> Vec<PostCheck> {
    let mut checks = Vec::new(env);
    checks.push_back(PostCheck {
        id: symbol_short!("rowcount"),
        passed,
    });
    checks
}

// ---------------------------------------------------------------------------
// Matrix tests
// ---------------------------------------------------------------------------

#[test]
fn matrix_matches_this_builds_supported_versions() {
    assert_eq!(
        (
            MIN_SUPPORTED_STORAGE_SCHEMA_VERSION,
            MAX_SUPPORTED_STORAGE_SCHEMA_VERSION
        ),
        (MATRIX_MIN_STORAGE_VERSION, MATRIX_MAX_STORAGE_VERSION),
        "the supported storage schema range changed: update fixtures/schema_migration_matrix/"
    );
    assert_eq!(CURRENT_STORAGE_SCHEMA_VERSION, MATRIX_MAX_STORAGE_VERSION);
    assert_eq!(
        CURRENT_RECORD_SCHEMA_VERSION, MATRIX_RECORD_VERSION,
        "the record schema version changed: update fixtures/schema_migration_matrix/record_read.csv"
    );
}

#[test]
fn storage_read_matrix() {
    let mut count = 0;
    for [id, stored, policy, expect] in rows::<4>(STORAGE_READ) {
        count += 1;
        let (env, contract, _admin) = setup();
        env.as_contract(&contract, || {
            if let Some(v) = version(stored) {
                set_storage_schema_version(&env, v);
            }
            let actual = match policy {
                "strict" => guard_storage_read(&env),
                "legacy" => validate_storage_schema_read(&env, true),
                "ensure" => ensure_storage_schema_version(&env),
                other => panic!("{id}: unknown read policy {other:?}"),
            };
            assert_eq!(
                actual,
                expected_version(expect),
                "{id}: {policy} read with stored version {stored}"
            );
            assert_eq!(
                get_storage_schema_version(&env),
                version(stored),
                "{id}: a read guard must never stamp a version"
            );
        });
    }
    assert!(count > 0, "storage_read.csv has no data rows");
}

#[test]
fn schema_migration_matrix() {
    let mut covered = [false; ALL_OUTCOMES.len()];
    for [id, stored, from, to, steps, journal, caller, check, commit, stored_after] in
        rows::<10>(SCHEMA_MIGRATION)
    {
        let (env, contract, admin) = setup();
        let stranger = Address::generate(&env);
        env.as_contract(&contract, || {
            if let Some(v) = version(stored) {
                set_storage_schema_version(&env, v);
            }
            let plan = plan(&env, number(from), number(to), number(steps));
            seed_journal(&env, journal, &plan);
            let caller = match caller {
                "admin" => admin.clone(),
                "stranger" => stranger.clone(),
                other => panic!("{id}: unknown caller {other:?}"),
            };

            // The preview is read-only.
            let expected_status = compatibility(check);
            assert_eq!(
                check_schema_migration(&env, &plan).status,
                expected_status,
                "{id}: check_schema_migration"
            );
            assert_eq!(
                get_storage_schema_version(&env),
                version(stored),
                "{id}: check_schema_migration must not write"
            );
            let index = ALL_OUTCOMES
                .iter()
                .position(|outcome| *outcome == expected_status)
                .unwrap_or_else(|| panic!("{id}: outcome missing from ALL_OUTCOMES"));
            covered[index] = true;

            // The commit stamps a version only on success and never edits the journal.
            let journal_before = load_journal(&env);
            assert_eq!(
                commit_schema_migration(&env, &caller, &plan),
                expected_version(commit),
                "{id}: commit_schema_migration"
            );
            assert_eq!(
                get_storage_schema_version(&env),
                version(stored_after),
                "{id}: stored version after commit"
            );
            assert_eq!(
                load_journal(&env),
                journal_before,
                "{id}: commit_schema_migration must not modify the journal"
            );
        });
    }
    for (outcome, seen) in ALL_OUTCOMES.iter().zip(covered) {
        assert!(seen, "no row in schema_migration.csv covers {outcome:?}");
    }
}

#[test]
fn record_read_matrix() {
    let mut count = 0;
    for [id, envelope, schema_version, amount, latest_cell, downgrade_cell, write_cell] in
        rows::<7>(RECORD_READ)
    {
        count += 1;
        let env = Env::default();
        let donor = Address::generate(&env);
        let recipient = Address::generate(&env);
        let token = Address::generate(&env);
        let amount: i128 = amount
            .parse()
            .unwrap_or_else(|_| panic!("{id}: bad amount {amount:?}"));

        let record = match envelope {
            "V1" => VersionedAidRecord::V1(LegacyAidRecord {
                id: 1,
                donor,
                recipient,
                amount,
                expiry_ledger: 1_000,
                status: CompatAidStatus::Pending,
            }),
            "V2" => VersionedAidRecord::V2(CurrentAidRecord {
                id: 1,
                donor,
                recipient,
                token,
                amount,
                expiry_ledger: 1_000,
                status: CompatAidStatus::Pending,
                schema_version: number(schema_version),
            }),
            other => panic!("{id}: unknown envelope {other:?}"),
        };

        let latest = to_latest(&env, &record);
        assert_eq!(
            latest.clone().map(|_| ()),
            expected_outcome(latest_cell),
            "{id}: to_latest"
        );
        if let Ok(latest) = &latest {
            assert_eq!(latest.schema_version, CURRENT_RECORD_SCHEMA_VERSION, "{id}");
            assert_eq!(latest.amount, amount, "{id}: amount must be preserved");
            if let VersionedAidRecord::V2(current) = &record {
                assert_eq!(
                    latest, current,
                    "{id}: a current record reads back unchanged"
                );
            }
        }

        if let VersionedAidRecord::V2(current) = &record {
            assert_eq!(
                downgrade_v2_to_v1(current).map(|_| ()),
                expected_outcome(downgrade_cell),
                "{id}: downgrade_v2_to_v1"
            );
            assert_eq!(
                from_latest(current).map(|_| ()),
                expected_outcome(write_cell),
                "{id}: from_latest"
            );
        } else {
            assert_eq!(
                (downgrade_cell, write_cell),
                ("-", "-"),
                "{id}: V1 rows have no downgrade or write path"
            );
        }
    }
    assert!(count > 0, "record_read.csv has no data rows");
}

// ---------------------------------------------------------------------------
// Lifecycle: normal, failure, retry, rollback and authorization paths
// ---------------------------------------------------------------------------

#[test]
fn failed_run_keeps_the_old_version_and_a_retry_completes() {
    let (env, contract, admin) = setup();
    env.as_contract(&contract, || {
        set_storage_schema_version(&env, 1);
        let plan = plan(&env, 1, 2, 2);

        // First attempt fails after one step.
        begin_migration(&env, &plan, 10).unwrap();
        mark_step_complete(&env, &plan, 1, 11).unwrap();
        fail_migration(&env, &symbol_short!("remap"), 42, 12).unwrap();

        // Rollback: nothing was stamped, so readers stay on V1 and the plan is still valid.
        assert_eq!(
            commit_schema_migration(&env, &admin, &plan),
            Err(Error::InvalidTransition)
        );
        assert_eq!(guard_storage_read(&env), Ok(1));
        assert_eq!(
            check_schema_migration(&env, &plan).status,
            SchemaCompatibility::Compatible
        );

        // Retry starts again from the first step.
        let journal = begin_migration(&env, &plan, 20).unwrap();
        assert_eq!(journal.completed_steps, 0);
        mark_step_complete(&env, &plan, 1, 21).unwrap();

        // While it runs, the preview reports it and the commit refuses.
        assert_eq!(
            check_schema_migration(&env, &plan).status,
            SchemaCompatibility::MigrationInProgress
        );
        assert_eq!(
            commit_schema_migration(&env, &admin, &plan),
            Err(Error::InvalidTransition)
        );

        mark_step_complete(&env, &plan, 2, 22).unwrap();
        finish_migration(&env, &post_checks(&env, true), 23).unwrap();

        assert_eq!(commit_schema_migration(&env, &admin, &plan), Ok(2));
        assert_eq!(guard_storage_read(&env), Ok(2));

        // Resubmitting the commit is harmless.
        assert_eq!(commit_schema_migration(&env, &admin, &plan), Ok(2));
        assert_eq!(get_storage_schema_version(&env), Some(2));
        assert_eq!(
            check_schema_migration(&env, &plan).status,
            SchemaCompatibility::AlreadyAtTarget
        );
    });
}

#[test]
fn a_failing_post_check_blocks_the_version_stamp() {
    let (env, contract, admin) = setup();
    env.as_contract(&contract, || {
        set_storage_schema_version(&env, 1);
        let plan = plan(&env, 1, 2, 1);
        begin_migration(&env, &plan, 10).unwrap();
        mark_step_complete(&env, &plan, 1, 11).unwrap();

        assert_eq!(
            finish_migration(&env, &post_checks(&env, false), 12),
            Err(MigrationError::PostCheckFailed)
        );
        let journal = load_journal(&env).unwrap();
        assert_eq!(journal.status, MigrationStatus::Failed);
        assert_eq!(journal.failed_step, Some(symbol_short!("rowcount")));

        assert_eq!(
            commit_schema_migration(&env, &admin, &plan),
            Err(Error::InvalidTransition)
        );
        assert_eq!(get_storage_schema_version(&env), Some(1));
    });
}

#[test]
fn only_the_admin_can_commit_and_a_refused_attempt_changes_nothing() {
    let (env, contract, admin) = setup();
    let stranger = Address::generate(&env);
    env.as_contract(&contract, || {
        let plan = plan(&env, 1, 2, 1);
        begin_migration(&env, &plan, 10).unwrap();
        mark_step_complete(&env, &plan, 1, 11).unwrap();
        finish_migration(&env, &post_checks(&env, true), 12).unwrap();

        assert_eq!(
            commit_schema_migration(&env, &stranger, &plan),
            Err(Error::Unauthorized)
        );
        assert_eq!(get_storage_schema_version(&env), None);

        // The completed journal is still there, so the admin can commit afterwards.
        assert_eq!(commit_schema_migration(&env, &admin, &plan), Ok(2));
        assert_eq!(get_storage_schema_version(&env), Some(2));
    });
}

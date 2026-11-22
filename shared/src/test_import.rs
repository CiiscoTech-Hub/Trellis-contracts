#![cfg(test)]

extern crate std;

use soroban_sdk::{
    contract, contractimpl, symbol_short,
    testutils::{Address as _, Ledger as _},
    Address, Bytes, Env, Vec,
};

use crate::import::{
    cancel_import, compute_batch_fingerprint, dry_run, execute_import, get_import_counter, get_imported_record,
    has_imported_record, DuplicatePolicy, ImportConfig, ImportError, ImportItem, ImportMode,
    is_import_cancelled, RollbackStrategy, ABSOLUTE_MAX_IMPORT_SIZE,
};

#[contract]
pub struct DummyImportContract;

#[contractimpl]
impl DummyImportContract {
    pub fn noop(_env: Env) {}
}

struct Ctx {
    env: Env,
    contract_id: Address,
    admin: Address,
    alice: Address,
    bob: Address,
}

impl Ctx {
    fn run<T>(&self, f: impl FnOnce() -> T) -> T {
        self.env.as_contract(&self.contract_id, f)
    }
}

fn setup() -> Ctx {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);

    let contract_id = env.register_contract(None, DummyImportContract);
    let admin = Address::generate(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    Ctx {
        env,
        contract_id,
        admin,
        alice,
        bob,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn dry_run_performs_no_persistent_writes() {
    let ctx = setup();
    ctx.run(|| {
        let mut items: Vec<ImportItem> = Vec::new(&ctx.env);
        let ext_1 = Bytes::from_slice(&ctx.env, b"DONOR-EXT-001");
        let ext_2 = Bytes::from_slice(&ctx.env, b"DONOR-EXT-002");

        items.push_back(ImportItem {
            row_id: 0,
            external_id: Some(ext_1.clone()),
            recipient: ctx.alice.clone(),
            amount: 500,
            expiry: 2_000,
            metadata_hash: None,
        });
        items.push_back(ImportItem {
            row_id: 1,
            external_id: Some(ext_2.clone()),
            recipient: ctx.bob.clone(),
            amount: 1_000,
            expiry: 3_000,
            metadata_hash: None,
        });

        let config = ImportConfig {
            dry_run: true,
            mode: ImportMode::AllOrNothing,
            duplicate_policy: DuplicatePolicy::SkipExisting,
            max_rows: 50,
        };

        let report = dry_run(&ctx.env, &items, &config).expect("dry run should succeed");

        assert!(report.is_dry_run);
        assert_eq!(report.total_rows, 2);
        assert_eq!(report.create_count, 2);
        assert_eq!(report.update_count, 0);
        assert_eq!(report.skip_count, 0);
        assert_eq!(report.error_count, 0);
        assert_eq!(report.errors.len(), 0);

        // Verification of Acceptance Criteria: Zero persistent writes during dry run
        assert!(!has_imported_record(&ctx.env, &ext_1));
        assert!(!has_imported_record(&ctx.env, &ext_2));
        assert_eq!(get_imported_record(&ctx.env, &ext_1), None);
        assert_eq!(get_imported_record(&ctx.env, &ext_2), None);
        assert_eq!(get_import_counter(&ctx.env), 0);
    });
}

#[test]
fn cancelled_import_is_rejected_before_commit() {
    let ctx = setup();
    ctx.run(|| {
        let mut items: Vec<ImportItem> = Vec::new(&ctx.env);
        items.push_back(ImportItem {
            row_id: 0,
            external_id: Some(Bytes::from_slice(&ctx.env, b"CANCEL-ME")),
            recipient: ctx.alice.clone(),
            amount: 10,
            expiry: 2_000,
            metadata_hash: None,
        });
        let fingerprint = compute_batch_fingerprint(&ctx.env, &items);
        cancel_import(&ctx.env, &ctx.admin, &fingerprint).unwrap();
        assert!(is_import_cancelled(&ctx.env, &fingerprint));
        let config = ImportConfig {
            dry_run: false,
            mode: ImportMode::AllOrNothing,
            duplicate_policy: DuplicatePolicy::SkipExisting,
            max_rows: 10,
        };
        assert_eq!(execute_import(&ctx.env, &ctx.admin, &items, &config), Err(ImportError::ImportCancelled));
        assert_eq!(get_import_counter(&ctx.env), 0);
    });
}

#[test]
fn repeated_imports_are_idempotent_with_external_ids() {
    let ctx = setup();
    ctx.run(|| {
        let mut items: Vec<ImportItem> = Vec::new(&ctx.env);
        let ext_id = Bytes::from_slice(&ctx.env, b"BENEFICIARY-ROSTER-99");

        items.push_back(ImportItem {
            row_id: 0,
            external_id: Some(ext_id.clone()),
            recipient: ctx.alice.clone(),
            amount: 250,
            expiry: 5_000,
            metadata_hash: None,
        });

        let config = ImportConfig {
            dry_run: false,
            mode: ImportMode::AllOrNothing,
            duplicate_policy: DuplicatePolicy::SkipExisting,
            max_rows: 50,
        };

        // First execution: commits record
        let report1 = execute_import(&ctx.env, &ctx.admin, &items, &config).unwrap();
        assert!(!report1.is_dry_run);
        assert_eq!(report1.create_count, 1);
        assert_eq!(report1.skip_count, 0);
        assert_eq!(report1.error_count, 0);

        assert!(has_imported_record(&ctx.env, &ext_id));
        let record = get_imported_record(&ctx.env, &ext_id).unwrap();
        assert_eq!(record.amount, 250);
        assert_eq!(record.recipient, ctx.alice);
        assert_eq!(get_import_counter(&ctx.env), 1);

        // Second execution: idempotent re-run with same external ID
        let report2 = execute_import(&ctx.env, &ctx.admin, &items, &config).unwrap();
        assert_eq!(report2.create_count, 0);
        assert_eq!(report2.skip_count, 1);
        assert_eq!(report2.update_count, 0);
        assert_eq!(report2.error_count, 0);

        // Counter must not increment; record remains unchanged
        assert_eq!(get_import_counter(&ctx.env), 1);
        let record_after = get_imported_record(&ctx.env, &ext_id).unwrap();
        assert_eq!(record_after.amount, 250);
    });
}

#[test]
fn update_existing_policy_updates_record_data() {
    let ctx = setup();
    ctx.run(|| {
        let ext_id = Bytes::from_slice(&ctx.env, b"EXT-UPDATE-1");

        let mut items1: Vec<ImportItem> = Vec::new(&ctx.env);
        items1.push_back(ImportItem {
            row_id: 0,
            external_id: Some(ext_id.clone()),
            recipient: ctx.alice.clone(),
            amount: 100,
            expiry: 2_000,
            metadata_hash: None,
        });

        let config_update = ImportConfig {
            dry_run: false,
            mode: ImportMode::AllOrNothing,
            duplicate_policy: DuplicatePolicy::UpdateExisting,
            max_rows: 50,
        };

        // Initial create
        let r1 = execute_import(&ctx.env, &ctx.admin, &items1, &config_update).unwrap();
        assert_eq!(r1.create_count, 1);
        assert_eq!(r1.update_count, 0);

        // Update with modified amount and expiry
        let mut items2: Vec<ImportItem> = Vec::new(&ctx.env);
        items2.push_back(ImportItem {
            row_id: 0,
            external_id: Some(ext_id.clone()),
            recipient: ctx.bob.clone(),
            amount: 750,
            expiry: 8_000,
            metadata_hash: None,
        });

        let r2 = execute_import(&ctx.env, &ctx.admin, &items2, &config_update).unwrap();
        assert_eq!(r2.create_count, 0);
        assert_eq!(r2.update_count, 1);
        assert_eq!(r2.skip_count, 0);

        let stored = get_imported_record(&ctx.env, &ext_id).unwrap();
        assert_eq!(stored.recipient, ctx.bob);
        assert_eq!(stored.amount, 750);
        assert_eq!(stored.expiry, 8_000);
    });
}

#[test]
fn invalid_rows_validation_and_diagnostics() {
    let ctx = setup();
    ctx.run(|| {
        let mut items: Vec<ImportItem> = Vec::new(&ctx.env);

        // Row 0: zero amount
        items.push_back(ImportItem {
            row_id: 0,
            external_id: Some(Bytes::from_slice(&ctx.env, b"ROW-0")),
            recipient: ctx.alice.clone(),
            amount: 0,
            expiry: 5_000,
            metadata_hash: None,
        });

        // Row 1: expired
        items.push_back(ImportItem {
            row_id: 1,
            external_id: Some(Bytes::from_slice(&ctx.env, b"ROW-1")),
            recipient: ctx.bob.clone(),
            amount: 100,
            expiry: 500, // current timestamp is 1_000
            metadata_hash: None,
        });

        // Row 2: valid
        items.push_back(ImportItem {
            row_id: 2,
            external_id: Some(Bytes::from_slice(&ctx.env, b"ROW-2")),
            recipient: ctx.alice.clone(),
            amount: 200,
            expiry: 5_000,
            metadata_hash: None,
        });

        let config = ImportConfig {
            dry_run: true,
            mode: ImportMode::AllOrNothing,
            duplicate_policy: DuplicatePolicy::SkipExisting,
            max_rows: 50,
        };

        let report = dry_run(&ctx.env, &items, &config).unwrap();
        assert_eq!(report.total_rows, 3);
        assert_eq!(report.create_count, 1);
        assert_eq!(report.error_count, 2);
        assert_eq!(report.errors.len(), 2);

        let err0 = report.errors.get(0).unwrap();
        assert_eq!(err0.row_id, 0);
        assert_eq!(err0.reason, symbol_short!("zero_amt"));

        let err1 = report.errors.get(1).unwrap();
        assert_eq!(err1.row_id, 1);
        assert_eq!(err1.reason, symbol_short!("expired"));

        // Rollback guidance indicates forward fix on rows
        assert_eq!(report.rollback_guidance.strategy, RollbackStrategy::ForwardFix);
        assert_eq!(report.rollback_guidance.action, symbol_short!("fix_rows"));
        assert_eq!(report.rollback_guidance.affected_records, 2);
    });
}

#[test]
fn reject_duplicate_policy_catches_intra_batch_and_storage_duplicates() {
    let ctx = setup();
    ctx.run(|| {
        let dup_id = Bytes::from_slice(&ctx.env, b"DUP-ID-TEST");

        let mut items: Vec<ImportItem> = Vec::new(&ctx.env);
        items.push_back(ImportItem {
            row_id: 0,
            external_id: Some(dup_id.clone()),
            recipient: ctx.alice.clone(),
            amount: 100,
            expiry: 5_000,
            metadata_hash: None,
        });
        items.push_back(ImportItem {
            row_id: 1,
            external_id: Some(dup_id.clone()), // intra-batch duplicate
            recipient: ctx.bob.clone(),
            amount: 200,
            expiry: 5_000,
            metadata_hash: None,
        });

        let config = ImportConfig {
            dry_run: true,
            mode: ImportMode::AllOrNothing,
            duplicate_policy: DuplicatePolicy::RejectDuplicate,
            max_rows: 50,
        };

        let report = dry_run(&ctx.env, &items, &config).unwrap();
        assert_eq!(report.create_count, 1);
        assert_eq!(report.error_count, 1);

        let err = report.errors.get(0).unwrap();
        assert_eq!(err.row_id, 1);
        assert_eq!(err.reason, symbol_short!("dup_batch"));
        assert_eq!(err.error_code, ImportError::DuplicateExternalId as u32);
    });
}

#[test]
fn all_or_nothing_mode_aborts_and_makes_no_writes_on_invalid_row() {
    let ctx = setup();
    ctx.run(|| {
        let valid_ext = Bytes::from_slice(&ctx.env, b"VALID-ROW-1");
        let invalid_ext = Bytes::from_slice(&ctx.env, b"INVALID-ROW-2");

        let mut items: Vec<ImportItem> = Vec::new(&ctx.env);
        items.push_back(ImportItem {
            row_id: 0,
            external_id: Some(valid_ext.clone()),
            recipient: ctx.alice.clone(),
            amount: 100,
            expiry: 5_000,
            metadata_hash: None,
        });
        items.push_back(ImportItem {
            row_id: 1,
            external_id: Some(invalid_ext.clone()),
            recipient: ctx.bob.clone(),
            amount: -10, // Invalid
            expiry: 5_000,
            metadata_hash: None,
        });

        let config = ImportConfig {
            dry_run: false,
            mode: ImportMode::AllOrNothing,
            duplicate_policy: DuplicatePolicy::SkipExisting,
            max_rows: 50,
        };

        let res = execute_import(&ctx.env, &ctx.admin, &items, &config);
        assert_eq!(res, Err(ImportError::InvalidRow));

        // Atomic guarantee: valid row was NOT written to storage
        assert!(!has_imported_record(&ctx.env, &valid_ext));
        assert_eq!(get_import_counter(&ctx.env), 0);
    });
}

#[test]
fn best_effort_mode_processes_valid_rows_and_records_partial_failures() {
    let ctx = setup();
    ctx.run(|| {
        let ext_good_1 = Bytes::from_slice(&ctx.env, b"GOOD-1");
        let ext_bad = Bytes::from_slice(&ctx.env, b"BAD-1");
        let ext_good_2 = Bytes::from_slice(&ctx.env, b"GOOD-2");

        let mut items: Vec<ImportItem> = Vec::new(&ctx.env);
        items.push_back(ImportItem {
            row_id: 0,
            external_id: Some(ext_good_1.clone()),
            recipient: ctx.alice.clone(),
            amount: 150,
            expiry: 3_000,
            metadata_hash: None,
        });
        items.push_back(ImportItem {
            row_id: 1,
            external_id: Some(ext_bad.clone()),
            recipient: ctx.bob.clone(),
            amount: 0, // Invalid amount
            expiry: 3_000,
            metadata_hash: None,
        });
        items.push_back(ImportItem {
            row_id: 2,
            external_id: Some(ext_good_2.clone()),
            recipient: ctx.alice.clone(),
            amount: 300,
            expiry: 4_000,
            metadata_hash: None,
        });

        let config = ImportConfig {
            dry_run: false,
            mode: ImportMode::BestEffort,
            duplicate_policy: DuplicatePolicy::SkipExisting,
            max_rows: 50,
        };

        let report = execute_import(&ctx.env, &ctx.admin, &items, &config).unwrap();

        assert_eq!(report.total_rows, 3);
        assert_eq!(report.create_count, 2);
        assert_eq!(report.error_count, 1);
        assert_eq!(report.errors.len(), 1);

        // Good rows committed
        assert!(has_imported_record(&ctx.env, &ext_good_1));
        assert!(has_imported_record(&ctx.env, &ext_good_2));
        assert!(!has_imported_record(&ctx.env, &ext_bad));

        // Remediation guidance provided
        assert_eq!(report.rollback_guidance.strategy, RollbackStrategy::ForwardFix);
        assert_eq!(report.rollback_guidance.action, symbol_short!("part_fix"));
        assert_eq!(report.rollback_guidance.affected_records, 1);
        assert_eq!(report.rollback_guidance.runbook_code, symbol_short!("part_rem"));
    });
}

#[test]
fn config_and_batch_size_limits() {
    let ctx = setup();
    ctx.run(|| {
        let items: Vec<ImportItem> = Vec::new(&ctx.env);

        // 1. Zero max_rows config
        let bad_config = ImportConfig {
            dry_run: true,
            mode: ImportMode::AllOrNothing,
            duplicate_policy: DuplicatePolicy::SkipExisting,
            max_rows: 0,
        };
        assert_eq!(dry_run(&ctx.env, &items, &bad_config), Err(ImportError::InvalidConfig));

        // 2. max_rows exceeding ABSOLUTE_MAX_IMPORT_SIZE
        let huge_config = ImportConfig {
            dry_run: true,
            mode: ImportMode::AllOrNothing,
            duplicate_policy: DuplicatePolicy::SkipExisting,
            max_rows: ABSOLUTE_MAX_IMPORT_SIZE + 1,
        };
        assert_eq!(dry_run(&ctx.env, &items, &huge_config), Err(ImportError::InvalidConfig));

        // 3. Empty batch
        let valid_config = ImportConfig {
            dry_run: true,
            mode: ImportMode::AllOrNothing,
            duplicate_policy: DuplicatePolicy::SkipExisting,
            max_rows: 50,
        };
        assert_eq!(dry_run(&ctx.env, &items, &valid_config), Err(ImportError::EmptyBatch));
    });
}

#[test]
fn batch_fingerprint_is_deterministic() {
    let ctx = setup();
    ctx.run(|| {
        let mut items1: Vec<ImportItem> = Vec::new(&ctx.env);
        let mut items2: Vec<ImportItem> = Vec::new(&ctx.env);

        items1.push_back(ImportItem {
            row_id: 0,
            external_id: Some(Bytes::from_slice(&ctx.env, b"ROW-FP")),
            recipient: ctx.alice.clone(),
            amount: 100,
            expiry: 2_000,
            metadata_hash: None,
        });

        items2.push_back(ImportItem {
            row_id: 0,
            external_id: Some(Bytes::from_slice(&ctx.env, b"ROW-FP")),
            recipient: ctx.alice.clone(),
            amount: 100,
            expiry: 2_000,
            metadata_hash: None,
        });

        let fp1 = compute_batch_fingerprint(&ctx.env, &items1);
        let fp2 = compute_batch_fingerprint(&ctx.env, &items2);

        assert_eq!(fp1, fp2);
    });
}

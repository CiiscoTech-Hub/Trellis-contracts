//! Operator-safe backfill framework (Issue #217).
//!
//! Provides deterministic backfill execution, dry-run diff previewing,
//! resumable checkpoints, and rollback/recovery for Trellis Soroban contracts
//! across Treasury, Aid, Referral, Governance, Oracle, and Marketplace modules.
//!
//! ## Architecture
//!
//! - [`BackfillPlan`] — defines the target module, batch size, and execution mode.
//! - [`dry_run`] — pure function simulating record changes, reporting created,
//!   updated, skipped, and invalid records with zero storage mutations.
//! - [`BackfillCheckpoint`] — persisted progress record enabling safe resumption
//!   from interruptions without repeating side effects.
//! - [`dedupe_items`] — applies a [`BackfillDuplicatePolicy`] to repeated record
//!   ids before a batch is previewed or applied.
//! - [`advance_checkpoint`] / [`fail_backfill`] / [`complete_backfill`] — state
//!   transitions enforcing deterministic ordering and recovery.
//! - [`resume_backfill`] — continues an `InProgress` or `AwaitingRecovery`
//!   checkpoint from its stored cursor.

use soroban_sdk::{contracterror, contracttype, symbol_short, Env, String, Symbol, Vec};

use crate::storage::{instance_get, instance_remove, instance_set};

/// Storage key prefix for the active backfill checkpoint in instance storage.
const BACKFILL_CHECKPOINT_KEY: Symbol = symbol_short!("bf_chk");

/// Backfill orchestration errors (range 960–979).
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum BackfillError {
    /// The backfill plan is invalid (e.g. zero batch size or invalid module).
    InvalidPlan = 960,
    /// A backfill operation is already running for this contract.
    AlreadyInProgress = 961,
    /// Operation requested requires an in-progress backfill.
    NotInProgress = 962,
    /// Record was submitted out of order or diverges from plan.
    RecordOutOfOrder = 963,
    /// No backfill checkpoint was found.
    CheckpointNotFound = 964,
    /// Record payload validation failed.
    ValidationFailed = 965,
    /// Invariant check failed during backfill.
    InvariantViolation = 966,
    /// The checkpoint is in a terminal state and cannot be resumed.
    CannotResume = 967,
    /// A batch contains the same record id more than once and the policy rejects it.
    DuplicateRecord = 968,
    /// A checkpoint awaits recovery; it must be resumed, not replaced by a new run.
    ResumeRequired = 969,
}

/// Target contract module for backfill operations.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackfillModule {
    Treasury,
    Aid,
    Referral,
    Governance,
    Oracle,
    Marketplace,
}

impl BackfillModule {
    pub fn as_symbol(self) -> Symbol {
        match self {
            BackfillModule::Treasury => symbol_short!("treasury"),
            BackfillModule::Aid => symbol_short!("aid"),
            BackfillModule::Referral => symbol_short!("referral"),
            BackfillModule::Governance => symbol_short!("gov"),
            BackfillModule::Oracle => symbol_short!("oracle"),
            BackfillModule::Marketplace => symbol_short!("market"),
        }
    }
}

/// Backfill execution policy mode.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackfillMode {
    /// Atomic: Any error stops backfill immediately and requires operator recovery.
    AllOrNothing,
    /// Resilient: Invalid records are reported and skipped while valid records proceed.
    BestEffort,
}

/// How repeated record ids inside one batch are handled before dry-run or apply.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackfillDuplicatePolicy {
    /// Keep the first occurrence of an id and drop later duplicates.
    Skip,
    /// Keep the last occurrence of an id, at the position of its first occurrence.
    Update,
    /// Refuse the whole batch when any id appears more than once.
    Reject,
}

/// Lifecycle state of a backfill run.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackfillStatus {
    NotStarted,
    InProgress,
    AwaitingRecovery,
    Completed,
    Failed,
    RolledBack,
}

/// Action to be performed for a single record.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackfillAction {
    Create,
    Update,
    Skip,
    Delete,
}

/// A single backfill candidate record description.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackfillItem {
    pub id: u64,
    pub action: BackfillAction,
    pub is_valid: bool,
    pub is_destructive: bool,
    pub reason: Symbol,
}

/// Specification for a backfill operation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackfillPlan {
    pub module: BackfillModule,
    pub mode: BackfillMode,
    pub batch_size: u32,
    pub total_records: u32,
    pub rollback_notes: String,
}

impl BackfillPlan {
    pub fn validate(&self) -> Result<(), BackfillError> {
        if self.batch_size == 0 || self.batch_size > 100 {
            return Err(BackfillError::InvalidPlan);
        }
        Ok(())
    }
}

/// Preview report generated by dry-run simulation without mutating state.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackfillReport {
    pub total_scanned: u32,
    pub to_create: u32,
    pub to_update: u32,
    pub to_skip: u32,
    pub failed_count: u32,
    pub destructive_count: u32,
    pub can_proceed: bool,
}

/// Checkpoint structure persisted between batches for deterministic resume.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackfillCheckpoint {
    pub module: BackfillModule,
    pub status: BackfillStatus,
    pub cursor: u32,
    pub total_records: u32,
    pub created_count: u32,
    pub updated_count: u32,
    pub skipped_count: u32,
    pub failed_count: u32,
    pub started_at: u64,
    pub updated_at: u64,
    pub last_error: u32,
}

/// Simulates impact of proposed records without writing to storage.
pub fn dry_run(plan: &BackfillPlan, items: &Vec<BackfillItem>) -> Result<BackfillReport, BackfillError> {
    plan.validate()?;

    let mut to_create: u32 = 0;
    let mut to_update: u32 = 0;
    let mut to_skip: u32 = 0;
    let mut failed_count: u32 = 0;
    let mut destructive_count: u32 = 0;

    for item in items.iter() {
        if !item.is_valid {
            failed_count = failed_count.saturating_add(1);
            continue;
        }

        if item.is_destructive {
            destructive_count = destructive_count.saturating_add(1);
        }

        match item.action {
            BackfillAction::Create => to_create = to_create.saturating_add(1),
            BackfillAction::Update => to_update = to_update.saturating_add(1),
            BackfillAction::Skip => to_skip = to_skip.saturating_add(1),
            BackfillAction::Delete => destructive_count = destructive_count.saturating_add(1),
        }
    }

    let can_proceed = match plan.mode {
        BackfillMode::AllOrNothing => failed_count == 0,
        BackfillMode::BestEffort => true,
    };

    Ok(BackfillReport {
        total_scanned: items.len(),
        to_create,
        to_update,
        to_skip,
        failed_count,
        destructive_count,
        can_proceed,
    })
}

/// Loads active checkpoint if present.
pub fn load_checkpoint(env: &Env) -> Option<BackfillCheckpoint> {
    instance_get(env, &BACKFILL_CHECKPOINT_KEY)
}

/// Persists active checkpoint.
pub fn save_checkpoint(env: &Env, checkpoint: &BackfillCheckpoint) {
    instance_set(env, &BACKFILL_CHECKPOINT_KEY, checkpoint);
}

/// Clears checkpoint once finished or abandoned.
pub fn clear_checkpoint(env: &Env) {
    instance_remove(env, &BACKFILL_CHECKPOINT_KEY);
}

/// Collapses repeated record ids according to `policy`.
///
/// Records are compared by [`BackfillItem::id`]. The first occurrence fixes the
/// output position of each id, so the result is deterministic for a given input
/// order. Under [`BackfillDuplicatePolicy::Reject`] the whole batch is refused
/// with [`BackfillError::DuplicateRecord`] and no partial result is returned.
pub fn dedupe_items(
    env: &Env,
    items: &Vec<BackfillItem>,
    policy: BackfillDuplicatePolicy,
) -> Result<Vec<BackfillItem>, BackfillError> {
    let mut deduped: Vec<BackfillItem> = Vec::new(env);

    for item in items.iter() {
        let mut existing: Option<u32> = None;
        for index in 0..deduped.len() {
            if deduped.get(index).map_or(false, |seen| seen.id == item.id) {
                existing = Some(index);
                break;
            }
        }

        match (existing, policy) {
            (None, _) => deduped.push_back(item),
            (Some(_), BackfillDuplicatePolicy::Skip) => {}
            (Some(index), BackfillDuplicatePolicy::Update) => deduped.set(index, item),
            (Some(_), BackfillDuplicatePolicy::Reject) => {
                return Err(BackfillError::DuplicateRecord)
            }
        }
    }

    Ok(deduped)
}

/// Begins a backfill operation, initializing the checkpoint.
///
/// An `AwaitingRecovery` checkpoint is not overwritten: it still holds the
/// cursor and counters for the interrupted run, so the caller must use
/// [`resume_backfill`] instead.
pub fn begin_backfill(
    env: &Env,
    plan: &BackfillPlan,
    now: u64,
) -> Result<BackfillCheckpoint, BackfillError> {
    plan.validate()?;

    if let Some(existing) = load_checkpoint(env) {
        if existing.status == BackfillStatus::InProgress {
            return Err(BackfillError::AlreadyInProgress);
        }
        if existing.status == BackfillStatus::AwaitingRecovery {
            return Err(BackfillError::ResumeRequired);
        }
    }

    let checkpoint = BackfillCheckpoint {
        module: plan.module,
        status: BackfillStatus::InProgress,
        cursor: 0,
        total_records: plan.total_records,
        created_count: 0,
        updated_count: 0,
        skipped_count: 0,
        failed_count: 0,
        started_at: now,
        updated_at: now,
        last_error: 0,
    };

    save_checkpoint(env, &checkpoint);
    Ok(checkpoint)
}

/// Advances checkpoint after a batch of items is committed.
pub fn advance_checkpoint(
    env: &Env,
    batch_created: u32,
    batch_updated: u32,
    batch_skipped: u32,
    batch_failed: u32,
    now: u64,
) -> Result<BackfillCheckpoint, BackfillError> {
    let mut checkpoint = load_checkpoint(env).ok_or(BackfillError::CheckpointNotFound)?;

    if checkpoint.status != BackfillStatus::InProgress {
        return Err(BackfillError::NotInProgress);
    }

    let processed = batch_created
        .saturating_add(batch_updated)
        .saturating_add(batch_skipped)
        .saturating_add(batch_failed);

    let cursor = checkpoint.cursor.saturating_add(processed);
    if cursor > checkpoint.total_records {
        // A replayed or oversized batch would count records that do not exist in
        // the plan. Reject it before any counter changes are persisted.
        return Err(BackfillError::RecordOutOfOrder);
    }

    checkpoint.cursor = cursor;
    checkpoint.created_count = checkpoint.created_count.saturating_add(batch_created);
    checkpoint.updated_count = checkpoint.updated_count.saturating_add(batch_updated);
    checkpoint.skipped_count = checkpoint.skipped_count.saturating_add(batch_skipped);
    checkpoint.failed_count = checkpoint.failed_count.saturating_add(batch_failed);
    checkpoint.updated_at = now;

    save_checkpoint(env, &checkpoint);
    Ok(checkpoint)
}

/// Records a failure and transitions status to AwaitingRecovery.
pub fn fail_backfill(
    env: &Env,
    error_code: u32,
    now: u64,
) -> Result<BackfillCheckpoint, BackfillError> {
    let mut checkpoint = load_checkpoint(env).ok_or(BackfillError::CheckpointNotFound)?;

    checkpoint.status = BackfillStatus::AwaitingRecovery;
    checkpoint.last_error = error_code;
    checkpoint.updated_at = now;

    save_checkpoint(env, &checkpoint);
    Ok(checkpoint)
}

/// Completes backfill and marks checkpoint as Completed.
pub fn complete_backfill(env: &Env, now: u64) -> Result<BackfillCheckpoint, BackfillError> {
    let mut checkpoint = load_checkpoint(env).ok_or(BackfillError::CheckpointNotFound)?;

    if checkpoint.status != BackfillStatus::InProgress
        && checkpoint.status != BackfillStatus::AwaitingRecovery
    {
        return Err(BackfillError::NotInProgress);
    }

    checkpoint.status = BackfillStatus::Completed;
    checkpoint.updated_at = now;

    save_checkpoint(env, &checkpoint);
    Ok(checkpoint)
}

/// Checks if a checkpoint can be resumed.
pub fn is_resumable(checkpoint: &BackfillCheckpoint) -> bool {
    checkpoint.status == BackfillStatus::InProgress
        || checkpoint.status == BackfillStatus::AwaitingRecovery
}

/// Resumes an interrupted backfill from its persisted checkpoint.
///
/// The stored cursor and counters are kept, so records before the cursor are not
/// processed again. Only `InProgress` and `AwaitingRecovery` checkpoints can be
/// resumed; terminal checkpoints return [`BackfillError::CannotResume`]. The
/// checkpoint's module must match `plan`, otherwise the call returns
/// [`BackfillError::InvalidPlan`].
pub fn resume_backfill(
    env: &Env,
    plan: &BackfillPlan,
    now: u64,
) -> Result<BackfillCheckpoint, BackfillError> {
    plan.validate()?;

    let mut checkpoint = load_checkpoint(env).ok_or(BackfillError::CheckpointNotFound)?;

    if checkpoint.module != plan.module {
        return Err(BackfillError::InvalidPlan);
    }
    if !is_resumable(&checkpoint) {
        return Err(BackfillError::CannotResume);
    }

    checkpoint.status = BackfillStatus::InProgress;
    checkpoint.last_error = 0;
    checkpoint.updated_at = now;

    save_checkpoint(env, &checkpoint);
    Ok(checkpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{contract, contractimpl};

    #[contract]
    struct DummyContract;
    #[contractimpl]
    impl DummyContract {}

    fn sample_plan(env: &Env, mode: BackfillMode) -> BackfillPlan {
        BackfillPlan {
            module: BackfillModule::Aid,
            mode,
            batch_size: 25,
            total_records: 10,
            rollback_notes: String::from_str(env, "rollback guidance test"),
        }
    }

    #[test]
    fn dry_run_reports_counts_without_mutations() {
        let env = Env::default();
        let contract = env.register_contract(None, DummyContract);

        env.as_contract(&contract, || {
            let plan = sample_plan(&env, BackfillMode::BestEffort);
            let mut items = Vec::new(&env);

            items.push_back(BackfillItem {
                id: 1,
                action: BackfillAction::Create,
                is_valid: true,
                is_destructive: false,
                reason: symbol_short!("new_rec"),
            });
            items.push_back(BackfillItem {
                id: 2,
                action: BackfillAction::Update,
                is_valid: true,
                is_destructive: false,
                reason: symbol_short!("v1_to_v2"),
            });
            items.push_back(BackfillItem {
                id: 3,
                action: BackfillAction::Skip,
                is_valid: true,
                is_destructive: false,
                reason: symbol_short!("up_to_dat"),
            });
            items.push_back(BackfillItem {
                id: 4,
                action: BackfillAction::Create,
                is_valid: false,
                is_destructive: false,
                reason: symbol_short!("bad_amt"),
            });

            let report = dry_run(&plan, &items).unwrap();
            assert_eq!(report.total_scanned, 4);
            assert_eq!(report.to_create, 1);
            assert_eq!(report.to_update, 1);
            assert_eq!(report.to_skip, 1);
            assert_eq!(report.failed_count, 1);
            assert!(report.can_proceed);

            // Verify no checkpoint was written
            assert!(load_checkpoint(&env).is_none());
        });
    }

    #[test]
    fn all_or_nothing_mode_blocks_proceed_on_invalid_records() {
        let env = Env::default();
        let plan = sample_plan(&env, BackfillMode::AllOrNothing);
        let mut items = Vec::new(&env);

        items.push_back(BackfillItem {
            id: 1,
            action: BackfillAction::Create,
            is_valid: false,
            is_destructive: false,
            reason: symbol_short!("bad_amt"),
        });

        let report = dry_run(&plan, &items).unwrap();
        assert_eq!(report.failed_count, 1);
        assert!(!report.can_proceed);
    }

    #[test]
    fn checkpoint_advancement_and_resumption() {
        let env = Env::default();
        let contract = env.register_contract(None, DummyContract);

        env.as_contract(&contract, || {
            let plan = sample_plan(&env, BackfillMode::BestEffort);

            let cp = begin_backfill(&env, &plan, 100).unwrap();
            assert_eq!(cp.status, BackfillStatus::InProgress);
            assert_eq!(cp.cursor, 0);

            // Advance by batch of 5 records
            let advanced = advance_checkpoint(&env, 2, 2, 1, 0, 105).unwrap();
            assert_eq!(advanced.cursor, 5);
            assert_eq!(advanced.created_count, 2);
            assert_eq!(advanced.updated_count, 2);
            assert_eq!(advanced.skipped_count, 1);
            assert!(is_resumable(&advanced));

            // Fail backfill
            let failed = fail_backfill(&env, 965, 110).unwrap();
            assert_eq!(failed.status, BackfillStatus::AwaitingRecovery);
            assert_eq!(failed.last_error, 965);
            assert!(is_resumable(&failed));

            // Complete backfill
            let completed = complete_backfill(&env, 120).unwrap();
            assert_eq!(completed.status, BackfillStatus::Completed);
            assert!(!is_resumable(&completed));

            clear_checkpoint(&env);
            assert!(load_checkpoint(&env).is_none());
        });
    }

    fn sample_item(id: u64, action: BackfillAction) -> BackfillItem {
        BackfillItem {
            id,
            action,
            is_valid: true,
            is_destructive: false,
            reason: symbol_short!("sample"),
        }
    }

    #[test]
    fn dedupe_skip_keeps_first_occurrence() {
        let env = Env::default();
        let mut items = Vec::new(&env);
        items.push_back(sample_item(1, BackfillAction::Create));
        items.push_back(sample_item(2, BackfillAction::Update));
        items.push_back(sample_item(1, BackfillAction::Skip));

        let deduped = dedupe_items(&env, &items, BackfillDuplicatePolicy::Skip).unwrap();
        assert_eq!(deduped.len(), 2);
        assert_eq!(deduped.get(0).unwrap().action, BackfillAction::Create);
        assert_eq!(deduped.get(1).unwrap().id, 2);
    }

    #[test]
    fn dedupe_update_keeps_last_occurrence_at_first_position() {
        let env = Env::default();
        let mut items = Vec::new(&env);
        items.push_back(sample_item(1, BackfillAction::Create));
        items.push_back(sample_item(2, BackfillAction::Update));
        items.push_back(sample_item(1, BackfillAction::Skip));

        let deduped = dedupe_items(&env, &items, BackfillDuplicatePolicy::Update).unwrap();
        assert_eq!(deduped.len(), 2);
        assert_eq!(deduped.get(0).unwrap().id, 1);
        assert_eq!(deduped.get(0).unwrap().action, BackfillAction::Skip);
        assert_eq!(deduped.get(1).unwrap().id, 2);
    }

    #[test]
    fn dedupe_reject_refuses_batch_with_any_duplicate() {
        let env = Env::default();
        let mut items = Vec::new(&env);
        items.push_back(sample_item(1, BackfillAction::Create));
        items.push_back(sample_item(1, BackfillAction::Create));

        assert_eq!(
            dedupe_items(&env, &items, BackfillDuplicatePolicy::Reject).err(),
            Some(BackfillError::DuplicateRecord)
        );

        // A batch with unique ids passes through unchanged under Reject.
        let mut unique = Vec::new(&env);
        unique.push_back(sample_item(1, BackfillAction::Create));
        unique.push_back(sample_item(2, BackfillAction::Create));
        let passed = dedupe_items(&env, &unique, BackfillDuplicatePolicy::Reject).unwrap();
        assert_eq!(passed.len(), 2);
    }

    #[test]
    fn begin_is_refused_while_awaiting_recovery_and_resume_continues_cursor() {
        let env = Env::default();
        let contract = env.register_contract(None, DummyContract);

        env.as_contract(&contract, || {
            let plan = sample_plan(&env, BackfillMode::BestEffort);
            begin_backfill(&env, &plan, 100).unwrap();
            advance_checkpoint(&env, 2, 0, 0, 0, 101).unwrap();
            fail_backfill(&env, 966, 102).unwrap();

            assert_eq!(
                begin_backfill(&env, &plan, 103).err(),
                Some(BackfillError::ResumeRequired)
            );

            let resumed = resume_backfill(&env, &plan, 104).unwrap();
            assert_eq!(resumed.status, BackfillStatus::InProgress);
            assert_eq!(resumed.cursor, 2);
            assert_eq!(resumed.created_count, 2);
            assert_eq!(resumed.last_error, 0);
            assert_eq!(resumed.updated_at, 104);

            clear_checkpoint(&env);
        });
    }

    #[test]
    fn resume_rejects_missing_terminal_and_mismatched_checkpoints() {
        let env = Env::default();
        let contract = env.register_contract(None, DummyContract);

        env.as_contract(&contract, || {
            let plan = sample_plan(&env, BackfillMode::BestEffort);
            assert_eq!(
                resume_backfill(&env, &plan, 100).err(),
                Some(BackfillError::CheckpointNotFound)
            );

            begin_backfill(&env, &plan, 100).unwrap();
            complete_backfill(&env, 101).unwrap();
            assert_eq!(
                resume_backfill(&env, &plan, 102).err(),
                Some(BackfillError::CannotResume)
            );

            clear_checkpoint(&env);
            begin_backfill(&env, &plan, 103).unwrap();
            let mut other = sample_plan(&env, BackfillMode::BestEffort);
            other.module = BackfillModule::Treasury;
            assert_eq!(
                resume_backfill(&env, &other, 104).err(),
                Some(BackfillError::InvalidPlan)
            );

            clear_checkpoint(&env);
        });
    }

    #[test]
    fn advance_past_total_records_is_rejected_without_persisting() {
        let env = Env::default();
        let contract = env.register_contract(None, DummyContract);

        env.as_contract(&contract, || {
            let plan = sample_plan(&env, BackfillMode::BestEffort);
            begin_backfill(&env, &plan, 100).unwrap();
            advance_checkpoint(&env, 6, 4, 0, 0, 101).unwrap();

            assert_eq!(
                advance_checkpoint(&env, 1, 0, 0, 0, 102).err(),
                Some(BackfillError::RecordOutOfOrder)
            );

            let stored = load_checkpoint(&env).unwrap();
            assert_eq!(stored.cursor, 10);
            assert_eq!(stored.created_count, 6);

            clear_checkpoint(&env);
        });
    }
}

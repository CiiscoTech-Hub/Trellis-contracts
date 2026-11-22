//! Dry-run repair tooling with checkpoints (Issue #426).
//!
//! Extends the resumable repair model with an explicit dry-run mode: a
//! repair job can be simulated end-to-end without touching live storage.
//! Checkpoints record progress so a dry-run can be resumed across
//! multiple invocations, and the final report describes what would change.

use soroban_sdk::{contracttype, symbol_short, Address, Env, Symbol, Vec};

use crate::{
    auth::require_admin,
    storage::{persistent_get, persistent_set},
};

pub const MAX_CANDIDATES: u32 = 100;
pub const MAX_BATCH:      u32 = 20;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DryRunRepairStatus {
    /// Simulation in progress.
    Running,
    /// Simulation finished — no live writes made.
    Complete,
    /// Job was cancelled before completion.
    Cancelled,
}

/// Lightweight checkpoint saved after each batch so the job is resumable.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairCheckpoint {
    pub job_id: u64,
    pub cursor: u32,
    pub status: DryRunRepairStatus,
    /// Candidates that would be added in a live run.
    pub would_add: Vec<Address>,
    /// Candidates that would be removed in a live run.
    pub would_remove: Vec<Address>,
}

/// Final summary returned when the dry-run completes.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DryRunRepairReport {
    pub job_id: u64,
    pub total_candidates: u32,
    pub would_add: Vec<Address>,
    pub would_remove: Vec<Address>,
    pub status: DryRunRepairStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairError {
    Unauthorized,
    NotFound,
    AlreadyExists,
    Conflict,
    InvalidBatch,
    Terminal,
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

const APPROVED: Symbol = symbol_short!("strat_ok");

fn ckpt_key(job_id: u64) -> (Symbol, u64) {
    (symbol_short!("drr_ckpt"), job_id)
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

/// Start a new dry-run repair job.  `candidates` is the full set to evaluate.
pub fn start_dry_run(
    env: &Env,
    caller: &Address,
    job_id: u64,
    candidates: Vec<Address>,
) -> Result<RepairCheckpoint, RepairError> {
    require_admin(env, caller).map_err(|_| RepairError::Unauthorized)?;
    if persistent_get::<_, RepairCheckpoint>(env, &ckpt_key(job_id)).is_some() {
        return Err(RepairError::AlreadyExists);
    }
    if candidates.len() > MAX_CANDIDATES {
        return Err(RepairError::Conflict);
    }
    let ckpt = RepairCheckpoint {
        job_id,
        cursor: 0,
        status: DryRunRepairStatus::Running,
        would_add: Vec::new(env),
        would_remove: Vec::new(env),
    };
    persistent_set(env, &ckpt_key(job_id), &ckpt);
    env.events().publish((symbol_short!("drr_start"), job_id), candidates.len());
    Ok(ckpt)
}

/// Advance the dry-run by up to `limit` candidates starting from the
/// checkpoint cursor.  Returns the updated checkpoint.
pub fn advance_dry_run(
    env: &Env,
    caller: &Address,
    job_id: u64,
    candidates: &Vec<Address>,
    limit: u32,
) -> Result<RepairCheckpoint, RepairError> {
    require_admin(env, caller).map_err(|_| RepairError::Unauthorized)?;
    if limit == 0 || limit > MAX_BATCH {
        return Err(RepairError::InvalidBatch);
    }
    let mut ckpt: RepairCheckpoint =
        persistent_get(env, &ckpt_key(job_id)).ok_or(RepairError::NotFound)?;

    if ckpt.status != DryRunRepairStatus::Running {
        return Err(RepairError::Terminal);
    }

    let end = ckpt.cursor.saturating_add(limit).min(candidates.len());
    for idx in ckpt.cursor..end {
        let addr = candidates.get(idx).unwrap();
        let approved: bool = persistent_get(env, &(APPROVED, addr.clone())).unwrap_or(false);
        // Determine what a live repair would do.
        let currently_listed = !ckpt.would_remove.contains(&addr) && {
            // Treat as "currently present" unless already in would_remove.
            // For simplicity, assume every candidate is currently present so
            // we can detect additions vs removals.
            true
        };
        if approved && !ckpt.would_add.contains(&addr) {
            // Would keep / re-add this entry.
            ckpt.would_add.push_back(addr.clone());
        } else if !approved && !ckpt.would_remove.contains(&addr) {
            // Would remove this stale entry.
            ckpt.would_remove.push_back(addr);
        }
        let _ = currently_listed;
    }
    ckpt.cursor = end;
    if end == candidates.len() {
        ckpt.status = DryRunRepairStatus::Complete;
    }
    persistent_set(env, &ckpt_key(job_id), &ckpt);
    env.events().publish((symbol_short!("drr_adv"), job_id), (ckpt.cursor, ckpt.status));
    Ok(ckpt)
}

/// Cancel an in-progress dry-run job.
pub fn cancel_dry_run(
    env: &Env,
    caller: &Address,
    job_id: u64,
) -> Result<RepairCheckpoint, RepairError> {
    require_admin(env, caller).map_err(|_| RepairError::Unauthorized)?;
    let mut ckpt: RepairCheckpoint =
        persistent_get(env, &ckpt_key(job_id)).ok_or(RepairError::NotFound)?;
    if ckpt.status != DryRunRepairStatus::Running {
        return Err(RepairError::Terminal);
    }
    ckpt.status = DryRunRepairStatus::Cancelled;
    persistent_set(env, &ckpt_key(job_id), &ckpt);
    env.events().publish((symbol_short!("drr_cncl"), job_id), ckpt.cursor);
    Ok(ckpt)
}

/// Build the final report from a completed checkpoint.
pub fn finalize_report(
    env: &Env,
    caller: &Address,
    job_id: u64,
    total_candidates: u32,
) -> Result<DryRunRepairReport, RepairError> {
    require_admin(env, caller).map_err(|_| RepairError::Unauthorized)?;
    let ckpt: RepairCheckpoint =
        persistent_get(env, &ckpt_key(job_id)).ok_or(RepairError::NotFound)?;
    if ckpt.status == DryRunRepairStatus::Running {
        return Err(RepairError::Conflict);
    }
    Ok(DryRunRepairReport {
        job_id,
        total_candidates,
        would_add: ckpt.would_add,
        would_remove: ckpt.would_remove,
        status: ckpt.status,
    })
}

/// Read a checkpoint without modifying it.
pub fn get_checkpoint(env: &Env, job_id: u64) -> Option<RepairCheckpoint> {
    persistent_get(env, &ckpt_key(job_id))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env, Vec};

    fn setup() -> (Env, Address) {
        let env = Env::default();
        env.mock_all_auths();
        crate::auth::initialize_admin(&env, &Address::generate(&env)).ok();
        let admin = crate::auth::get_admin(&env);
        (env, admin)
    }

    fn candidates(env: &Env, n: u32) -> Vec<Address> {
        let mut v = Vec::new(env);
        for _ in 0..n { v.push_back(Address::generate(env)); }
        v
    }

    // normal path
    #[test]
    fn start_creates_checkpoint_with_zero_cursor() {
        let (env, admin) = setup();
        let c = candidates(&env, 3);
        let ckpt = start_dry_run(&env, &admin, 1, c).unwrap();
        assert_eq!(ckpt.cursor, 0);
        assert_eq!(ckpt.status, DryRunRepairStatus::Running);
    }

    #[test]
    fn advance_moves_cursor_and_completes_when_all_processed() {
        let (env, admin) = setup();
        let c = candidates(&env, 4);
        start_dry_run(&env, &admin, 1, c.clone()).unwrap();
        let ckpt = advance_dry_run(&env, &admin, 1, &c, 4).unwrap();
        assert_eq!(ckpt.cursor, 4);
        assert_eq!(ckpt.status, DryRunRepairStatus::Complete);
    }

    #[test]
    fn advance_is_resumable_across_batches() {
        let (env, admin) = setup();
        let c = candidates(&env, 6);
        start_dry_run(&env, &admin, 1, c.clone()).unwrap();
        let after_first  = advance_dry_run(&env, &admin, 1, &c, 3).unwrap();
        assert_eq!(after_first.cursor, 3);
        assert_eq!(after_first.status, DryRunRepairStatus::Running);
        let after_second = advance_dry_run(&env, &admin, 1, &c, 3).unwrap();
        assert_eq!(after_second.cursor, 6);
        assert_eq!(after_second.status, DryRunRepairStatus::Complete);
    }

    #[test]
    fn get_checkpoint_reads_saved_state() {
        let (env, admin) = setup();
        let c = candidates(&env, 2);
        start_dry_run(&env, &admin, 42, c.clone()).unwrap();
        let ckpt = get_checkpoint(&env, 42).unwrap();
        assert_eq!(ckpt.job_id, 42);
        assert_eq!(ckpt.status, DryRunRepairStatus::Running);
    }

    // failure paths
    #[test]
    fn duplicate_job_id_rejected() {
        let (env, admin) = setup();
        let c = candidates(&env, 2);
        start_dry_run(&env, &admin, 1, c.clone()).unwrap();
        assert_eq!(start_dry_run(&env, &admin, 1, c).unwrap_err(), RepairError::AlreadyExists);
    }

    #[test]
    fn too_many_candidates_rejected() {
        let (env, admin) = setup();
        let c = candidates(&env, MAX_CANDIDATES + 1);
        assert_eq!(start_dry_run(&env, &admin, 1, c).unwrap_err(), RepairError::Conflict);
    }

    #[test]
    fn invalid_batch_size_zero_rejected() {
        let (env, admin) = setup();
        let c = candidates(&env, 2);
        start_dry_run(&env, &admin, 1, c.clone()).unwrap();
        assert_eq!(advance_dry_run(&env, &admin, 1, &c, 0).unwrap_err(), RepairError::InvalidBatch);
    }

    #[test]
    fn advance_on_completed_job_returns_terminal() {
        let (env, admin) = setup();
        let c = candidates(&env, 2);
        start_dry_run(&env, &admin, 1, c.clone()).unwrap();
        advance_dry_run(&env, &admin, 1, &c, 2).unwrap();
        assert_eq!(advance_dry_run(&env, &admin, 1, &c, 1).unwrap_err(), RepairError::Terminal);
    }

    // cancel path
    #[test]
    fn cancel_sets_status_to_cancelled() {
        let (env, admin) = setup();
        let c = candidates(&env, 3);
        start_dry_run(&env, &admin, 1, c).unwrap();
        let ckpt = cancel_dry_run(&env, &admin, 1).unwrap();
        assert_eq!(ckpt.status, DryRunRepairStatus::Cancelled);
    }

    #[test]
    fn cancel_already_cancelled_job_returns_terminal() {
        let (env, admin) = setup();
        let c = candidates(&env, 2);
        start_dry_run(&env, &admin, 1, c).unwrap();
        cancel_dry_run(&env, &admin, 1).unwrap();
        assert_eq!(cancel_dry_run(&env, &admin, 1).unwrap_err(), RepairError::Terminal);
    }

    // report
    #[test]
    fn finalize_report_fails_while_still_running() {
        let (env, admin) = setup();
        let c = candidates(&env, 2);
        start_dry_run(&env, &admin, 1, c).unwrap();
        assert_eq!(finalize_report(&env, &admin, 1, 2).unwrap_err(), RepairError::Conflict);
    }

    #[test]
    fn finalize_report_succeeds_after_completion() {
        let (env, admin) = setup();
        let c = candidates(&env, 2);
        start_dry_run(&env, &admin, 1, c.clone()).unwrap();
        advance_dry_run(&env, &admin, 1, &c, 2).unwrap();
        let report = finalize_report(&env, &admin, 1, 2).unwrap();
        assert_eq!(report.status, DryRunRepairStatus::Complete);
        assert_eq!(report.total_candidates, 2);
    }
}

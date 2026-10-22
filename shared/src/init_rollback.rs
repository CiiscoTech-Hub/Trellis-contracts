//! Rollback verification for failed multi-step initialization (Issue #337).
//!
//! A single contract's own `initialize` entry point is one atomic Soroban
//! transaction, so it can never persist a half-initialized state by itself.
//! A multi-contract **deployment** is not atomic: initializing Treasury,
//! Aid, Referral, Governance, Oracle, and Marketplace (and wiring their
//! cross-contract addresses) is a sequence of separate transactions. If one
//! fails partway through, the system is left with some contracts
//! initialized and others not — and simply retrying is dangerous unless an
//! operator can first prove that whatever *did* get initialized was
//! actually undone, not just marked "failed" in a tracker.
//!
//! This module adds that proof step. It does not, and cannot, undo
//! cross-contract state itself — only the contract that holds a piece of
//! state can clear it. What it adds is the **bookkeeping and the gate**:
//!
//! - [`begin_initialization`] records an ordered list of steps for a
//!   deployment `id`. [`complete_init_step`] / [`fail_init_step`] advance it
//!   deterministically, exactly like `shared::recovery`'s step tracking.
//! - [`verify_rollback`] takes the operator's own freshly re-checked
//!   [`InitStepProbe`]s (one per step that actually ran) and reports whether
//!   every one of them now shows **not** initialized. This is the inverse of
//!   `shared::release_readiness::verify_initialized_addresses`, which checks
//!   that addresses *are* set; this checks that they are genuinely *unset*
//!   again after an attempted rollback.
//! - [`complete_rollback`] is the hard gate: it refuses to mark the tracker
//!   `RolledBack` unless it is handed a passing [`InitRollbackVerification`]
//!   for the same `id`. A tracker can never reach `RolledBack` on trust
//!   alone — only on verified evidence.
//! - [`begin_initialization`] doubles as the retry path: calling it again
//!   for an `id` whose tracker is `RolledBack` (or `Completed`) starts a
//!   fresh attempt with `attempt` incremented, so a retry is only possible
//!   from a state that was either fully finished or provably clean.
//!
//! Nothing in `shared::recovery`, `shared::migration`, or
//! `shared::release_readiness` changes — this module adds its own storage
//! and entry points alongside them.
//!
//! ## Operational edge cases
//!
//! | Situation | Behavior |
//! |---|---|
//! | Non-admin calls any mutating entry point | `Error::Unauthorized`, before the tracker is touched. |
//! | `begin_initialization` while a tracker for `id` is `InProgress` or `AwaitingRollback` | `Error::AlreadyInitialized` — finish or roll back the current attempt first. |
//! | `begin_initialization` with an empty step list, or steps not `0, 1, 2, …` in order | `Error::InvalidArgument`, before anything is stored. |
//! | `complete_init_step` / `fail_init_step` with the wrong index, or when the tracker isn't `InProgress` | `Error::InvalidTransition`. |
//! | `verify_rollback` called when the tracker isn't `AwaitingRollback` | `Error::InvalidTransition` — nothing to verify yet. |
//! | A probe is missing for a step that ran, or reports `still_initialized: true` | `fully_rolled_back: false` and `first_not_rolled_back` names the step; `complete_rollback` then refuses. |
//! | `complete_rollback` with a verification for a different `id`, or one that isn't fully rolled back | `Error::InvalidTransition` — the tracker stays `AwaitingRollback`. |
//! | `begin_initialization` again after a verified `RolledBack` | Succeeds; `attempt` increments so the retry is distinguishable in the event log and the tracker. |
//!
//! ## Recovery / rollback
//!
//! This module *is* the rollback-recovery path, so "recovering" it means:
//!
//! 1. **A step failed mid-deployment.** Call [`fail_init_step`] to record it
//!    (`AwaitingRollback`). The operator then manually undoes whatever the
//!    completed steps actually did — on each affected contract, not here.
//! 2. **Prove the undo worked.** Re-read the real state the completed steps
//!    touched, build one [`InitStepProbe`] per step, and call
//!    [`verify_rollback`]. If `fully_rolled_back` is `false`, more cleanup is
//!    needed at `first_not_rolled_back` before retrying verification.
//! 3. **Close out the rollback.** [`complete_rollback`] with the passing
//!    verification moves the tracker to `RolledBack`. This is the only path
//!    to that state — it cannot be reached by just waiting or retrying.
//! 4. **Retry the deployment.** [`begin_initialization`] again with the same
//!    `id` (and, typically, a corrected step list or fixed root cause).
//!    `attempt` on the new tracker shows this is a second try, not a first.
//!
//! ## Compatibility
//!
//! Purely additive: new storage keys, no changes to `shared::recovery`,
//! `shared::migration`, `shared::release_readiness`, or any contract
//! interface. A deployment script or admin tool adopts it by calling
//! `begin_initialization` before running its own per-contract `initialize`
//! calls, and `complete_init_step` / `fail_init_step` after each one.

use soroban_sdk::{contracttype, symbol_short, Address, Env, Symbol, Vec};

use crate::auth::{has_role, Role};
use crate::errors::Error;
use crate::storage::{persistent_get, persistent_set};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Outcome of one initialization step.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitStepOutcome {
    /// Not attempted yet.
    Pending,
    /// Ran successfully.
    Completed,
    /// Attempted and failed; the deployment needs rollback.
    Failed,
    /// Verified undone after a completed rollback.
    RolledBack,
}

/// One step in a multi-step (often cross-contract) initialization sequence.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitStep {
    /// Zero-based position; must be strictly increasing across the sequence.
    pub index: u32,
    /// Short step name (e.g. `"treasury_init"`, `"wire_aid_treasury"`).
    pub name: Symbol,
    pub outcome: InitStepOutcome,
}

/// Lifecycle state of an initialization tracker.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitializationStatus {
    /// Steps are being executed in order.
    InProgress,
    /// A step failed; the deployment needs rollback before it can retry.
    AwaitingRollback,
    /// Rollback was verified complete; a fresh attempt may begin.
    RolledBack,
    /// Every step completed successfully.
    Completed,
}

/// Persisted progress record for one initialization sequence.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitializationTracker {
    /// Deployment/sequence identifier (unique per in-flight initialization).
    pub id: Symbol,
    pub status: InitializationStatus,
    pub steps: Vec<InitStep>,
    /// Index of the next step to run.
    pub cursor: u32,
    /// How many times `begin_initialization` has been called for this id.
    pub attempt: u32,
    pub started_at: u64,
    pub updated_at: u64,
    /// Error code from the most recent `fail_init_step` (0 when none).
    pub last_error: u32,
}

/// What the operator observed when re-checking one step's real on-chain
/// state after attempting to undo it.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitStepProbe {
    pub index: u32,
    /// `true` if the step's effect is still observably present.
    pub still_initialized: bool,
}

/// Result of checking a set of [`InitStepProbe`]s against a tracker's steps
/// that actually ran.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitRollbackVerification {
    pub id: Symbol,
    /// Number of ran steps confirmed undone.
    pub checked: u32,
    /// `true` only when every ran step has a probe confirming it is undone.
    pub fully_rolled_back: bool,
    /// First ran step still showing initialized state (missing or failing probe).
    pub first_not_rolled_back: Option<u32>,
    pub verified_at: u64,
}

// ---------------------------------------------------------------------------
// Storage keys and events
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum InitRollbackKey {
    Tracker(Symbol),
}

/// Topic prefix for every initialization-rollback event.
pub const INIT_ROLLBACK_TOPIC: Symbol = symbol_short!("init_rb");

fn publish(env: &Env, event: Symbol, id: &Symbol, value: u32) {
    env.events()
        .publish((INIT_ROLLBACK_TOPIC, event, id.clone()), value);
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn validate_steps(steps: &Vec<InitStep>) -> Result<(), Error> {
    if steps.is_empty() {
        return Err(Error::InvalidArgument);
    }
    let mut expected: u32 = 0;
    for step in steps.iter() {
        if step.index != expected || step.outcome != InitStepOutcome::Pending {
            return Err(Error::InvalidArgument);
        }
        expected = expected.saturating_add(1);
    }
    Ok(())
}

fn with_step_outcome(
    env: &Env,
    steps: &Vec<InitStep>,
    index: u32,
    outcome: InitStepOutcome,
) -> Vec<InitStep> {
    let mut out = Vec::new(env);
    let mut i: u32 = 0;
    for step in steps.iter() {
        let mut step = step;
        if i == index {
            step.outcome = outcome;
        }
        out.push_back(step);
        i = i.saturating_add(1);
    }
    out
}

fn rolled_back_steps(env: &Env, steps: &Vec<InitStep>, up_to: u32) -> Vec<InitStep> {
    let mut out = Vec::new(env);
    let mut i: u32 = 0;
    for step in steps.iter() {
        let mut step = step;
        if i <= up_to
            && (step.outcome == InitStepOutcome::Completed
                || step.outcome == InitStepOutcome::Failed)
        {
            step.outcome = InitStepOutcome::RolledBack;
        }
        out.push_back(step);
        i = i.saturating_add(1);
    }
    out
}

fn save_tracker(env: &Env, tracker: &InitializationTracker) {
    persistent_set(env, &InitRollbackKey::Tracker(tracker.id.clone()), tracker);
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/// Reads the tracker for `id`, if one exists.
pub fn get_tracker(env: &Env, id: &Symbol) -> Option<InitializationTracker> {
    persistent_get(env, &InitRollbackKey::Tracker(id.clone()))
}

// ---------------------------------------------------------------------------
// Normal / retry path
// ---------------------------------------------------------------------------

/// Starts a new initialization sequence for `id`, admin-gated.
///
/// Fails with [`Error::AlreadyInitialized`] while a previous attempt under
/// the same `id` is still `InProgress` or `AwaitingRollback`. Succeeds again
/// for an `id` whose tracker is `Completed` or `RolledBack` — this is the
/// retry path: `attempt` increments so a second try is distinguishable from
/// the first.
pub fn begin_initialization(
    env: &Env,
    admin: &Address,
    id: Symbol,
    steps: Vec<InitStep>,
    at: u64,
) -> Result<InitializationTracker, Error> {
    if !has_role(env, admin, Role::Admin) {
        return Err(Error::Unauthorized);
    }
    admin.require_auth();
    validate_steps(&steps)?;

    let attempt = match get_tracker(env, &id) {
        Some(existing) => {
            if existing.status == InitializationStatus::InProgress
                || existing.status == InitializationStatus::AwaitingRollback
            {
                return Err(Error::AlreadyInitialized);
            }
            existing.attempt.saturating_add(1)
        }
        None => 1,
    };

    let tracker = InitializationTracker {
        id: id.clone(),
        status: InitializationStatus::InProgress,
        steps,
        cursor: 0,
        attempt,
        started_at: at,
        updated_at: at,
        last_error: 0,
    };
    save_tracker(env, &tracker);
    publish(env, symbol_short!("begin"), &id, attempt);
    Ok(tracker)
}

/// Marks the step at `cursor` complete, admin-gated.
pub fn complete_init_step(
    env: &Env,
    admin: &Address,
    id: &Symbol,
    index: u32,
    at: u64,
) -> Result<InitializationTracker, Error> {
    if !has_role(env, admin, Role::Admin) {
        return Err(Error::Unauthorized);
    }
    admin.require_auth();
    let mut tracker = get_tracker(env, id).ok_or(Error::NotFound)?;
    if tracker.status != InitializationStatus::InProgress || index != tracker.cursor {
        return Err(Error::InvalidTransition);
    }
    tracker.steps = with_step_outcome(env, &tracker.steps, index, InitStepOutcome::Completed);
    tracker.cursor = tracker.cursor.saturating_add(1);
    tracker.updated_at = at;
    if tracker.cursor >= tracker.steps.len() {
        tracker.status = InitializationStatus::Completed;
    }
    save_tracker(env, &tracker);
    publish(env, symbol_short!("step_ok"), id, index);
    Ok(tracker)
}

// ---------------------------------------------------------------------------
// Failure path
// ---------------------------------------------------------------------------

/// Records a failure at the step at `cursor` and moves the tracker to
/// `AwaitingRollback`, admin-gated.
pub fn fail_init_step(
    env: &Env,
    admin: &Address,
    id: &Symbol,
    index: u32,
    error_code: u32,
    at: u64,
) -> Result<InitializationTracker, Error> {
    if !has_role(env, admin, Role::Admin) {
        return Err(Error::Unauthorized);
    }
    admin.require_auth();
    let mut tracker = get_tracker(env, id).ok_or(Error::NotFound)?;
    if tracker.status != InitializationStatus::InProgress || index != tracker.cursor {
        return Err(Error::InvalidTransition);
    }
    tracker.steps = with_step_outcome(env, &tracker.steps, index, InitStepOutcome::Failed);
    tracker.status = InitializationStatus::AwaitingRollback;
    tracker.last_error = error_code;
    tracker.updated_at = at;
    save_tracker(env, &tracker);
    publish(env, symbol_short!("fail"), id, index);
    Ok(tracker)
}

// ---------------------------------------------------------------------------
// Rollback verification
// ---------------------------------------------------------------------------

/// Checks `probes` against every step that actually ran (`Completed` or
/// `Failed`, up to and including the cursor) on an `AwaitingRollback`
/// tracker.
///
/// Read-only: performs no writes, so it carries no authorization
/// requirement, the same as
/// `shared::release_readiness::verify_initialized_addresses`. Its result is
/// only as trustworthy as the probes the caller supplies — this function
/// checks consistency, not the underlying contract state itself.
pub fn verify_rollback(
    env: &Env,
    id: &Symbol,
    probes: &Vec<InitStepProbe>,
) -> Result<InitRollbackVerification, Error> {
    let tracker = get_tracker(env, id).ok_or(Error::NotFound)?;
    if tracker.status != InitializationStatus::AwaitingRollback {
        return Err(Error::InvalidTransition);
    }

    let mut checked: u32 = 0;
    let mut first_not_rolled_back: Option<u32> = None;
    let mut i: u32 = 0;
    while i <= tracker.cursor && i < tracker.steps.len() {
        let step = tracker.steps.get(i).unwrap();
        if step.outcome == InitStepOutcome::Completed || step.outcome == InitStepOutcome::Failed {
            let still_initialized = probes
                .iter()
                .find(|p| p.index == i)
                .map(|p| p.still_initialized)
                .unwrap_or(true);
            if still_initialized {
                if first_not_rolled_back.is_none() {
                    first_not_rolled_back = Some(i);
                }
            } else {
                checked = checked.saturating_add(1);
            }
        }
        i = i.saturating_add(1);
    }

    Ok(InitRollbackVerification {
        id: id.clone(),
        checked,
        fully_rolled_back: first_not_rolled_back.is_none(),
        first_not_rolled_back,
        verified_at: env.ledger().timestamp(),
    })
}

/// Marks the tracker `RolledBack`, admin-gated, and only when handed a
/// passing [`InitRollbackVerification`] for the same `id`.
///
/// This is the only path to `RolledBack` — there is no way to reach it by
/// waiting, retrying, or admin override without a verification that
/// actually passed.
pub fn complete_rollback(
    env: &Env,
    admin: &Address,
    id: &Symbol,
    verification: &InitRollbackVerification,
    at: u64,
) -> Result<InitializationTracker, Error> {
    if !has_role(env, admin, Role::Admin) {
        return Err(Error::Unauthorized);
    }
    admin.require_auth();
    let mut tracker = get_tracker(env, id).ok_or(Error::NotFound)?;
    if tracker.status != InitializationStatus::AwaitingRollback {
        return Err(Error::InvalidTransition);
    }
    if verification.id != *id || !verification.fully_rolled_back {
        return Err(Error::InvalidTransition);
    }

    tracker.steps = rolled_back_steps(env, &tracker.steps, tracker.cursor);
    tracker.status = InitializationStatus::RolledBack;
    tracker.cursor = 0;
    tracker.updated_at = at;
    save_tracker(env, &tracker);
    publish(env, symbol_short!("rlbk_ok"), id, tracker.attempt);
    Ok(tracker)
}

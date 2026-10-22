//! Dead-letter recovery for failed domain-event handlers (Issue #335).
//!
//! `shared::domain_events` validates and publishes [`DomainEvent`]s, but has
//! no concept of an in-contract consumer that reacts to one (indexing
//! bookkeeping, a downstream side effect, cross-module notification, …). If
//! that reaction fails, the options today are: let the error propagate and
//! abort the whole transaction — including the event publish itself — or
//! swallow it silently and lose the failure. Neither is acceptable for a
//! handler whose failure must not block the primary action but also must
//! not disappear.
//!
//! This module gives domain-event handler dispatch the same dead-letter
//! discipline `shared::jobs` already gives background work, and reuses
//! [`RetryPolicy`] directly rather than inventing a second retry-policy type:
//!
//! - [`dispatch_event`] runs the handler. On success nothing is stored. On
//!   failure, instead of propagating the error, it records an
//!   [`EventDeadLetter`] and returns which outcome occurred — the caller's
//!   own transaction (e.g. the code that published the event) can still
//!   commit.
//! - [`retry_dead_letter`] is the permissionless, backoff-gated retry path:
//!   anyone can call it once a pending dead letter's `next_attempt_ledger`
//!   has passed; it re-runs the handler and either clears the letter,
//!   reschedules it, or marks it dead-lettered once retries are exhausted.
//! - [`requeue_dead_letter`] / [`discard_dead_letter`] are the admin-gated
//!   recovery/rollback path for a letter that has exhausted its retries.
//!
//! Nothing in `shared::domain_events` or `shared::jobs` changes: this module
//! only reads their public types ([`DomainEvent`], [`RetryPolicy`],
//! `is_retryable_error`) and adds its own storage and entry points.
//!
//! ## Operational edge cases
//!
//! | Situation | Behavior |
//! |---|---|
//! | Handler succeeds (first attempt or a retry) | `DispatchOutcome::Succeeded`; no record is kept. |
//! | Handler fails with a non-retryable error code, or `policy.max_attempts == 1` | Dead-lettered immediately, no retry scheduled. |
//! | Handler fails with a retryable error code and attempts remain | `DispatchOutcome::Retried`; `next_attempt_ledger` is set from `policy.backoff_after`. |
//! | `retry_dead_letter` called before `next_attempt_ledger` | `Error::ActionTooEarly` — the letter is untouched, no attempt is consumed. |
//! | `retry_dead_letter` called on an id that is already `DeadLettered` or does not exist | `Error::InvalidTransition` / `Error::NotFound`; dead letters must go through `requeue_dead_letter` first. |
//! | `requeue_dead_letter` / `discard_dead_letter` on a `Pending` letter | `Error::InvalidTransition` — only exhausted (`DeadLettered`) letters can be requeued or discarded. |
//! | Non-admin calls `requeue_dead_letter` / `discard_dead_letter` | `Error::Unauthorized` before the record is touched. |
//! | Invalid `RetryPolicy` passed to `dispatch_event` | `Error::ConfigInvalid`, same validation `shared::jobs::RetryPolicy::validate` already enforces. |
//!
//! ## Recovery / rollback
//!
//! 1. **A handler bug caused a batch of letters to dead-letter.** Fix and
//!    redeploy the handler, then call `requeue_dead_letter` for each
//!    affected id (or iterate `dead_letter_ids`) to give them a fresh
//!    attempt budget. The original event payload is preserved exactly, so
//!    replay is deterministic.
//! 2. **A dead letter should not be retried at all** (e.g. the underlying
//!    event is now obsolete): call `discard_dead_letter`. The record itself
//!    is kept for audit — only its membership in the dead-letter index is
//!    cleared — mirroring `shared::jobs::discard_dead_letter`.
//! 3. **A dependency the handler needs was degraded and is now healthy
//!    again**, and letters are still inside their backoff window: there is
//!    no need to wait them out — `requeue_dead_letter` resets
//!    `next_attempt_ledger` to "now" immediately.
//! 4. **Rollback of a bad `RetryPolicy`**: `dispatch_event` takes the policy
//!    per call (it is not global, persistent configuration), so correcting
//!    it only affects events dispatched after the fix; already-stored
//!    letters keep the policy they were created with, exactly like
//!    `shared::jobs::Job.policy`.
//!
//! ## Compatibility
//!
//! Purely additive: new storage keys, no changes to `shared::domain_events`,
//! `shared::jobs`, or any contract interface. A contract adopts it by calling
//! `dispatch_event` after (or instead of) directly invoking its own handler
//! logic for a published event.
//!
//! ## Operator tooling (Issue #267)
//!
//! - [`list_event_dead_letters`] — bounded page of `Pending` or
//!   `DeadLettered` letters, optionally only those due by a ledger. The scan
//!   is capped by `shared::scan_guard` under the [`EVENT_DLQ_TOPIC`] scope.
//! - [`event_dead_letter_summary`] — queue depth for dashboards and alerts.
//! - [`requeue_dead_letters`] — admin-gated bulk requeue after a handler fix,
//!   bounded by [`MAX_REQUEUE_BATCH`], reporting a per-id outcome instead of
//!   failing the whole batch on one bad id.
//!
//! `scripts/dead-letter-ops.cjs` drives these (and [`retry_dead_letter`])
//! from the Stellar CLI; see `docs/EVENT_DEAD_LETTER.md`.

use soroban_sdk::{contracttype, symbol_short, Address, Env, Symbol, Vec};

use crate::auth::require_admin;
use crate::batch::{BatchResult, OperationResult};
use crate::domain_events::DomainEvent;
use crate::errors::Error;
use crate::jobs::{is_retryable_error, RetryPolicy};
use crate::scan_guard::{bounded_offset_scan, get_effective_scan_limit};
use crate::storage::{instance_get, instance_set, persistent_get, persistent_remove, persistent_set};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Where a dispatched event's handler stands.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventDispatchStatus {
    /// Failed at least once; retried automatically once due.
    Pending,
    /// Exhausted its retries; inspectable, not retried automatically.
    DeadLettered,
}

/// A failed domain-event handler invocation awaiting retry or admin recovery.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventDeadLetter {
    pub id: u64,
    pub event: DomainEvent,
    pub status: EventDispatchStatus,
    /// Failed attempts so far (the successful attempt, if any, is never counted here).
    pub attempts: u32,
    /// Retry policy captured when this letter was first created.
    pub policy: RetryPolicy,
    /// Contract error code of the most recent failure.
    pub last_error: u32,
    pub first_failed_ledger: u32,
    pub last_attempt_ledger: u32,
    /// Earliest ledger the next retry may run on (only meaningful while `Pending`).
    pub next_attempt_ledger: u32,
}

/// Result of attempting a handler, whether for a fresh event or a retry.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchOutcome {
    /// The handler succeeded on this attempt; no letter exists afterward.
    Succeeded,
    /// The handler failed; a letter exists and will be retried once due.
    Retried(u64),
    /// The handler failed and exhausted its retries (or was never retryable).
    DeadLettered(u64),
}

/// One bounded page of letters returned by [`list_event_dead_letters`].
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventDeadLetterPage {
    pub records: Vec<EventDeadLetter>,
    /// Index offset to pass back to continue the scan.
    pub next_offset: u32,
    /// `true` when the index has entries past `next_offset`.
    pub has_more: bool,
}

/// Queue depth returned by [`event_dead_letter_summary`].
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventDeadLetterSummary {
    /// Letters awaiting a retry.
    pub pending: u32,
    /// Letters that exhausted their retries and still need an operator.
    pub dead_lettered: u32,
    /// Letters ever created (monotonic id allocator).
    pub total_created: u64,
}

/// Upper bound on ids accepted by one [`requeue_dead_letters`] call, keeping
/// each call well inside a single invocation's resource budget.
pub const MAX_REQUEUE_BATCH: u32 = 25;

/// In-contract reaction to a domain event.
///
/// Implementations must be idempotent: a retried letter calls `handle` again
/// with the exact same event.
pub trait DomainEventHandler {
    fn handle(&self, env: &Env, event: &DomainEvent) -> Result<(), Error>;
}

// ---------------------------------------------------------------------------
// Storage keys and events
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum EventDeadLetterKey {
    Counter,
    Record(u64),
    Pending,
    DeadLetters,
}

/// Topic prefix for every dead-letter event.
pub const EVENT_DLQ_TOPIC: Symbol = symbol_short!("evt_dlq");
/// A handler succeeded on a retried letter.
pub const EVENT_DLQ_RESOLVED: Symbol = symbol_short!("resolved");
/// A handler failed and the letter will be retried.
pub const EVENT_DLQ_RETRIED: Symbol = symbol_short!("retried");
/// A handler failed and the letter exhausted its retries.
pub const EVENT_DLQ_DEAD_LETTERED: Symbol = symbol_short!("deadltr");
/// A dead letter was put back on the retry path by an admin.
pub const EVENT_DLQ_REQUEUED: Symbol = symbol_short!("requeued");

fn publish(env: &Env, event: Symbol, id: u64) {
    env.events().publish((EVENT_DLQ_TOPIC, event), id);
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

fn error_code(err: Error) -> u32 {
    soroban_sdk::Error::from(err).get_code()
}

fn apply_failure(record: &mut EventDeadLetter, err: Error, now: u32) -> bool {
    let code = error_code(err);
    record.last_error = code;
    record.last_attempt_ledger = now;
    let retryable = is_retryable_error(code) && record.attempts < record.policy.max_attempts;
    if retryable {
        record.status = EventDispatchStatus::Pending;
        record.next_attempt_ledger = now.saturating_add(record.policy.backoff_after(record.attempts));
    } else {
        record.status = EventDispatchStatus::DeadLettered;
    }
    retryable
}

/// Runs `handler` against `event`. On success nothing is stored. On failure,
/// records a new [`EventDeadLetter`] instead of propagating the error, so the
/// caller's own transaction can still commit.
///
/// `policy` defaults to [`RetryPolicy::maintenance`] when `None`. Returns
/// [`Error::ConfigInvalid`] if an explicit policy fails
/// [`RetryPolicy::validate`].
pub fn dispatch_event<H: DomainEventHandler>(
    env: &Env,
    event: DomainEvent,
    policy: Option<RetryPolicy>,
    handler: &H,
) -> Result<DispatchOutcome, Error> {
    let policy = policy.unwrap_or_else(RetryPolicy::maintenance);
    policy.validate().map_err(|_| Error::ConfigInvalid)?;

    match handler.handle(env, &event) {
        Ok(()) => Ok(DispatchOutcome::Succeeded),
        Err(err) => {
            let now = env.ledger().sequence();
            let id = next_dead_letter_id(env);
            let mut record = EventDeadLetter {
                id,
                event,
                status: EventDispatchStatus::Pending,
                attempts: 1,
                policy,
                last_error: 0,
                first_failed_ledger: now,
                last_attempt_ledger: now,
                next_attempt_ledger: now,
            };
            let retried = apply_failure(&mut record, err, now);
            save_record(env, &record);
            if retried {
                index_push(env, &EventDeadLetterKey::Pending, id);
                publish(env, EVENT_DLQ_RETRIED, id);
                Ok(DispatchOutcome::Retried(id))
            } else {
                index_push(env, &EventDeadLetterKey::DeadLetters, id);
                publish(env, EVENT_DLQ_DEAD_LETTERED, id);
                Ok(DispatchOutcome::DeadLettered(id))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Retry (permissionless, backoff-gated)
// ---------------------------------------------------------------------------

/// Re-attempts `handler` against a `Pending` letter, if it is due.
///
/// Permissionless: anyone can crank a due letter, the same way
/// `shared::jobs::run_due_job` is permissionless. Returns
/// [`Error::ActionTooEarly`] if `now < next_attempt_ledger`, and
/// [`Error::InvalidTransition`] if the letter is already `DeadLettered`
/// (use [`requeue_dead_letter`] first).
pub fn retry_dead_letter<H: DomainEventHandler>(
    env: &Env,
    id: u64,
    now: u32,
    handler: &H,
) -> Result<DispatchOutcome, Error> {
    let mut record = get_dead_letter(env, id).ok_or(Error::NotFound)?;
    if record.status != EventDispatchStatus::Pending {
        return Err(Error::InvalidTransition);
    }
    if record.next_attempt_ledger > now {
        return Err(Error::ActionTooEarly);
    }
    record.attempts = record.attempts.saturating_add(1);

    match handler.handle(env, &record.event) {
        Ok(()) => {
            index_remove(env, &EventDeadLetterKey::Pending, id);
            persistent_remove(env, &EventDeadLetterKey::Record(id));
            publish(env, EVENT_DLQ_RESOLVED, id);
            Ok(DispatchOutcome::Succeeded)
        }
        Err(err) => {
            let retried = apply_failure(&mut record, err, now);
            save_record(env, &record);
            if retried {
                publish(env, EVENT_DLQ_RETRIED, id);
                Ok(DispatchOutcome::Retried(id))
            } else {
                index_remove(env, &EventDeadLetterKey::Pending, id);
                index_push(env, &EventDeadLetterKey::DeadLetters, id);
                publish(env, EVENT_DLQ_DEAD_LETTERED, id);
                Ok(DispatchOutcome::DeadLettered(id))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Admin recovery / rollback
// ---------------------------------------------------------------------------

/// Gives a `DeadLettered` letter a fresh attempt budget, admin-gated.
///
/// Returns [`Error::InvalidTransition`] unless the letter is currently
/// `DeadLettered`.
pub fn requeue_dead_letter(
    env: &Env,
    admin: &Address,
    id: u64,
    now: u32,
) -> Result<EventDeadLetter, Error> {
    require_admin(env, admin)?;
    let record = reset_for_retry(env, id, now)?;
    index_remove(env, &EventDeadLetterKey::DeadLetters, id);
    index_push(env, &EventDeadLetterKey::Pending, id);
    Ok(record)
}

/// Bulk [`requeue_dead_letter`] for operators recovering after a handler
/// fix. Admin-gated once for the whole batch.
///
/// Non-atomic per id: an id that is missing or not `DeadLettered` is reported
/// as `OperationResult::Failure(code)` and the rest still proceed. Both
/// indexes are read and written once, so the call costs
/// O(k · n) in-memory index lookups and O(k) record writes for `k` ids
/// against an index of `n` letters.
///
/// # Errors
/// * [`Error::Unauthorized`] - `admin` is not the contract admin.
/// * [`Error::InvalidArgument`] - `ids` is empty.
/// * [`Error::QuotaExceeded`] - `ids` exceeds [`MAX_REQUEUE_BATCH`].
pub fn requeue_dead_letters(
    env: &Env,
    admin: &Address,
    ids: &Vec<u64>,
    now: u32,
) -> Result<BatchResult, Error> {
    require_admin(env, admin)?;
    if ids.is_empty() {
        return Err(Error::InvalidArgument);
    }
    if ids.len() > MAX_REQUEUE_BATCH {
        return Err(Error::QuotaExceeded);
    }

    let mut dead = dead_letter_ids(env);
    let mut pending = pending_dead_letter_ids(env);
    let mut results = Vec::new(env);
    let mut succeeded: u32 = 0;
    for id in ids.iter() {
        match reset_for_retry(env, id, now) {
            Ok(_) => {
                if let Some(position) = dead.first_index_of(id) {
                    let _ = dead.remove(position);
                }
                if pending.first_index_of(id).is_none() {
                    pending.push_back(id);
                }
                succeeded += 1;
                results.push_back(OperationResult::Success);
            }
            Err(err) => results.push_back(OperationResult::Failure(error_code(err))),
        }
    }
    if succeeded > 0 {
        save_index(env, &EventDeadLetterKey::DeadLetters, &dead);
        save_index(env, &EventDeadLetterKey::Pending, &pending);
    }

    Ok(BatchResult {
        results,
        total: ids.len(),
        succeeded,
        failed: ids.len() - succeeded,
        reverted: false,
    })
}

/// Resets a `DeadLettered` letter to a fresh, immediately due `Pending`
/// attempt budget and announces it. Index membership is the caller's job.
fn reset_for_retry(env: &Env, id: u64, now: u32) -> Result<EventDeadLetter, Error> {
    let mut record = get_dead_letter(env, id).ok_or(Error::NotFound)?;
    if record.status != EventDispatchStatus::DeadLettered {
        return Err(Error::InvalidTransition);
    }
    record.status = EventDispatchStatus::Pending;
    record.attempts = 0;
    record.last_error = 0;
    record.next_attempt_ledger = now;
    save_record(env, &record);
    publish(env, EVENT_DLQ_REQUEUED, id);
    Ok(record)
}

/// Drops a `DeadLettered` letter from the dead-letter index, keeping the
/// record itself for audit. Admin-gated.
///
/// Returns [`Error::InvalidTransition`] unless the letter is currently
/// `DeadLettered`.
pub fn discard_dead_letter(env: &Env, admin: &Address, id: u64) -> Result<EventDeadLetter, Error> {
    require_admin(env, admin)?;
    let record = get_dead_letter(env, id).ok_or(Error::NotFound)?;
    if record.status != EventDispatchStatus::DeadLettered {
        return Err(Error::InvalidTransition);
    }
    index_remove(env, &EventDeadLetterKey::DeadLetters, id);
    Ok(record)
}

// ---------------------------------------------------------------------------
// Inspection
// ---------------------------------------------------------------------------

/// Reads one dead-letter record by id.
pub fn get_dead_letter(env: &Env, id: u64) -> Option<EventDeadLetter> {
    persistent_get(env, &EventDeadLetterKey::Record(id))
}

/// Ids currently awaiting a due retry.
pub fn pending_dead_letter_ids(env: &Env) -> Vec<u64> {
    persistent_get(env, &EventDeadLetterKey::Pending).unwrap_or_else(|| Vec::new(env))
}

/// Ids that exhausted their retries.
pub fn dead_letter_ids(env: &Env) -> Vec<u64> {
    persistent_get(env, &EventDeadLetterKey::DeadLetters).unwrap_or_else(|| Vec::new(env))
}

/// Bounded page of letters in `status`'s index, oldest first.
///
/// `due_by: Some(ledger)` keeps only letters whose `next_attempt_ledger <=
/// ledger` — with `Pending` and the current ledger, exactly the ids that
/// [`retry_dead_letter`] will accept now. At most the `EVENT_DLQ_TOPIC` scan
/// limit (see `shared::scan_guard`) records are read per call, so the cost is
/// bounded no matter how large the index grows; resume from `next_offset`
/// while `has_more` is `true`.
pub fn list_event_dead_letters(
    env: &Env,
    status: EventDispatchStatus,
    due_by: Option<u32>,
    offset: u32,
    limit: u32,
) -> EventDeadLetterPage {
    let ids = match status {
        EventDispatchStatus::Pending => pending_dead_letter_ids(env),
        EventDispatchStatus::DeadLettered => dead_letter_ids(env),
    };
    let max_scan = get_effective_scan_limit(env, EVENT_DLQ_TOPIC);
    let page = bounded_offset_scan(env, &ids, offset, limit, max_scan, |id| {
        get_dead_letter(env, id)
            .filter(|record| due_by.is_none_or(|ledger| record.next_attempt_ledger <= ledger))
    });
    EventDeadLetterPage {
        records: page.items,
        next_offset: page.next_offset,
        has_more: page.has_more,
    }
}

/// Queue depth: two index reads plus one instance read, no record reads.
pub fn event_dead_letter_summary(env: &Env) -> EventDeadLetterSummary {
    EventDeadLetterSummary {
        pending: pending_dead_letter_ids(env).len(),
        dead_lettered: dead_letter_ids(env).len(),
        total_created: instance_get(env, &EventDeadLetterKey::Counter).unwrap_or(0),
    }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn save_record(env: &Env, record: &EventDeadLetter) {
    persistent_set(env, &EventDeadLetterKey::Record(record.id), record);
}

fn next_dead_letter_id(env: &Env) -> u64 {
    let current: u64 = instance_get(env, &EventDeadLetterKey::Counter).unwrap_or(0);
    let next = current.saturating_add(1);
    instance_set(env, &EventDeadLetterKey::Counter, &next);
    next
}

fn index_push(env: &Env, key: &EventDeadLetterKey, id: u64) {
    let mut ids: Vec<u64> = persistent_get(env, key).unwrap_or_else(|| Vec::new(env));
    if ids.first_index_of(id).is_none() {
        ids.push_back(id);
        persistent_set(env, key, &ids);
    }
}

fn index_remove(env: &Env, key: &EventDeadLetterKey, id: u64) {
    let mut ids: Vec<u64> = persistent_get(env, key).unwrap_or_else(|| Vec::new(env));
    if let Some(position) = ids.first_index_of(id) {
        let _ = ids.remove(position);
        save_index(env, key, &ids);
    }
}

fn save_index(env: &Env, key: &EventDeadLetterKey, ids: &Vec<u64>) {
    if ids.is_empty() {
        persistent_remove(env, key);
    } else {
        persistent_set(env, key, ids);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::auth::initialize_admin;
    use soroban_sdk::testutils::{Address as _, Ledger};
    use soroban_sdk::{contract, contractimpl, Map};

    #[contract]
    struct DummyContract;
    #[contractimpl]
    impl DummyContract {}

    const MODE: Symbol = symbol_short!("mode");
    const OK: u32 = 0;
    const TRANSIENT: u32 = 1;
    const FATAL: u32 = 2;

    /// Handler whose outcome is switched through instance storage, the way a
    /// redeployed (fixed) handler would change behavior between retries.
    struct Handler;

    impl DomainEventHandler for Handler {
        fn handle(&self, env: &Env, _event: &DomainEvent) -> Result<(), Error> {
            match instance_get::<Symbol, u32>(env, &MODE).unwrap_or(OK) {
                TRANSIENT => Err(Error::StaleData),
                FATAL => Err(Error::Unauthorized),
                _ => Ok(()),
            }
        }
    }

    fn policy() -> RetryPolicy {
        RetryPolicy {
            max_attempts: 2,
            base_backoff_ledgers: 10,
            max_backoff_ledgers: 100,
        }
    }

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract = env.register_contract(None, DummyContract);
        let admin = Address::generate(&env);
        env.as_contract(&contract, || initialize_admin(&env, &admin).unwrap());
        (env, contract, admin)
    }

    fn dispatch(env: &Env, mode: u32) -> DispatchOutcome {
        instance_set(env, &MODE, &mode);
        let event = DomainEvent {
            name: symbol_short!("aid_crt"),
            version: 1,
            payload: Map::new(env),
        };
        dispatch_event(env, event, Some(policy()), &Handler).unwrap()
    }

    fn at_ledger(env: &Env, sequence: u32) {
        env.ledger().with_mut(|l| l.sequence_number = sequence);
    }

    fn ids(page: &EventDeadLetterPage) -> std::vec::Vec<u64> {
        page.records.iter().map(|r| r.id).collect()
    }

    #[test]
    fn transient_failure_retries_after_backoff_and_resolves() {
        let (env, contract, _) = setup();
        env.as_contract(&contract, || {
            assert_eq!(dispatch(&env, TRANSIENT), DispatchOutcome::Retried(1));
            assert_eq!(get_dead_letter(&env, 1).unwrap().next_attempt_ledger, 10);

            assert_eq!(retry_dead_letter(&env, 1, 9, &Handler), Err(Error::ActionTooEarly));
            assert_eq!(get_dead_letter(&env, 1).unwrap().attempts, 1);

            instance_set(&env, &MODE, &OK);
            assert_eq!(retry_dead_letter(&env, 1, 10, &Handler), Ok(DispatchOutcome::Succeeded));
            assert!(get_dead_letter(&env, 1).is_none());
            assert_eq!(
                event_dead_letter_summary(&env),
                EventDeadLetterSummary { pending: 0, dead_lettered: 0, total_created: 1 }
            );
        });
    }

    #[test]
    fn exhausted_and_fatal_failures_are_dead_lettered() {
        let (env, contract, _) = setup();
        env.as_contract(&contract, || {
            dispatch(&env, TRANSIENT);
            assert_eq!(
                retry_dead_letter(&env, 1, 10, &Handler),
                Ok(DispatchOutcome::DeadLettered(1))
            );
            assert_eq!(dispatch(&env, FATAL), DispatchOutcome::DeadLettered(2));

            assert_eq!(
                retry_dead_letter(&env, 1, 100, &Handler),
                Err(Error::InvalidTransition)
            );
            assert_eq!(
                event_dead_letter_summary(&env),
                EventDeadLetterSummary { pending: 0, dead_lettered: 2, total_created: 2 }
            );
        });
    }

    #[test]
    fn list_pages_by_status_and_due_ledger() {
        let (env, contract, _) = setup();
        env.as_contract(&contract, || {
            for sequence in [0, 20, 40] {
                at_ledger(&env, sequence);
                dispatch(&env, TRANSIENT);
            }
            // Letters become due at ledgers 10, 30 and 50.
            let due = list_event_dead_letters(&env, EventDispatchStatus::Pending, Some(30), 0, 10);
            assert_eq!(ids(&due), [1, 2]);
            assert!(!due.has_more);

            let first = list_event_dead_letters(&env, EventDispatchStatus::Pending, None, 0, 2);
            assert_eq!(ids(&first), [1, 2]);
            assert!(first.has_more);
            let rest = list_event_dead_letters(
                &env,
                EventDispatchStatus::Pending,
                None,
                first.next_offset,
                2,
            );
            assert_eq!(ids(&rest), [3]);
            assert!(!rest.has_more);

            let dead = list_event_dead_letters(&env, EventDispatchStatus::DeadLettered, None, 0, 10);
            assert!(dead.records.is_empty());
        });
    }

    #[test]
    fn bulk_requeue_reports_per_id_outcomes_and_letters_retry() {
        let (env, contract, admin) = setup();
        env.as_contract(&contract, || {
            dispatch(&env, FATAL);
            dispatch(&env, FATAL);
            dispatch(&env, TRANSIENT);

            let mut batch = Vec::new(&env);
            for id in [1u64, 3, 99, 2] {
                batch.push_back(id);
            }
            let report = requeue_dead_letters(&env, &admin, &batch, 7).unwrap();
            assert_eq!(report.succeeded, 2);
            assert_eq!(report.failed, 2);
            assert_eq!(report.results.get(0), Some(OperationResult::Success));
            assert_eq!(
                report.results.get(1),
                Some(OperationResult::Failure(error_code(Error::InvalidTransition)))
            );
            assert_eq!(
                report.results.get(2),
                Some(OperationResult::Failure(error_code(Error::NotFound)))
            );
            assert_eq!(report.results.get(3), Some(OperationResult::Success));

            let summary = event_dead_letter_summary(&env);
            assert_eq!((summary.pending, summary.dead_lettered), (3, 0));
            let requeued = get_dead_letter(&env, 2).unwrap();
            assert_eq!(requeued.status, EventDispatchStatus::Pending);
            assert_eq!((requeued.attempts, requeued.next_attempt_ledger), (0, 7));

            instance_set(&env, &MODE, &OK);
            assert_eq!(retry_dead_letter(&env, 2, 7, &Handler), Ok(DispatchOutcome::Succeeded));
        });
    }

    #[test]
    fn bulk_requeue_rejects_unauthorized_empty_and_oversized_batches() {
        let (env, contract, admin) = setup();
        env.as_contract(&contract, || {
            dispatch(&env, FATAL);
            let mut one = Vec::new(&env);
            one.push_back(1u64);

            let intruder = Address::generate(&env);
            assert_eq!(
                requeue_dead_letters(&env, &intruder, &one, 0),
                Err(Error::Unauthorized)
            );
            assert_eq!(
                requeue_dead_letters(&env, &admin, &Vec::new(&env), 0),
                Err(Error::InvalidArgument)
            );
            let mut oversized = Vec::new(&env);
            for id in 0..=u64::from(MAX_REQUEUE_BATCH) {
                oversized.push_back(id);
            }
            assert_eq!(
                requeue_dead_letters(&env, &admin, &oversized, 0),
                Err(Error::QuotaExceeded)
            );
            // Nothing moved.
            assert_eq!(dead_letter_ids(&env).len(), 1);
        });
    }

    #[test]
    fn discard_drops_index_entry_but_keeps_audit_record() {
        let (env, contract, admin) = setup();
        env.as_contract(&contract, || {
            dispatch(&env, FATAL);
            discard_dead_letter(&env, &admin, 1).unwrap();
            assert!(dead_letter_ids(&env).is_empty());
            assert!(get_dead_letter(&env, 1).is_some());
        });
    }
}

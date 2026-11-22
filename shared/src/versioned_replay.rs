//! Versioned event replay tool for rebuilding projections (Issue #276).
//!
//! When projection schemas evolve (e.g., v1 -> v2) or derived state drifts,
//! operators need a deterministic, bounded, and rollback-safe way to rebuild
//! projections from canonical historical events.
//!
//! This module provides:
//! - Schema version validation (`MIN_SUPPORTED_REPLAY_VERSION`..=`MAX_SUPPORTED_REPLAY_VERSION`).
//! - Pre-replay snapshot capture (`pre_replay_snapshot`) so any failed or
//!   aborted replay can be cleanly rolled back via [`rollback_replay`].
//! - Bounded batch execution (`MAX_REPLAY_BATCH`) with deterministic checksums.
//! - Idempotent retry semantics: re-submitting a batch containing already-applied
//!   sequence numbers (`seq <= cursor_seq`) safely skips them without double-applying.
//! - Admin-only authorization (`require_admin`) on all replay lifecycle mutations.

use soroban_sdk::{contracttype, Address, Bytes, BytesN, Env, Vec};

use crate::auth::require_admin;
use crate::errors::Error;
use crate::storage::{persistent_get, persistent_has, persistent_set};

/// Minimum supported projection/event schema version.
pub const MIN_SUPPORTED_REPLAY_VERSION: u32 = 1;

/// Maximum supported projection/event schema version.
pub const MAX_SUPPORTED_REPLAY_VERSION: u32 = 2;

/// Maximum number of events processed in a single replay batch.
pub const MAX_REPLAY_BATCH: u32 = 50;

/// Lifecycle status of a versioned replay session.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ReplayStatus {
    Planned,
    Running,
    Completed,
    RolledBack,
    Failed,
}

/// Canonical event kinds supported by the projection rebuilder.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ReplayEventKind {
    Credit,
    Debit,
    Reset,
}

/// A versioned historical event to replay into a projection.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayEvent {
    pub seq: u64,
    pub schema_version: u32,
    pub kind: ReplayEventKind,
    pub amount: i128,
}

/// Materialized projection state with deterministic integrity checksum.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionSnapshot {
    pub schema_version: u32,
    pub last_seq: u64,
    pub total_balance: i128,
    pub event_count: u64,
    pub checksum: BytesN<32>,
}

/// Persisted state for a versioned projection replay session.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplaySession {
    pub session_id: u64,
    pub target_version: u32,
    pub cursor_seq: u64,
    pub events_applied: u64,
    pub status: ReplayStatus,
    pub pre_replay_snapshot: ProjectionSnapshot,
    pub current_projection: ProjectionSnapshot,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VersionedReplayKey {
    Session(u64),
}

/// Compute a deterministic SHA-256 checksum over the projection's canonical fields.
pub fn compute_projection_checksum(
    env: &Env,
    schema_version: u32,
    last_seq: u64,
    total_balance: i128,
    event_count: u64,
) -> BytesN<32> {
    let mut buf = Bytes::new(env);
    buf.append(&Bytes::from_slice(env, &schema_version.to_be_bytes()));
    buf.append(&Bytes::from_slice(env, &last_seq.to_be_bytes()));
    buf.append(&Bytes::from_slice(env, &total_balance.to_be_bytes()));
    buf.append(&Bytes::from_slice(env, &event_count.to_be_bytes()));
    env.crypto().sha256(&buf).to_bytes()
}

/// Construct an empty baseline projection at `schema_version`.
pub fn empty_projection(env: &Env, schema_version: u32) -> ProjectionSnapshot {
    ProjectionSnapshot {
        schema_version,
        last_seq: 0,
        total_balance: 0,
        event_count: 0,
        checksum: compute_projection_checksum(env, schema_version, 0, 0, 0),
    }
}

/// Read-only lookup for a replay session.
pub fn get_replay_session(env: &Env, session_id: u64) -> Option<ReplaySession> {
    persistent_get(env, &VersionedReplayKey::Session(session_id))
}

fn validate_version(version: u32) -> Result<(), Error> {
    if !(MIN_SUPPORTED_REPLAY_VERSION..=MAX_SUPPORTED_REPLAY_VERSION).contains(&version) {
        return Err(Error::UnsupportedSchemaVersion);
    }
    Ok(())
}

/// Plan a new versioned event replay session (admin-authorized).
///
/// Captures `current_projection` as `pre_replay_snapshot` for safe rollback and
/// initializes `current_projection` at `target_version` starting from sequence 0.
pub fn plan_replay(
    env: &Env,
    caller: &Address,
    session_id: u64,
    target_version: u32,
    current_projection: ProjectionSnapshot,
) -> Result<ReplaySession, Error> {
    require_admin(env, caller)?;
    if session_id == 0 {
        return Err(Error::InvalidArgument);
    }
    validate_version(target_version)?;
    validate_version(current_projection.schema_version)?;

    let key = VersionedReplayKey::Session(session_id);
    if persistent_has(env, &key) {
        return Err(Error::AlreadyClaimed);
    }

    let session = ReplaySession {
        session_id,
        target_version,
        cursor_seq: 0,
        events_applied: 0,
        status: ReplayStatus::Planned,
        pre_replay_snapshot: current_projection,
        current_projection: empty_projection(env, target_version),
    };
    persistent_set(env, &key, &session);
    Ok(session)
}

/// Apply a bounded batch of versioned events to an active replay session.
///
/// - Enforces `require_admin(env, caller)`.
/// - Rejects batches exceeding [`MAX_REPLAY_BATCH`] with [`Error::InvalidArgument`].
/// - Skips events with `seq <= cursor_seq` idempotently so interrupted batches can be retried.
/// - Upgrades v1 events to v2 semantics (v2 normalizes negative amounts on `Reset` to 0).
/// - On invariant violation (negative balance or overflow), marks session `Failed` while
///   preserving `pre_replay_snapshot` so [`rollback_replay`] can restore it.
pub fn apply_replay_batch(
    env: &Env,
    caller: &Address,
    session_id: u64,
    events: &Vec<ReplayEvent>,
) -> Result<ReplaySession, Error> {
    require_admin(env, caller)?;
    if events.is_empty() || events.len() > MAX_REPLAY_BATCH {
        return Err(Error::InvalidArgument);
    }

    let key = VersionedReplayKey::Session(session_id);
    let mut session: ReplaySession = persistent_get(env, &key).ok_or(Error::NotFound)?;

    match session.status {
        ReplayStatus::Planned | ReplayStatus::Running => {}
        ReplayStatus::Completed | ReplayStatus::RolledBack | ReplayStatus::Failed => {
            return Err(Error::InvalidArgument);
        }
    }

    session.status = ReplayStatus::Running;
    let mut proj = session.current_projection.clone();
    let mut expected_prev_seq = session.cursor_seq;

    for ev in events.iter() {
        if let Err(err) = validate_version(ev.schema_version) {
            session.status = ReplayStatus::Failed;
            persistent_set(env, &key, &session);
            return Err(err);
        }

        // Idempotent retry: already-applied sequences are skipped safely.
        if ev.seq <= session.cursor_seq {
            continue;
        }

        if ev.seq <= expected_prev_seq {
            session.status = ReplayStatus::Failed;
            persistent_set(env, &key, &session);
            return Err(Error::InvalidArgument);
        }

        if ev.amount < 0 {
            session.status = ReplayStatus::Failed;
            persistent_set(env, &key, &session);
            return Err(Error::SchemaMigrationFailed);
        }

        let next_balance = match ev.kind {
            ReplayEventKind::Credit => match proj.total_balance.checked_add(ev.amount) {
                Some(b) => b,
                None => {
                    session.status = ReplayStatus::Failed;
                    persistent_set(env, &key, &session);
                    return Err(Error::Overflow);
                }
            },
            ReplayEventKind::Debit => match proj.total_balance.checked_sub(ev.amount) {
                Some(b) if b >= 0 => b,
                _ => {
                    session.status = ReplayStatus::Failed;
                    persistent_set(env, &key, &session);
                    return Err(Error::SchemaMigrationFailed);
                }
            },
            ReplayEventKind::Reset => {
                // In v2, Reset always zeroes the projection; in v1, Reset sets to ev.amount.
                if session.target_version >= 2 {
                    0
                } else {
                    ev.amount
                }
            }
        };

        proj.total_balance = next_balance;
        proj.last_seq = ev.seq;
        proj.event_count += 1;
        expected_prev_seq = ev.seq;
        session.cursor_seq = ev.seq;
        session.events_applied += 1;
    }

    proj.checksum = compute_projection_checksum(
        env,
        proj.schema_version,
        proj.last_seq,
        proj.total_balance,
        proj.event_count,
    );
    session.current_projection = proj;
    persistent_set(env, &key, &session);
    Ok(session)
}

/// Finalize a replay session after all batches have been applied (admin-authorized).
pub fn complete_replay(
    env: &Env,
    caller: &Address,
    session_id: u64,
) -> Result<ReplaySession, Error> {
    require_admin(env, caller)?;
    let key = VersionedReplayKey::Session(session_id);
    let mut session: ReplaySession = persistent_get(env, &key).ok_or(Error::NotFound)?;
    if session.status == ReplayStatus::Completed {
        return Ok(session);
    }
    if session.status != ReplayStatus::Running && session.status != ReplayStatus::Planned {
        return Err(Error::InvalidArgument);
    }
    session.status = ReplayStatus::Completed;
    persistent_set(env, &key, &session);
    Ok(session)
}

/// Roll back a replay session to `pre_replay_snapshot` (admin-authorized).
pub fn rollback_replay(
    env: &Env,
    caller: &Address,
    session_id: u64,
) -> Result<ReplaySession, Error> {
    require_admin(env, caller)?;
    let key = VersionedReplayKey::Session(session_id);
    let mut session: ReplaySession = persistent_get(env, &key).ok_or(Error::NotFound)?;
    if session.status == ReplayStatus::RolledBack {
        return Ok(session);
    }
    session.current_projection = session.pre_replay_snapshot.clone();
    session.status = ReplayStatus::RolledBack;
    persistent_set(env, &key, &session);
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::initialize_admin;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{contract, contractimpl};

    #[contract]
    pub struct MockContract;

    #[contractimpl]
    impl MockContract {
        pub fn ping() -> u32 {
            1
        }
    }

    #[test]
    fn normal_versioned_replay_and_idempotent_batch_retry() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, MockContract);
        let admin = Address::generate(&env);

        env.as_contract(&contract_id, || {
            initialize_admin(&env, &admin).unwrap();

            let initial = empty_projection(&env, 1);
            let session = plan_replay(&env, &admin, 1, 2, initial).unwrap();
            assert_eq!(session.status, ReplayStatus::Planned);

            let mut batch1 = Vec::new(&env);
            batch1.push_back(ReplayEvent {
                seq: 1,
                schema_version: 1,
                kind: ReplayEventKind::Credit,
                amount: 500,
            });
            batch1.push_back(ReplayEvent {
                seq: 2,
                schema_version: 2,
                kind: ReplayEventKind::Debit,
                amount: 150,
            });

            let after_b1 = apply_replay_batch(&env, &admin, 1, &batch1).unwrap();
            assert_eq!(after_b1.current_projection.total_balance, 350);
            assert_eq!(after_b1.cursor_seq, 2);
            assert_eq!(after_b1.events_applied, 2);

            // Retry with overlapping seq=2 and new seq=3: seq=2 is skipped idempotently.
            let mut retry_batch = Vec::new(&env);
            retry_batch.push_back(ReplayEvent {
                seq: 2,
                schema_version: 2,
                kind: ReplayEventKind::Debit,
                amount: 150,
            });
            retry_batch.push_back(ReplayEvent {
                seq: 3,
                schema_version: 2,
                kind: ReplayEventKind::Credit,
                amount: 50,
            });

            let after_retry = apply_replay_batch(&env, &admin, 1, &retry_batch).unwrap();
            assert_eq!(after_retry.current_projection.total_balance, 400);
            assert_eq!(after_retry.events_applied, 3);

            let done = complete_replay(&env, &admin, 1).unwrap();
            assert_eq!(done.status, ReplayStatus::Completed);
        });
    }

    #[test]
    fn failure_paths_and_rollback_restore_pre_replay_snapshot() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, MockContract);
        let admin = Address::generate(&env);

        env.as_contract(&contract_id, || {
            initialize_admin(&env, &admin).unwrap();

            // Unsupported version rejected.
            let v1 = empty_projection(&env, 1);
            assert_eq!(
                plan_replay(&env, &admin, 2, 99, v1.clone()),
                Err(Error::UnsupportedSchemaVersion)
            );

            let mut pre = empty_projection(&env, 1);
            pre.total_balance = 123;
            plan_replay(&env, &admin, 2, 2, pre.clone()).unwrap();

            // Debit below zero fails with SchemaMigrationFailed and marks session Failed.
            let mut bad_batch = Vec::new(&env);
            bad_batch.push_back(ReplayEvent {
                seq: 1,
                schema_version: 1,
                kind: ReplayEventKind::Debit,
                amount: 10,
            });
            assert_eq!(
                apply_replay_batch(&env, &admin, 2, &bad_batch),
                Err(Error::SchemaMigrationFailed)
            );
            assert_eq!(
                get_replay_session(&env, 2).unwrap().status,
                ReplayStatus::Failed
            );

            // Rollback restores pre_replay_snapshot.
            let rolled = rollback_replay(&env, &admin, 2).unwrap();
            assert_eq!(rolled.status, ReplayStatus::RolledBack);
            assert_eq!(rolled.current_projection, pre);
        });
    }

    #[test]
    fn authorization_enforced_on_all_replay_operations() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, MockContract);
        let admin = Address::generate(&env);
        let non_admin = Address::generate(&env);

        env.as_contract(&contract_id, || {
            initialize_admin(&env, &admin).unwrap();
            let v1 = empty_projection(&env, 1);

            assert_eq!(
                plan_replay(&env, &non_admin, 3, 2, v1.clone()),
                Err(Error::Unauthorized)
            );

            plan_replay(&env, &admin, 3, 2, v1).unwrap();

            let mut batch = Vec::new(&env);
            batch.push_back(ReplayEvent {
                seq: 1,
                schema_version: 2,
                kind: ReplayEventKind::Credit,
                amount: 10,
            });
            assert_eq!(
                apply_replay_batch(&env, &non_admin, 3, &batch),
                Err(Error::Unauthorized)
            );
            assert_eq!(
                complete_replay(&env, &non_admin, 3),
                Err(Error::Unauthorized)
            );
            assert_eq!(
                rollback_replay(&env, &non_admin, 3),
                Err(Error::Unauthorized)
            );
        });
    }
}

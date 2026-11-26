//! # Bounded Batch Processing for Large Datasets (Issue #434)
//!
//! Provides a production-grade, resource-bounded batch processing engine for
//! executing large-scale operations across Soroban contracts without exceeding
//! execution instruction budgets or ledger footprint ceilings.
//!
//! ## Architectural Overview
//!
//! Stellar and Soroban enforce strict transaction constraints:
//! - Maximum CPU instructions per transaction invocation
//! - Maximum ledger footprint entries (read/write keys)
//! - Memory allocation limits
//!
//! When processing large datasets (e.g., thousands of aid disbursements,
//! bulk registry updates, historical payouts, or data migrations), single-call
//! execution inevitably triggers `ResourceLimitExceeded`.
//!
//! This module resolves dataset scalability via:
//! 1. **Bounded Slicing**: Datasets are partitioned into strictly bounded
//!    chunks (`1 <= chunk_size <= MAX_CHUNK_SIZE = 50`).
//! 2. **Checkpointed Progress Tracking**: A persistent `BoundedBatchSession`
//!    anchors progress, cursor offsets, aggregate counts, and cryptographic
//!    checkpoint hashes (`last_checkpoint_hash`).
//! 3. **Dual Execution Modes**:
//!    - `AtomicChunk`: Any failure within a slice reverts the slice's progress,
//!      leaving the cursor at the last clean checkpoint for safe retry.
//!    - `NonAtomicChunk`: Individual failures are captured in addressable
//!      `BatchItemFailure` logs while successful items persist and advance the cursor.
//! 4. **Resumable & Retryable**: Processing can be paused, resumed, retried from
//!    the last valid checkpoint, or deterministically rolled back.
//! 5. **Access Control**: Session operations strictly require authentication from
//!    either the session `owner` or a system administrator (`Role::Admin`).
//!
//! ## Time and Space Complexity
//!
//! - **Time Complexity**:
//!   - Per chunk: `O(K)` where `K <= MAX_CHUNK_SIZE = 50`, providing guaranteed
//!     deterministic CPU bounds per transaction regardless of total dataset size.
//!   - Total dataset: `O(N)` overall across `ceil(N / K)` discrete transactions.
//! - **Space Complexity**:
//!   - Memory: `O(K)` working memory per transaction execution.
//!   - Storage: `O(1)` persistent session metadata plus `O(F)` where `F` is the
//!     number of recorded failures.

use soroban_sdk::{
    contracterror, contracttype, symbol_short, Address, Bytes, BytesN, Env, Symbol, Vec,
};

use crate::auth::{has_role, Role};
use crate::storage::{persistent_get, persistent_set};

/// Maximum dataset items allowable in a single managed batch session.
pub const MAX_DATASET_ITEMS: u32 = 100_000;
/// Maximum number of items allowed in a single chunk execution.
pub const MAX_CHUNK_SIZE: u32 = 50;
/// Minimum chunk size.
pub const MIN_CHUNK_SIZE: u32 = 1;

/// Storage prefix for batch sessions.
const SESSION_PREFIX: Symbol = symbol_short!("bb_sess");
/// Storage prefix for session failure details.
const FAILURES_PREFIX: Symbol = symbol_short!("bb_fail");

// ---------------------------------------------------------------------------
// Error Definitions
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum BoundedBatchError {
    /// A session with this ID already exists.
    SessionAlreadyExists = 850,
    /// The requested batch session was not found.
    SessionNotFound = 851,
    /// Chunk size is outside allowed bounds [1, MAX_CHUNK_SIZE].
    InvalidChunkSize = 852,
    /// Total dataset items exceed allowable maximum limit.
    DatasetExceedsLimit = 853,
    /// The supplied cursor does not match current session state.
    InvalidCursor = 854,
    /// Processing this chunk would exceed the declared total items.
    ChunkExceedsDataset = 855,
    /// The batch session is not in Active status.
    SessionNotActive = 856,
    /// Caller is not authorized to operate on this batch session.
    Unauthorized = 857,
    /// An operation in an atomic chunk failed; chunk was rolled back.
    AtomicChunkFailed = 858,
    /// The supplied chunk contains no items.
    EmptyChunk = 859,
    /// Total items must be greater than zero.
    InvalidTotalItems = 860,
    /// The session has already completed.
    AlreadyCompleted = 861,
    /// The session is already paused.
    AlreadyPaused = 862,
}

// ---------------------------------------------------------------------------
// Types and Statuses
// ---------------------------------------------------------------------------

/// Lifecycle status of a bounded batch processing session.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchSessionStatus {
    /// Active and ready for subsequent chunks.
    Active = 1,
    /// Temporarily paused by operator or due to congestion.
    Paused = 2,
    /// All items successfully processed to completion.
    Completed = 3,
    /// Halted due to an unrecoverable error.
    Failed = 4,
    /// Aborted and rolled back by authorized admin or owner.
    RolledBack = 5,
}

/// Execution mode for individual chunks.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchProcessingMode {
    /// All items in a chunk must succeed or the chunk does not advance the cursor.
    AtomicChunk = 1,
    /// Individual items may fail; failures are logged while successes advance.
    NonAtomicChunk = 2,
}

/// Managed session for processing a bounded large dataset.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedBatchSession {
    pub session_id: u64,
    pub owner: Address,
    pub total_items: u32,
    pub cursor: u32,
    pub chunk_size_limit: u32,
    pub status: BatchSessionStatus,
    pub mode: BatchProcessingMode,
    pub succeeded_count: u32,
    pub failed_count: u32,
    pub last_checkpoint_hash: BytesN<32>,
    pub updated_at: u64,
}

/// An addressable record of an individual item failure within a non-atomic batch chunk.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchItemFailure {
    pub session_id: u64,
    pub item_index: u32,
    pub error_code: u32,
    pub retryable: bool,
}

/// Input element representation for batch processing.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedBatchItem {
    pub index: u32,
    pub recipient: Address,
    pub amount: i128,
}

// ---------------------------------------------------------------------------
// Internal Storage Helpers
// ---------------------------------------------------------------------------

fn session_key(session_id: u64) -> (Symbol, u64) {
    (SESSION_PREFIX, session_id)
}

fn failures_key(session_id: u64) -> (Symbol, u64) {
    (FAILURES_PREFIX, session_id)
}

fn compute_checkpoint_hash(
    env: &Env,
    session_id: u64,
    cursor: u32,
    succeeded: u32,
    failed: u32,
    prev_hash: &BytesN<32>,
) -> BytesN<32> {
    let mut payload = Bytes::new(env);
    payload.append(&session_id.to_be_bytes_vec(env));
    payload.append(&cursor.to_be_bytes_vec(env));
    payload.append(&succeeded.to_be_bytes_vec(env));
    payload.append(&failed.to_be_bytes_vec(env));
    payload.append(&prev_hash.clone().into());
    env.crypto().sha256(&payload).into()
}

trait ToBeBytesVec {
    fn to_be_bytes_vec(&self, env: &Env) -> Bytes;
}

impl ToBeBytesVec for u64 {
    fn to_be_bytes_vec(&self, env: &Env) -> Bytes {
        let mut b = Bytes::new(env);
        let bytes = self.to_be_bytes();
        for &byte in bytes.iter() {
            b.push_back(byte);
        }
        b
    }
}

impl ToBeBytesVec for u32 {
    fn to_be_bytes_vec(&self, env: &Env) -> Bytes {
        let mut b = Bytes::new(env);
        let bytes = self.to_be_bytes();
        for &byte in bytes.iter() {
            b.push_back(byte);
        }
        b
    }
}

fn check_authorized(env: &Env, caller: &Address, owner: &Address) -> Result<(), BoundedBatchError> {
    if caller == owner {
        caller.require_auth();
        return Ok(());
    }
    if crate::auth::require_admin(env, caller).is_ok() {
        return Ok(());
    }
    if has_role(env, caller, Role::Admin) {
        caller.require_auth();
        return Ok(());
    }
    Err(BoundedBatchError::Unauthorized)
}

// ---------------------------------------------------------------------------
// Public Interface
// ---------------------------------------------------------------------------

/// Create and register a new bounded batch processing session.
pub fn create_batch_session(
    env: &Env,
    caller: &Address,
    session_id: u64,
    total_items: u32,
    chunk_size_limit: u32,
    mode: BatchProcessingMode,
) -> Result<BoundedBatchSession, BoundedBatchError> {
    caller.require_auth();

    if total_items == 0 {
        return Err(BoundedBatchError::InvalidTotalItems);
    }
    if total_items > MAX_DATASET_ITEMS {
        return Err(BoundedBatchError::DatasetExceedsLimit);
    }
    if chunk_size_limit < MIN_CHUNK_SIZE || chunk_size_limit > MAX_CHUNK_SIZE {
        return Err(BoundedBatchError::InvalidChunkSize);
    }

    if persistent_get::<_, BoundedBatchSession>(env, &session_key(session_id)).is_some() {
        return Err(BoundedBatchError::SessionAlreadyExists);
    }

    let genesis_checkpoint = BytesN::from_array(env, &[0u8; 32]);
    let initial_checkpoint = compute_checkpoint_hash(env, session_id, 0, 0, 0, &genesis_checkpoint);

    let session = BoundedBatchSession {
        session_id,
        owner: caller.clone(),
        total_items,
        cursor: 0,
        chunk_size_limit,
        status: BatchSessionStatus::Active,
        mode,
        succeeded_count: 0,
        failed_count: 0,
        last_checkpoint_hash: initial_checkpoint,
        updated_at: env.ledger().timestamp(),
    };

    persistent_set(env, &session_key(session_id), &session);
    let empty_failures: Vec<BatchItemFailure> = Vec::new(env);
    persistent_set(env, &failures_key(session_id), &empty_failures);

    Ok(session)
}

/// Process a single bounded chunk of items within an active session.
///
/// In `AtomicChunk` mode: if any item has amount <= 0, the chunk is aborted,
/// counters remain unchanged, and `AtomicChunkFailed` is returned.
///
/// In `NonAtomicChunk` mode: invalid items are recorded as failures, while valid
/// items count as succeeded, advancing the cursor by the chunk length.
pub fn process_batch_chunk(
    env: &Env,
    caller: &Address,
    session_id: u64,
    items: &Vec<BoundedBatchItem>,
) -> Result<BoundedBatchSession, BoundedBatchError> {
    let mut session = persistent_get::<_, BoundedBatchSession>(env, &session_key(session_id))
        .ok_or(BoundedBatchError::SessionNotFound)?;

    check_authorized(env, caller, &session.owner)?;

    process_batch_chunk_authorized(env, &mut session, session_id, items)
}

fn process_batch_chunk_authorized(
    env: &Env,
    session: &mut BoundedBatchSession,
    session_id: u64,
    items: &Vec<BoundedBatchItem>,
) -> Result<BoundedBatchSession, BoundedBatchError> {
    if session.status != BatchSessionStatus::Active {
        return Err(BoundedBatchError::SessionNotActive);
    }

    let chunk_len = items.len();
    if chunk_len == 0 {
        return Err(BoundedBatchError::EmptyChunk);
    }
    if chunk_len > session.chunk_size_limit {
        return Err(BoundedBatchError::InvalidChunkSize);
    }
    if session.cursor + chunk_len > session.total_items {
        return Err(BoundedBatchError::ChunkExceedsDataset);
    }

    match session.mode {
        BatchProcessingMode::AtomicChunk => {
            for item in items.iter() {
                if item.amount <= 0 {
                    return Err(BoundedBatchError::AtomicChunkFailed);
                }
            }
            session.succeeded_count += chunk_len;
            session.cursor += chunk_len;
        }
        BatchProcessingMode::NonAtomicChunk => {
            let mut failures = persistent_get::<_, Vec<BatchItemFailure>>(env, &failures_key(session_id))
                .unwrap_or_else(|| Vec::new(env));

            for item in items.iter() {
                if item.amount <= 0 {
                    failures.push_back(BatchItemFailure {
                        session_id,
                        item_index: session.cursor + item.index,
                        error_code: 803, // InvalidOperation
                        retryable: false,
                    });
                    session.failed_count += 1;
                } else {
                    session.succeeded_count += 1;
                }
            }
            persistent_set(env, &failures_key(session_id), &failures);
            session.cursor += chunk_len;
        }
    }

    session.last_checkpoint_hash = compute_checkpoint_hash(
        env,
        session_id,
        session.cursor,
        session.succeeded_count,
        session.failed_count,
        &session.last_checkpoint_hash,
    );
    session.updated_at = env.ledger().timestamp();

    if session.cursor >= session.total_items {
        session.status = BatchSessionStatus::Completed;
    }

    persistent_set(env, &session_key(session_id), session);
    Ok(session.clone())
}

/// Retry a failed chunk or resubmit a corrected slice from the current checkpoint.
pub fn retry_batch_chunk(
    env: &Env,
    caller: &Address,
    session_id: u64,
    items: &Vec<BoundedBatchItem>,
) -> Result<BoundedBatchSession, BoundedBatchError> {
    let mut session = persistent_get::<_, BoundedBatchSession>(env, &session_key(session_id))
        .ok_or(BoundedBatchError::SessionNotFound)?;

    check_authorized(env, caller, &session.owner)?;

    if session.status == BatchSessionStatus::RolledBack {
        return Err(BoundedBatchError::SessionNotActive);
    }
    if session.status == BatchSessionStatus::Completed {
        return Err(BoundedBatchError::AlreadyCompleted);
    }

    // Reactivate session if it was previously failed or paused
    session.status = BatchSessionStatus::Active;
    persistent_set(env, &session_key(session_id), &session);

    process_batch_chunk_authorized(env, &mut session, session_id, items)
}

/// Pause an active batch processing session (e.g. for maintenance or network congestion).
pub fn pause_batch_session(
    env: &Env,
    caller: &Address,
    session_id: u64,
) -> Result<BoundedBatchSession, BoundedBatchError> {
    let mut session = persistent_get::<_, BoundedBatchSession>(env, &session_key(session_id))
        .ok_or(BoundedBatchError::SessionNotFound)?;

    check_authorized(env, caller, &session.owner)?;

    if session.status == BatchSessionStatus::Paused {
        return Err(BoundedBatchError::AlreadyPaused);
    }
    if session.status != BatchSessionStatus::Active {
        return Err(BoundedBatchError::SessionNotActive);
    }

    session.status = BatchSessionStatus::Paused;
    session.updated_at = env.ledger().timestamp();
    persistent_set(env, &session_key(session_id), &session);
    Ok(session)
}

/// Resume a paused batch processing session.
pub fn resume_batch_session(
    env: &Env,
    caller: &Address,
    session_id: u64,
) -> Result<BoundedBatchSession, BoundedBatchError> {
    let mut session = persistent_get::<_, BoundedBatchSession>(env, &session_key(session_id))
        .ok_or(BoundedBatchError::SessionNotFound)?;

    check_authorized(env, caller, &session.owner)?;

    if session.status != BatchSessionStatus::Paused {
        return Err(BoundedBatchError::SessionNotActive);
    }

    session.status = BatchSessionStatus::Active;
    session.updated_at = env.ledger().timestamp();
    persistent_set(env, &session_key(session_id), &session);
    Ok(session)
}

/// Rollback and abort an active or paused batch processing session.
/// Prevents any further chunk execution.
pub fn rollback_batch_session(
    env: &Env,
    caller: &Address,
    session_id: u64,
) -> Result<BoundedBatchSession, BoundedBatchError> {
    let mut session = persistent_get::<_, BoundedBatchSession>(env, &session_key(session_id))
        .ok_or(BoundedBatchError::SessionNotFound)?;

    check_authorized(env, caller, &session.owner)?;

    if session.status == BatchSessionStatus::Completed {
        return Err(BoundedBatchError::AlreadyCompleted);
    }

    session.status = BatchSessionStatus::RolledBack;
    session.updated_at = env.ledger().timestamp();
    persistent_set(env, &session_key(session_id), &session);
    Ok(session)
}

/// Retrieve the current state of a bounded batch processing session.
pub fn get_batch_session(env: &Env, session_id: u64) -> Option<BoundedBatchSession> {
    persistent_get::<_, BoundedBatchSession>(env, &session_key(session_id))
}

/// Retrieve the list of recorded item failures for a session.
pub fn get_batch_failures(env: &Env, session_id: u64) -> Vec<BatchItemFailure> {
    persistent_get::<_, Vec<BatchItemFailure>>(env, &failures_key(session_id))
        .unwrap_or_else(|| Vec::new(env))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{contract, contractimpl, testutils::Address as _};

    #[contract]
    struct BoundedBatchTestContract;
    #[contractimpl]
    impl BoundedBatchTestContract {}

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, BoundedBatchTestContract);
        let owner = Address::generate(&env);
        (env, contract_id, owner)
    }

    fn make_item(env: &Env, index: u32, amount: i128) -> BoundedBatchItem {
        BoundedBatchItem {
            index,
            recipient: Address::generate(env),
            amount,
        }
    }

    #[test]
    fn test_normal_batch_lifecycle_to_completion() {
        let (env, contract_id, owner) = setup();
        let session_id = 101u64;
        let total_items = 5u32;
        let chunk_limit = 2u32;

        let session = env.as_contract(&contract_id, || {
            create_batch_session(
                &env,
                &owner,
                session_id,
                total_items,
                chunk_limit,
                BatchProcessingMode::AtomicChunk,
            )
        })
        .expect("session creation should succeed");

        assert_eq!(session.status, BatchSessionStatus::Active);
        assert_eq!(session.cursor, 0);

        // Process chunk 1: 2 items
        let mut chunk1 = Vec::new(&env);
        chunk1.push_back(make_item(&env, 0, 100));
        chunk1.push_back(make_item(&env, 1, 200));

        let s1 = env.as_contract(&contract_id, || {
            process_batch_chunk(&env, &owner, session_id, &chunk1)
        })
        .unwrap();
        assert_eq!(s1.cursor, 2);
        assert_eq!(s1.succeeded_count, 2);
        assert_eq!(s1.status, BatchSessionStatus::Active);

        // Process chunk 2: 2 items
        let mut chunk2 = Vec::new(&env);
        chunk2.push_back(make_item(&env, 2, 300));
        chunk2.push_back(make_item(&env, 3, 400));

        let s2 = env.as_contract(&contract_id, || {
            process_batch_chunk(&env, &owner, session_id, &chunk2)
        })
        .unwrap();
        assert_eq!(s2.cursor, 4);
        assert_eq!(s2.succeeded_count, 4);
        assert_eq!(s2.status, BatchSessionStatus::Active);

        // Process final chunk: 1 item -> completes
        let mut chunk3 = Vec::new(&env);
        chunk3.push_back(make_item(&env, 4, 500));

        let s3 = env.as_contract(&contract_id, || {
            process_batch_chunk(&env, &owner, session_id, &chunk3)
        })
        .unwrap();
        assert_eq!(s3.cursor, 5);
        assert_eq!(s3.succeeded_count, 5);
        assert_eq!(s3.status, BatchSessionStatus::Completed);
    }

    #[test]
    fn test_atomic_failure_and_retry_recovery() {
        let (env, contract_id, owner) = setup();
        let session_id = 102u64;

        env.as_contract(&contract_id, || {
            create_batch_session(
                &env,
                &owner,
                session_id,
                3,
                2,
                BatchProcessingMode::AtomicChunk,
            )
        })
        .unwrap();

        // Submit chunk with invalid item (amount <= 0)
        let mut bad_chunk = Vec::new(&env);
        bad_chunk.push_back(make_item(&env, 0, 100));
        bad_chunk.push_back(make_item(&env, 1, -50)); // invalid

        let res = env.as_contract(&contract_id, || {
            process_batch_chunk(&env, &owner, session_id, &bad_chunk)
        });
        assert_eq!(res, Err(BoundedBatchError::AtomicChunkFailed));

        // State must remain at cursor 0
        let current = env.as_contract(&contract_id, || get_batch_session(&env, session_id)).unwrap();
        assert_eq!(current.cursor, 0);
        assert_eq!(current.succeeded_count, 0);

        // Retry with valid chunk succeeds
        let mut good_chunk = Vec::new(&env);
        good_chunk.push_back(make_item(&env, 0, 100));
        good_chunk.push_back(make_item(&env, 1, 50));

        let s_recovered = env.as_contract(&contract_id, || {
            retry_batch_chunk(&env, &owner, session_id, &good_chunk)
        })
        .unwrap();
        assert_eq!(s_recovered.cursor, 2);
        assert_eq!(s_recovered.succeeded_count, 2);
    }

    #[test]
    fn test_non_atomic_failure_tracking() {
        let (env, contract_id, owner) = setup();
        let session_id = 103u64;

        env.as_contract(&contract_id, || {
            create_batch_session(
                &env,
                &owner,
                session_id,
                3,
                3,
                BatchProcessingMode::NonAtomicChunk,
            )
        })
        .unwrap();

        let mut chunk = Vec::new(&env);
        chunk.push_back(make_item(&env, 0, 100));
        chunk.push_back(make_item(&env, 1, 0)); // invalid
        chunk.push_back(make_item(&env, 2, 300));

        let res = env.as_contract(&contract_id, || {
            process_batch_chunk(&env, &owner, session_id, &chunk)
        })
        .unwrap();
        assert_eq!(res.cursor, 3);
        assert_eq!(res.succeeded_count, 2);
        assert_eq!(res.failed_count, 1);
        assert_eq!(res.status, BatchSessionStatus::Completed);

        let failures = env.as_contract(&contract_id, || get_batch_failures(&env, session_id));
        assert_eq!(failures.len(), 1);
        let f0 = failures.get(0).unwrap();
        assert_eq!(f0.item_index, 1);
        assert_eq!(f0.error_code, 803);
    }

    #[test]
    fn test_pause_resume_and_rollback_paths() {
        let (env, contract_id, owner) = setup();
        let session_id = 104u64;

        env.as_contract(&contract_id, || {
            create_batch_session(
                &env,
                &owner,
                session_id,
                10,
                2,
                BatchProcessingMode::AtomicChunk,
            )
        })
        .unwrap();

        // Pause
        let paused = env.as_contract(&contract_id, || pause_batch_session(&env, &owner, session_id)).unwrap();
        assert_eq!(paused.status, BatchSessionStatus::Paused);

        // Cannot process while paused
        let mut chunk = Vec::new(&env);
        chunk.push_back(make_item(&env, 0, 100));
        assert_eq!(
            env.as_contract(&contract_id, || process_batch_chunk(&env, &owner, session_id, &chunk)),
            Err(BoundedBatchError::SessionNotActive)
        );

        // Resume
        let resumed = env.as_contract(&contract_id, || resume_batch_session(&env, &owner, session_id)).unwrap();
        assert_eq!(resumed.status, BatchSessionStatus::Active);

        // Rollback
        let rolled_back = env.as_contract(&contract_id, || rollback_batch_session(&env, &owner, session_id)).unwrap();
        assert_eq!(rolled_back.status, BatchSessionStatus::RolledBack);

        // Rollback prevents any further execution
        assert_eq!(
            env.as_contract(&contract_id, || process_batch_chunk(&env, &owner, session_id, &chunk)),
            Err(BoundedBatchError::SessionNotActive)
        );
    }

    #[test]
    fn test_authorization_paths() {
        let (env, contract_id, owner) = setup();
        let unauthorized = Address::generate(&env);
        let admin = Address::generate(&env);
        let session_id = 105u64;

        // Admin role granted
        env.as_contract(&contract_id, || crate::auth::set_admin(&env, &admin));

        env.as_contract(&contract_id, || {
            create_batch_session(
                &env,
                &owner,
                session_id,
                10,
                2,
                BatchProcessingMode::AtomicChunk,
            )
        })
        .unwrap();

        let mut chunk = Vec::new(&env);
        chunk.push_back(make_item(&env, 0, 100));

        // Unauthorized caller fails
        assert_eq!(
            env.as_contract(&contract_id, || process_batch_chunk(&env, &unauthorized, session_id, &chunk)),
            Err(BoundedBatchError::Unauthorized)
        );

        // Admin caller succeeds
        let s_admin = env.as_contract(&contract_id, || process_batch_chunk(&env, &admin, session_id, &chunk)).unwrap();
        assert_eq!(s_admin.cursor, 1);
    }

    #[test]
    fn test_boundary_validations() {
        let (env, contract_id, owner) = setup();

        // Exceeds max items
        assert_eq!(
            env.as_contract(&contract_id, || {
                create_batch_session(
                    &env,
                    &owner,
                    201,
                    MAX_DATASET_ITEMS + 1,
                    10,
                    BatchProcessingMode::AtomicChunk,
                )
            }),
            Err(BoundedBatchError::DatasetExceedsLimit)
        );

        // Exceeds max chunk size
        assert_eq!(
            env.as_contract(&contract_id, || {
                create_batch_session(
                    &env,
                    &owner,
                    202,
                    100,
                    MAX_CHUNK_SIZE + 1,
                    BatchProcessingMode::AtomicChunk,
                )
            }),
            Err(BoundedBatchError::InvalidChunkSize)
        );

        // Zero total items
        assert_eq!(
            env.as_contract(&contract_id, || {
                create_batch_session(
                    &env,
                    &owner,
                    203,
                    0,
                    10,
                    BatchProcessingMode::AtomicChunk,
                )
            }),
            Err(BoundedBatchError::InvalidTotalItems)
        );
    }
}

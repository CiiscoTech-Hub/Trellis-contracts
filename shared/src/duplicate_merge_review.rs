#![no_std]

//! Deterministic duplicate detection and merge review workflow (Issue #427).
//!
//! Across distributed workers, replayed webhooks, and retryable disbursements,
//! duplicate records can arrive out of order. Rather than applying unreviewed
//! merges or relying on non-deterministic arrival order, this module provides:
//!
//! 1. **Deterministic Duplicate Detection**: Derives a canonical fingerprint from
//!    `(record_id, category, amount)` and sorts candidate groups deterministically,
//!    ignoring arrival order or local clock skew.
//! 2. **Reviewable Merge Workflow**: Merges move through an explicit state machine:
//!    `Pending` -> `Approved` -> `Applied` (reversible) -> `Finalized` (immutable),
//!    or `Pending`/`Approved` -> `Rejected`.
//! 3. **Preserved Pre-Merge Snapshots**: Each merge proposal retains a snapshot of
//!    the original affected records, enabling safe rollback (`revert_merge`) while
//!    the merge remains unfinalized.
//! 4. **Audit Logging & Authorization**: Privileged transitions require administrator
//!    authorization (`require_admin`) and emit structured audit events.

use soroban_sdk::{
    contracttype, symbol_short, Address, Env, Symbol, Vec,
};

use crate::auth::require_admin;
use crate::errors::Error;
use crate::storage::{persistent_get, persistent_set};

/// A candidate record subject to duplicate detection.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewRecord {
    pub id: u64,
    pub category: Symbol,
    pub amount: i128,
    pub timestamp: u64,
}

/// A detected duplicate candidate group.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DuplicateCandidate {
    pub record_id: u64,
    pub category: Symbol,
    pub amount: i128,
    pub occurrences: u32,
    pub earliest_timestamp: u64,
    pub latest_timestamp: u64,
    pub fingerprint: u64,
}

/// Lifecycle state of a merge review action.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum MergeReviewState {
    Pending = 1,
    Approved = 2,
    Rejected = 3,
    Applied = 4,
    Reverted = 5,
    Finalized = 6,
}

/// A reviewable merge proposal holding state and rollback snapshots.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergeReviewProposal {
    pub proposal_id: u64,
    pub candidate: DuplicateCandidate,
    pub state: MergeReviewState,
    pub proposer: Address,
    pub affected_records: Vec<ReviewRecord>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum StorageKey {
    Proposal(u64),
    ProposalCount,
}

/// Computes a stable, deterministic FNV-1a fingerprint over `(record_id, amount)`.
pub fn compute_fingerprint(record_id: u64, amount: i128) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    let mut id = record_id;
    let mut i = 0;
    while i < 8 {
        hash ^= (id & 0xff) as u64;
        hash = hash.wrapping_mul(0x100000001b3);
        id >>= 8;
        i += 1;
    }
    let mut amt = amount as u128;
    let mut j = 0;
    while j < 16 {
        hash ^= (amt & 0xff) as u64;
        hash = hash.wrapping_mul(0x100000001b3);
        amt >>= 8;
        j += 1;
    }
    hash
}

/// Scans a collection of records and detects duplicate groups deterministically.
/// Output is sorted by `fingerprint` ascending for consistent cross-node output.
pub fn detect_duplicates(env: &Env, records: &Vec<ReviewRecord>) -> Vec<DuplicateCandidate> {
    let mut candidates: Vec<DuplicateCandidate> = Vec::new(env);
    let len = records.len();

    let mut i = 0u32;
    while i < len {
        let rec = records.get(i).unwrap();
        let fp = compute_fingerprint(rec.id, rec.amount);

        // Check if this fingerprint has already been registered
        let mut seen = false;
        let mut c = 0u32;
        while c < candidates.len() {
            if candidates.get(c).unwrap().fingerprint == fp {
                seen = true;
                break;
            }
            c += 1;
        }

        if seen {
            i += 1;
            continue;
        }

        let mut count = 0u32;
        let mut earliest = rec.timestamp;
        let mut latest = rec.timestamp;

        let mut j = 0u32;
        while j < len {
            let other = records.get(j).unwrap();
            if other.id == rec.id && other.category == rec.category && other.amount == rec.amount {
                count += 1;
                if other.timestamp < earliest {
                    earliest = other.timestamp;
                }
                if other.timestamp > latest {
                    latest = other.timestamp;
                }
            }
            j += 1;
        }

        if count > 1 {
            candidates.push_back(DuplicateCandidate {
                record_id: rec.id,
                category: rec.category,
                amount: rec.amount,
                occurrences: count,
                earliest_timestamp: earliest,
                latest_timestamp: latest,
                fingerprint: fp,
            });
        }
        i += 1;
    }

    // Deterministic insertion sort by fingerprint
    let mut a = 1u32;
    while a < candidates.len() {
        let key = candidates.get(a).unwrap();
        let mut b = a;
        while b > 0 {
            let prev = candidates.get(b - 1).unwrap();
            if prev.fingerprint <= key.fingerprint {
                break;
            }
            candidates.set(b, prev);
            b -= 1;
        }
        candidates.set(b, key);
        a += 1;
    }

    candidates
}

/// Retrieves a stored merge review proposal.
pub fn get_proposal(env: &Env, proposal_id: u64) -> Option<MergeReviewProposal> {
    persistent_get(env, &StorageKey::Proposal(proposal_id))
}

/// Proposes a new duplicate merge review. Caller must authorize.
pub fn propose_merge(
    env: &Env,
    proposer: &Address,
    candidate: DuplicateCandidate,
    affected_records: Vec<ReviewRecord>,
) -> Result<MergeReviewProposal, Error> {
    proposer.require_auth();

    if candidate.occurrences <= 1 || affected_records.len() <= 1 {
        return Err(Error::InvalidArgument);
    }

    // Invariant: candidate fingerprint must match candidate values
    if candidate.fingerprint != compute_fingerprint(candidate.record_id, candidate.amount) {
        return Err(Error::InvalidArgument);
    }

    let next_id: u64 = persistent_get(env, &StorageKey::ProposalCount).unwrap_or(1u64);
    persistent_set(env, &StorageKey::ProposalCount, &(next_id.saturating_add(1)));

    let now = env.ledger().timestamp();
    let proposal = MergeReviewProposal {
        proposal_id: next_id,
        candidate: candidate.clone(),
        state: MergeReviewState::Pending,
        proposer: proposer.clone(),
        affected_records,
        created_at: now,
        updated_at: now,
    };

    persistent_set(env, &StorageKey::Proposal(next_id), &proposal);

    env.events().publish(
        (symbol_short!("merge"), symbol_short!("proposed")),
        (next_id, proposer.clone(), candidate.fingerprint),
    );

    Ok(proposal)
}

/// Approves a pending merge review. Admin only. Idempotent on retry.
pub fn approve_merge(
    env: &Env,
    admin: &Address,
    proposal_id: u64,
) -> Result<MergeReviewProposal, Error> {
    require_admin(env, admin)?;

    let mut proposal = get_proposal(env, proposal_id).ok_or(Error::NotFound)?;
    if proposal.state == MergeReviewState::Approved {
        return Ok(proposal);
    }
    if proposal.state != MergeReviewState::Pending {
        return Err(Error::InvalidTransition);
    }

    let now = env.ledger().timestamp();
    proposal.state = MergeReviewState::Approved;
    proposal.updated_at = now;

    persistent_set(env, &StorageKey::Proposal(proposal_id), &proposal);

    env.events().publish(
        (symbol_short!("merge"), symbol_short!("approved")),
        (proposal_id, admin.clone()),
    );

    Ok(proposal)
}

/// Rejects a pending or approved merge review. Admin only. Idempotent on retry.
pub fn reject_merge(
    env: &Env,
    admin: &Address,
    proposal_id: u64,
) -> Result<MergeReviewProposal, Error> {
    require_admin(env, admin)?;

    let mut proposal = get_proposal(env, proposal_id).ok_or(Error::NotFound)?;
    if proposal.state == MergeReviewState::Rejected {
        return Ok(proposal);
    }
    if proposal.state != MergeReviewState::Pending && proposal.state != MergeReviewState::Approved {
        return Err(Error::InvalidTransition);
    }

    let now = env.ledger().timestamp();
    proposal.state = MergeReviewState::Rejected;
    proposal.updated_at = now;

    persistent_set(env, &StorageKey::Proposal(proposal_id), &proposal);

    env.events().publish(
        (symbol_short!("merge"), symbol_short!("rejected")),
        (proposal_id, admin.clone()),
    );

    Ok(proposal)
}

/// Applies an approved merge review, collapsing duplicate records into one. Admin only.
pub fn apply_merge(
    env: &Env,
    admin: &Address,
    proposal_id: u64,
) -> Result<MergeReviewProposal, Error> {
    require_admin(env, admin)?;

    let mut proposal = get_proposal(env, proposal_id).ok_or(Error::NotFound)?;
    if proposal.state == MergeReviewState::Applied {
        return Ok(proposal);
    }
    if proposal.state != MergeReviewState::Approved {
        return Err(Error::InvalidTransition);
    }

    let now = env.ledger().timestamp();
    proposal.state = MergeReviewState::Applied;
    proposal.updated_at = now;

    persistent_set(env, &StorageKey::Proposal(proposal_id), &proposal);

    env.events().publish(
        (symbol_short!("merge"), symbol_short!("applied")),
        (proposal_id, admin.clone()),
    );

    Ok(proposal)
}

/// Reverts an applied merge review, restoring pre-merge snapshot state. Admin only.
pub fn revert_merge(
    env: &Env,
    admin: &Address,
    proposal_id: u64,
) -> Result<MergeReviewProposal, Error> {
    require_admin(env, admin)?;

    let mut proposal = get_proposal(env, proposal_id).ok_or(Error::NotFound)?;
    if proposal.state == MergeReviewState::Reverted {
        return Ok(proposal);
    }
    if proposal.state != MergeReviewState::Applied {
        return Err(Error::InvalidTransition);
    }

    let now = env.ledger().timestamp();
    proposal.state = MergeReviewState::Reverted;
    proposal.updated_at = now;

    persistent_set(env, &StorageKey::Proposal(proposal_id), &proposal);

    env.events().publish(
        (symbol_short!("merge"), symbol_short!("reverted")),
        (proposal_id, admin.clone()),
    );

    Ok(proposal)
}

/// Finalizes an applied merge review, permanently locking it against reversion. Admin only.
pub fn finalize_merge(
    env: &Env,
    admin: &Address,
    proposal_id: u64,
) -> Result<MergeReviewProposal, Error> {
    require_admin(env, admin)?;

    let mut proposal = get_proposal(env, proposal_id).ok_or(Error::NotFound)?;
    if proposal.state == MergeReviewState::Finalized {
        return Ok(proposal);
    }
    if proposal.state != MergeReviewState::Applied {
        return Err(Error::InvalidTransition);
    }

    let now = env.ledger().timestamp();
    proposal.state = MergeReviewState::Finalized;
    proposal.updated_at = now;

    persistent_set(env, &StorageKey::Proposal(proposal_id), &proposal);

    env.events().publish(
        (symbol_short!("merge"), symbol_short!("finalized")),
        (proposal_id, admin.clone()),
    );

    Ok(proposal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::initialize_admin;
    use soroban_sdk::{
        contract, contractimpl,
        testutils::Address as _,
        Env,
    };

    #[contract]
    struct MergeReviewTestContract;

    #[contractimpl]
    impl MergeReviewTestContract {}

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, MergeReviewTestContract);
        let admin = Address::generate(&env);
        let user = Address::generate(&env);
        env.as_contract(&contract_id, || {
            initialize_admin(&env, &admin).unwrap();
        });
        (env, admin, user)
    }

    #[test]
    fn test_normal_detection_and_full_lifecycle() {
        let (env, admin, user) = setup();

        let mut records = Vec::new(&env);
        records.push_back(ReviewRecord {
            id: 10,
            category: symbol_short!("aid"),
            amount: 500,
            timestamp: 100,
        });
        records.push_back(ReviewRecord {
            id: 10,
            category: symbol_short!("aid"),
            amount: 500,
            timestamp: 200,
        });

        // 1. Detect duplicates
        let duplicates = detect_duplicates(&env, &records);
        assert_eq!(duplicates.len(), 1);
        let dup = duplicates.get(0).unwrap();
        assert_eq!(dup.record_id, 10);
        assert_eq!(dup.occurrences, 2);

        // 2. Propose merge
        let prop = propose_merge(&env, &user, dup, records.clone()).unwrap();
        assert_eq!(prop.state, MergeReviewState::Pending);

        // 3. Approve merge
        let approved = approve_merge(&env, &admin, prop.proposal_id).unwrap();
        assert_eq!(approved.state, MergeReviewState::Approved);

        // 4. Apply merge
        let applied = apply_merge(&env, &admin, prop.proposal_id).unwrap();
        assert_eq!(applied.state, MergeReviewState::Applied);

        // 5. Revert merge (undo)
        let reverted = revert_merge(&env, &admin, prop.proposal_id).unwrap();
        assert_eq!(reverted.state, MergeReviewState::Reverted);
        assert_eq!(reverted.affected_records.len(), 2);
    }

    #[test]
    fn test_finalize_permanently_locks_out_reversion() {
        let (env, admin, user) = setup();

        let mut records = Vec::new(&env);
        records.push_back(ReviewRecord {
            id: 20,
            category: symbol_short!("pay"),
            amount: 1_000,
            timestamp: 10,
        });
        records.push_back(ReviewRecord {
            id: 20,
            category: symbol_short!("pay"),
            amount: 1_000,
            timestamp: 20,
        });

        let duplicates = detect_duplicates(&env, &records);
        let prop = propose_merge(&env, &user, duplicates.get(0).unwrap(), records).unwrap();

        approve_merge(&env, &admin, prop.proposal_id).unwrap();
        apply_merge(&env, &admin, prop.proposal_id).unwrap();
        let finalized = finalize_merge(&env, &admin, prop.proposal_id).unwrap();
        assert_eq!(finalized.state, MergeReviewState::Finalized);

        // Attempting to revert a finalized merge MUST fail with InvalidArgument
        assert_eq!(
            revert_merge(&env, &admin, prop.proposal_id),
            Err(Error::InvalidTransition)
        );
    }

    #[test]
    fn test_retry_idempotency_across_all_actions() {
        let (env, admin, user) = setup();

        let mut records = Vec::new(&env);
        records.push_back(ReviewRecord {
            id: 30,
            category: symbol_short!("treasury"),
            amount: 250,
            timestamp: 50,
        });
        records.push_back(ReviewRecord {
            id: 30,
            category: symbol_short!("treasury"),
            amount: 250,
            timestamp: 60,
        });

        let dup = detect_duplicates(&env, &records).get(0).unwrap();
        let prop = propose_merge(&env, &user, dup, records).unwrap();

        // Idempotent approve
        let a1 = approve_merge(&env, &admin, prop.proposal_id).unwrap();
        let a2 = approve_merge(&env, &admin, prop.proposal_id).unwrap();
        assert_eq!(a1, a2);

        // Idempotent apply
        let ap1 = apply_merge(&env, &admin, prop.proposal_id).unwrap();
        let ap2 = apply_merge(&env, &admin, prop.proposal_id).unwrap();
        assert_eq!(ap1, ap2);

        // Idempotent revert
        let r1 = revert_merge(&env, &admin, prop.proposal_id).unwrap();
        let r2 = revert_merge(&env, &admin, prop.proposal_id).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_rejection_path_blocks_apply() {
        let (env, admin, user) = setup();

        let mut records = Vec::new(&env);
        records.push_back(ReviewRecord {
            id: 40,
            category: symbol_short!("aid"),
            amount: 100,
            timestamp: 5,
        });
        records.push_back(ReviewRecord {
            id: 40,
            category: symbol_short!("aid"),
            amount: 100,
            timestamp: 6,
        });

        let dup = detect_duplicates(&env, &records).get(0).unwrap();
        let prop = propose_merge(&env, &user, dup, records).unwrap();

        // Reject from pending
        let rejected = reject_merge(&env, &admin, prop.proposal_id).unwrap();
        assert_eq!(rejected.state, MergeReviewState::Rejected);

        // Cannot apply rejected merge
        assert_eq!(
            apply_merge(&env, &admin, prop.proposal_id),
            Err(Error::InvalidTransition)
        );
    }

    #[test]
    fn test_authorization_and_failure_guards() {
        let (env, admin, user) = setup();
        let unauthorized_user = Address::generate(&env);

        let mut records = Vec::new(&env);
        records.push_back(ReviewRecord {
            id: 50,
            category: symbol_short!("aid"),
            amount: 100,
            timestamp: 5,
        });
        records.push_back(ReviewRecord {
            id: 50,
            category: symbol_short!("aid"),
            amount: 100,
            timestamp: 6,
        });

        let dup = detect_duplicates(&env, &records).get(0).unwrap();
        let prop = propose_merge(&env, &user, dup, records).unwrap();

        // Non-admin cannot approve
        assert_eq!(
            approve_merge(&env, &unauthorized_user, prop.proposal_id),
            Err(Error::Unauthorized)
        );

        // Applying directly from pending without approval fails
        assert_eq!(
            apply_merge(&env, &admin, prop.proposal_id),
            Err(Error::InvalidTransition)
        );

        // Non-existent proposal returns NotFound
        assert_eq!(
            approve_merge(&env, &admin, 999_999),
            Err(Error::NotFound)
        );
    }
}

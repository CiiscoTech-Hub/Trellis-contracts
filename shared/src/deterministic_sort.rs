//! Deterministic sorting for mixed-status records, status digests, and event lists (Issues #284, #492).
//!
//! When records, statuses, and events span multiple lifecycle statuses (`Pending`, `Active`,
//! `Failed`, `Paused`, `Settled`, `Cancelled`, `Archived`) and arrive out of
//! order or share identical timestamps/ledger sequences, naive sorting can
//! produce unstable or non-deterministic results across nodes and retries.
//!
//! This module provides:
//! - Canonical [`RecordStatus::priority_rank`] ordering for mixed-status datasets.
//! - Total-order comparators (`compare_records`, `compare_events`, `compare_statuses`)
//!   with strict tie-breaking chains.
//! - Bounded, `no_std`-compatible insertion sort (`MAX_SORT_ITEMS = 200`) to prevent
//!   unbounded gas consumption.
//! - Deterministic event list sorting (`sort_events`) and component status sorting (`sort_statuses`).
//! - Visibility- and authorization-aware event sorting (`sort_events_for_viewer`)
//!   reusing [`crate::pagination::EventVisibility`].
//! - Canonicalization and deduplication (`canonicalize_and_dedup_events`).
//! - Sorted assertions (`is_events_sorted`, `is_statuses_sorted`).

use core::cmp::Ordering;
use soroban_sdk::{contracttype, Address, Env, Symbol, Vec};

use crate::auth::require_admin;
use crate::errors::Error;
use crate::pagination::EventVisibility;

/// Maximum number of items accepted in a single deterministic sort call.
pub const MAX_SORT_ITEMS: u32 = 200;

/// Lifecycle status of a record or event for mixed-status sorting.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RecordStatus {
    Failed,
    Pending,
    Active,
    Paused,
    Settled,
    Cancelled,
    Archived,
}

impl RecordStatus {
    /// Canonical operational priority rank (lower rank sorts first in `StatusPriorityFirst`).
    ///
    /// Order: `Failed (0) < Pending (1) < Active (2) < Paused (3) < Settled (4) < Cancelled (5) < Archived (6)`.
    pub fn priority_rank(self) -> u8 {
        match self {
            RecordStatus::Failed => 0,
            RecordStatus::Pending => 1,
            RecordStatus::Active => 2,
            RecordStatus::Paused => 3,
            RecordStatus::Settled => 4,
            RecordStatus::Cancelled => 5,
            RecordStatus::Archived => 6,
        }
    }
}

/// Sorting policy for mixed-status collections.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SortPolicy {
    /// Operational priority first (`Failed`, `Pending`, `Active`, ...), then timestamp asc, then id asc.
    StatusPriorityFirst,
    /// Chronological ascending (`timestamp` asc, `ledger_seq` asc, status rank asc, `id` asc).
    TimestampAsc,
    /// Reverse chronological (`timestamp` desc, `ledger_seq` desc, status rank asc, `id` asc).
    TimestampDesc,
    /// Ledger sequence ascending (`ledger_seq` asc, `timestamp` asc, status rank asc, `id` asc).
    LedgerSeqAsc,
}

/// A mixed-status record with deterministic tie-breaking fields.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SortableRecord {
    pub id: u64,
    pub status: RecordStatus,
    pub timestamp: u64,
    pub ledger_seq: u32,
    pub tie_breaker: u64,
}

/// A mixed-status event with visibility classification and deterministic tie-breakers.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SortableEvent {
    pub event_id: u64,
    pub status: RecordStatus,
    pub timestamp: u64,
    pub ledger_seq: u32,
    pub tx_index: u32,
    pub visibility: EventVisibility,
}

/// A structured component health or operational status digest (#492).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SortableStatus {
    pub component_id: Symbol,
    /// 1 = Critical, 2 = High, 3 = Medium, 4 = Low, 5 = Operational
    pub severity_rank: u32,
    pub last_heartbeat: u64,
    pub is_healthy: bool,
}

// ---------------------------------------------------------------------------
// Comparators
// ---------------------------------------------------------------------------

/// Total-order comparator for [`SortableRecord`].
pub fn compare_records(a: &SortableRecord, b: &SortableRecord, policy: SortPolicy) -> Ordering {
    let primary = match policy {
        SortPolicy::StatusPriorityFirst => a
            .status
            .priority_rank()
            .cmp(&b.status.priority_rank())
            .then_with(|| a.timestamp.cmp(&b.timestamp))
            .then_with(|| a.ledger_seq.cmp(&b.ledger_seq)),
        SortPolicy::TimestampAsc => a
            .timestamp
            .cmp(&b.timestamp)
            .then_with(|| a.ledger_seq.cmp(&b.ledger_seq))
            .then_with(|| a.status.priority_rank().cmp(&b.status.priority_rank())),
        SortPolicy::TimestampDesc => b
            .timestamp
            .cmp(&a.timestamp)
            .then_with(|| b.ledger_seq.cmp(&a.ledger_seq))
            .then_with(|| a.status.priority_rank().cmp(&b.status.priority_rank())),
        SortPolicy::LedgerSeqAsc => a
            .ledger_seq
            .cmp(&b.ledger_seq)
            .then_with(|| a.timestamp.cmp(&b.timestamp))
            .then_with(|| a.status.priority_rank().cmp(&b.status.priority_rank())),
    };

    primary
        .then_with(|| a.tie_breaker.cmp(&b.tie_breaker))
        .then_with(|| a.id.cmp(&b.id))
}

/// Total-order comparator for [`SortableEvent`].
pub fn compare_events(a: &SortableEvent, b: &SortableEvent, policy: SortPolicy) -> Ordering {
    let primary = match policy {
        SortPolicy::StatusPriorityFirst => a
            .status
            .priority_rank()
            .cmp(&b.status.priority_rank())
            .then_with(|| a.timestamp.cmp(&b.timestamp))
            .then_with(|| a.ledger_seq.cmp(&b.ledger_seq)),
        SortPolicy::TimestampAsc => a
            .timestamp
            .cmp(&b.timestamp)
            .then_with(|| a.ledger_seq.cmp(&b.ledger_seq))
            .then_with(|| a.status.priority_rank().cmp(&b.status.priority_rank())),
        SortPolicy::TimestampDesc => b
            .timestamp
            .cmp(&a.timestamp)
            .then_with(|| b.ledger_seq.cmp(&a.ledger_seq))
            .then_with(|| a.status.priority_rank().cmp(&b.status.priority_rank())),
        SortPolicy::LedgerSeqAsc => a
            .ledger_seq
            .cmp(&b.ledger_seq)
            .then_with(|| a.timestamp.cmp(&b.timestamp))
            .then_with(|| a.status.priority_rank().cmp(&b.status.priority_rank())),
    };

    primary
        .then_with(|| a.tx_index.cmp(&b.tx_index))
        .then_with(|| a.event_id.cmp(&b.event_id))
}

/// Total-order comparator for [`SortableStatus`] (#492).
pub fn compare_statuses(a: &SortableStatus, b: &SortableStatus, policy: SortPolicy) -> Ordering {
    match policy {
        SortPolicy::StatusPriorityFirst => a
            .severity_rank
            .cmp(&b.severity_rank)
            .then_with(|| b.last_heartbeat.cmp(&a.last_heartbeat))
            .then_with(|| a.is_healthy.cmp(&b.is_healthy)),
        SortPolicy::TimestampAsc => a
            .last_heartbeat
            .cmp(&b.last_heartbeat)
            .then_with(|| a.severity_rank.cmp(&b.severity_rank))
            .then_with(|| a.is_healthy.cmp(&b.is_healthy)),
        SortPolicy::TimestampDesc => b
            .last_heartbeat
            .cmp(&a.last_heartbeat)
            .then_with(|| a.severity_rank.cmp(&b.severity_rank))
            .then_with(|| a.is_healthy.cmp(&b.is_healthy)),
        SortPolicy::LedgerSeqAsc => a
            .severity_rank
            .cmp(&b.severity_rank)
            .then_with(|| a.last_heartbeat.cmp(&b.last_heartbeat)),
    }
}

// ---------------------------------------------------------------------------
// Sorting Operations
// ---------------------------------------------------------------------------

/// Sort a vector of [`SortableRecord`]s deterministically according to `policy`.
pub fn sort_records(
    env: &Env,
    records: &Vec<SortableRecord>,
    policy: SortPolicy,
    strict_unique: bool,
) -> Result<Vec<SortableRecord>, Error> {
    if records.len() > MAX_SORT_ITEMS {
        return Err(Error::InvalidArgument);
    }

    let mut out = Vec::new(env);
    for item in records.iter() {
        out.push_back(item);
    }

    // Stable insertion sort in Soroban Vec (bounded by MAX_SORT_ITEMS = 200).
    let len = out.len();
    let mut i = 1u32;
    while i < len {
        let key = out.get(i).unwrap();
        let mut j = i;
        while j > 0 {
            let prev = out.get(j - 1).unwrap();
            if compare_records(&prev, &key, policy) == Ordering::Greater {
                out.set(j, prev);
                j -= 1;
            } else {
                break;
            }
        }
        out.set(j, key);
        i += 1;
    }

    if strict_unique && len > 1 {
        for idx in 1..len {
            let prev = out.get(idx - 1).unwrap();
            let curr = out.get(idx).unwrap();
            if prev.id == curr.id {
                return Err(Error::InvalidArgument);
            }
        }
    }

    Ok(out)
}

/// Sort a vector of [`SortableEvent`]s deterministically (#492).
pub fn sort_events(
    env: &Env,
    events: &Vec<SortableEvent>,
    policy: SortPolicy,
) -> Result<Vec<SortableEvent>, Error> {
    if events.len() > MAX_SORT_ITEMS {
        return Err(Error::InvalidArgument);
    }

    let mut out = Vec::new(env);
    for item in events.iter() {
        out.push_back(item);
    }

    let len = out.len();
    let mut i = 1u32;
    while i < len {
        let key = out.get(i).unwrap();
        let mut j = i;
        while j > 0 {
            let prev = out.get(j - 1).unwrap();
            if compare_events(&prev, &key, policy) == Ordering::Greater {
                out.set(j, prev);
                j -= 1;
            } else {
                break;
            }
        }
        out.set(j, key);
        i += 1;
    }

    Ok(out)
}

/// Sort a vector of [`SortableEvent`]s according to `policy`, filtering out
/// `MaintainerOnly` events unless `caller` is admin and `include_maintainer_only` is true.
pub fn sort_events_for_viewer(
    env: &Env,
    caller: &Address,
    events: &Vec<SortableEvent>,
    policy: SortPolicy,
    include_maintainer_only: bool,
) -> Result<Vec<SortableEvent>, Error> {
    if events.len() > MAX_SORT_ITEMS {
        return Err(Error::InvalidArgument);
    }
    if include_maintainer_only {
        require_admin(env, caller)?;
    }

    let mut out = Vec::new(env);
    for ev in events.iter() {
        if include_maintainer_only || ev.visibility.is_user_facing() {
            out.push_back(ev);
        }
    }

    let len = out.len();
    let mut i = 1u32;
    while i < len {
        let key = out.get(i).unwrap();
        let mut j = i;
        while j > 0 {
            let prev = out.get(j - 1).unwrap();
            if compare_events(&prev, &key, policy) == Ordering::Greater {
                out.set(j, prev);
                j -= 1;
            } else {
                break;
            }
        }
        out.set(j, key);
        i += 1;
    }

    Ok(out)
}

/// Sort a vector of [`SortableStatus`] component digests deterministically (#492).
pub fn sort_statuses(
    env: &Env,
    statuses: &Vec<SortableStatus>,
    policy: SortPolicy,
) -> Result<Vec<SortableStatus>, Error> {
    if statuses.len() > MAX_SORT_ITEMS {
        return Err(Error::InvalidArgument);
    }

    let mut out = Vec::new(env);
    for item in statuses.iter() {
        out.push_back(item);
    }

    let len = out.len();
    let mut i = 1u32;
    while i < len {
        let key = out.get(i).unwrap();
        let mut j = i;
        while j > 0 {
            let prev = out.get(j - 1).unwrap();
            if compare_statuses(&prev, &key, policy) == Ordering::Greater {
                out.set(j, prev);
                j -= 1;
            } else {
                break;
            }
        }
        out.set(j, key);
        i += 1;
    }

    Ok(out)
}

/// Verifies whether an event vector is already deterministically sorted.
pub fn is_events_sorted(events: &Vec<SortableEvent>, policy: SortPolicy) -> bool {
    let len = events.len();
    if len <= 1 {
        return true;
    }
    for i in 1..len {
        let prev = events.get(i - 1).unwrap();
        let curr = events.get(i).unwrap();
        if compare_events(&prev, &curr, policy) == Ordering::Greater {
            return false;
        }
    }
    true
}

/// Verifies whether a status vector is already deterministically sorted.
pub fn is_statuses_sorted(statuses: &Vec<SortableStatus>, policy: SortPolicy) -> bool {
    let len = statuses.len();
    if len <= 1 {
        return true;
    }
    for i in 1..len {
        let prev = statuses.get(i - 1).unwrap();
        let curr = statuses.get(i).unwrap();
        if compare_statuses(&prev, &curr, policy) == Ordering::Greater {
            return false;
        }
    }
    true
}

/// Sorts events and strips exact duplicates (identical event_id, status, timestamp, ledger_seq).
pub fn canonicalize_and_dedup_events(
    env: &Env,
    events: &Vec<SortableEvent>,
    policy: SortPolicy,
) -> Result<Vec<SortableEvent>, Error> {
    let sorted = sort_events(env, events, policy)?;
    let len = sorted.len();
    if len <= 1 {
        return Ok(sorted);
    }

    let mut deduped = Vec::new(env);
    let first = sorted.get(0).unwrap();
    deduped.push_back(first.clone());
    let mut last = first;

    for i in 1..len {
        let curr = sorted.get(i).unwrap();
        let is_dup = curr.event_id == last.event_id
            && curr.status == last.status
            && curr.timestamp == last.timestamp
            && curr.ledger_seq == last.ledger_seq;

        if !is_dup {
            deduped.push_back(curr.clone());
            last = curr;
        }
    }

    Ok(deduped)
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::auth::initialize_admin;
    use soroban_sdk::{
        contract, contractimpl, symbol_short,
        testutils::Address as _,
        Address, Env,
    };

    #[contract]
    pub struct MockContract;

    #[contractimpl]
    impl MockContract {
        pub fn ping() -> u32 {
            1
        }
    }

    fn rec(id: u64, status: RecordStatus, ts: u64, seq: u32, tie: u64) -> SortableRecord {
        SortableRecord {
            id,
            status,
            timestamp: ts,
            ledger_seq: seq,
            tie_breaker: tie,
        }
    }

    fn ev(
        id: u64,
        status: RecordStatus,
        ts: u64,
        seq: u32,
        tx: u32,
        vis: EventVisibility,
    ) -> SortableEvent {
        SortableEvent {
            event_id: id,
            status,
            timestamp: ts,
            ledger_seq: seq,
            tx_index: tx,
            visibility: vis,
        }
    }

    #[test]
    fn mixed_status_priority_and_tie_breakers_are_deterministic() {
        let env = Env::default();
        let mut input = Vec::new(&env);
        input.push_back(rec(5, RecordStatus::Settled, 100, 10, 2));
        input.push_back(rec(2, RecordStatus::Failed, 200, 20, 1));
        input.push_back(rec(4, RecordStatus::Pending, 100, 10, 2));
        input.push_back(rec(3, RecordStatus::Pending, 100, 10, 1));
        input.push_back(rec(1, RecordStatus::Active, 50, 5, 0));

        let sorted = sort_records(&env, &input, SortPolicy::StatusPriorityFirst, true).unwrap();
        assert_eq!(sorted.get(0).unwrap().id, 2); // Failed
        assert_eq!(sorted.get(1).unwrap().id, 3); // Pending, tie=1
        assert_eq!(sorted.get(2).unwrap().id, 4); // Pending, tie=2
        assert_eq!(sorted.get(3).unwrap().id, 1); // Active
        assert_eq!(sorted.get(4).unwrap().id, 5); // Settled

        // Retry / idempotency: sorting already-sorted output yields identical result.
        let resorted = sort_records(&env, &sorted, SortPolicy::StatusPriorityFirst, true).unwrap();
        assert_eq!(sorted, resorted);
    }

    #[test]
    fn permutation_invariance_under_timestamp_desc() {
        let env = Env::default();
        let mut p1 = Vec::new(&env);
        p1.push_back(rec(1, RecordStatus::Active, 100, 10, 0));
        p1.push_back(rec(2, RecordStatus::Failed, 100, 10, 0));
        p1.push_back(rec(3, RecordStatus::Settled, 200, 11, 0));

        let mut p2 = Vec::new(&env);
        p2.push_back(rec(3, RecordStatus::Settled, 200, 11, 0));
        p2.push_back(rec(2, RecordStatus::Failed, 100, 10, 0));
        p2.push_back(rec(1, RecordStatus::Active, 100, 10, 0));

        let s1 = sort_records(&env, &p1, SortPolicy::TimestampDesc, true).unwrap();
        let s2 = sort_records(&env, &p2, SortPolicy::TimestampDesc, true).unwrap();
        assert_eq!(s1, s2);
        assert_eq!(s1.get(0).unwrap().id, 3);
        assert_eq!(s1.get(1).unwrap().id, 2); // Failed beats Active on tie
        assert_eq!(s1.get(2).unwrap().id, 1);
    }

    #[test]
    fn rejects_oversized_batches_and_duplicate_ids() {
        let env = Env::default();
        let mut dup = Vec::new(&env);
        dup.push_back(rec(7, RecordStatus::Pending, 100, 1, 0));
        dup.push_back(rec(7, RecordStatus::Active, 100, 1, 0));
        assert_eq!(
            sort_records(&env, &dup, SortPolicy::TimestampAsc, true),
            Err(Error::InvalidArgument)
        );

        let mut huge = Vec::new(&env);
        for i in 0..(MAX_SORT_ITEMS + 1) {
            huge.push_back(rec(i as u64, RecordStatus::Active, i as u64, i, 0));
        }
        assert_eq!(
            sort_records(&env, &huge, SortPolicy::LedgerSeqAsc, false),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn event_sorting_enforces_visibility_and_admin_authorization() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, MockContract);
        let admin = Address::generate(&env);
        let user = Address::generate(&env);

        let mut events = Vec::new(&env);
        events.push_back(ev(10, RecordStatus::Settled, 300, 3, 1, EventVisibility::Public));
        events.push_back(ev(
            11,
            RecordStatus::Failed,
            100,
            1,
            0,
            EventVisibility::MaintainerOnly,
        ));
        events.push_back(ev(
            12,
            RecordStatus::Pending,
            200,
            2,
            0,
            EventVisibility::Authorized,
        ));

        env.as_contract(&contract_id, || {
            initialize_admin(&env, &admin).unwrap();
        });

        // Non-admin requesting MaintainerOnly events is rejected.
        env.as_contract(&contract_id, || {
            assert_eq!(
                sort_events_for_viewer(&env, &user, &events, SortPolicy::TimestampAsc, true),
                Err(Error::Unauthorized)
            );
        });

        // Non-admin with include_maintainer_only = false gets only user-facing events, sorted.
        env.as_contract(&contract_id, || {
            let user_view =
                sort_events_for_viewer(&env, &user, &events, SortPolicy::TimestampAsc, false)
                    .unwrap();
            assert_eq!(user_view.len(), 2);
            assert_eq!(user_view.get(0).unwrap().event_id, 12);
            assert_eq!(user_view.get(1).unwrap().event_id, 10);
        });

        // Admin with include_maintainer_only = true sees all 3 in canonical order.
        env.as_contract(&contract_id, || {
            let admin_view =
                sort_events_for_viewer(&env, &admin, &events, SortPolicy::TimestampAsc, true)
                    .unwrap();
            assert_eq!(admin_view.len(), 3);
            assert_eq!(admin_view.get(0).unwrap().event_id, 11);
        });
    }

    #[test]
    fn test_direct_event_sorting_and_assertions() {
        let env = Env::default();
        let mut events = Vec::new(&env);

        events.push_back(ev(3, RecordStatus::Active, 300, 3, 0, EventVisibility::Public));
        events.push_back(ev(1, RecordStatus::Active, 100, 1, 0, EventVisibility::Public));
        events.push_back(ev(2, RecordStatus::Active, 200, 2, 0, EventVisibility::Public));

        assert!(!is_events_sorted(&events, SortPolicy::TimestampAsc));

        let sorted = sort_events(&env, &events, SortPolicy::TimestampAsc).unwrap();
        assert_eq!(sorted.get(0).unwrap().event_id, 1);
        assert_eq!(sorted.get(1).unwrap().event_id, 2);
        assert_eq!(sorted.get(2).unwrap().event_id, 3);
        assert!(is_events_sorted(&sorted, SortPolicy::TimestampAsc));
    }

    #[test]
    fn test_canonicalize_and_dedup_events() {
        let env = Env::default();
        let mut events = Vec::new(&env);

        events.push_back(ev(1, RecordStatus::Pending, 100, 1, 0, EventVisibility::Public));
        events.push_back(ev(2, RecordStatus::Active, 200, 2, 0, EventVisibility::Public));
        events.push_back(ev(1, RecordStatus::Pending, 100, 1, 0, EventVisibility::Public)); // duplicate

        let deduped = canonicalize_and_dedup_events(&env, &events, SortPolicy::TimestampAsc).unwrap();
        assert_eq!(deduped.len(), 2);
        assert_eq!(deduped.get(0).unwrap().event_id, 1);
        assert_eq!(deduped.get(1).unwrap().event_id, 2);
    }

    #[test]
    fn test_status_list_sorting_and_priority() {
        let env = Env::default();
        let mut statuses = Vec::new(&env);

        statuses.push_back(SortableStatus {
            component_id: symbol_short!("relayer"),
            severity_rank: 5,
            last_heartbeat: 100,
            is_healthy: true,
        });
        statuses.push_back(SortableStatus {
            component_id: symbol_short!("oracle"),
            severity_rank: 1,
            last_heartbeat: 90,
            is_healthy: false,
        });
        statuses.push_back(SortableStatus {
            component_id: symbol_short!("treasury"),
            severity_rank: 2,
            last_heartbeat: 95,
            is_healthy: false,
        });

        assert!(!is_statuses_sorted(&statuses, SortPolicy::StatusPriorityFirst));

        let sorted = sort_statuses(&env, &statuses, SortPolicy::StatusPriorityFirst).unwrap();
        assert_eq!(sorted.get(0).unwrap().component_id, symbol_short!("oracle"));
        assert_eq!(sorted.get(1).unwrap().component_id, symbol_short!("treasury"));
        assert_eq!(sorted.get(2).unwrap().component_id, symbol_short!("relayer"));
        assert!(is_statuses_sorted(&sorted, SortPolicy::StatusPriorityFirst));
    }
}

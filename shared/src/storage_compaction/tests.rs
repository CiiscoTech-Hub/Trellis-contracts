//! Tests for shared storage page compaction and orphan sweeping (Issue #537).
//!
//! Coverage map:
//! - normal: append/paging, plan, compact a fragmented index, sweep orphans
//! - failure: uninitialised namespace, bad capacity, oversized refusal, no-confirm
//! - retry/idempotency: re-compacting a dense index is a no-op; resumable sweep
//! - authorization: a non-admin caller is rejected before any mutation
//! - invariant: compaction preserves the exact multiset of live keys

extern crate std;

use super::*;
use crate::auth;
use soroban_sdk::{
    contract, contractimpl, symbol_short, testutils::Address as _, Address, Env, Symbol,
};

fn ns() -> Symbol {
    symbol_short!("idx")
}

/// Collect every live key across all pages, in page/slot order.
fn all_entries(env: &Env, namespace: &Symbol) -> std::vec::Vec<Symbol> {
    let dir = get_directory(env, namespace).unwrap();
    let mut out = std::vec::Vec::new();
    for p in 0..dir.page_count {
        let page = read_page(env, namespace, p);
        for i in 0..page.len() {
            out.push(page.get(i).unwrap());
        }
    }
    out
}

fn sym(env: &Env, n: u32) -> Symbol {
    // Deterministic distinct symbols k0..kN (<= 9 chars for symbol_short domain).
    Symbol::new(env, &std::format!("k{n}"))
}

// A contract shell so storage helpers run inside a real contract invocation.
#[contract]
struct Harness;

#[contractimpl]
impl Harness {
    pub fn seed(env: Env, capacity: u32, count: u32) {
        init_index(&env, &ns(), capacity).unwrap();
        for n in 0..count {
            append(&env, &ns(), &sym(&env, n)).unwrap();
        }
    }

    pub fn dir(env: Env) -> PageDirectory {
        get_directory(&env, &ns()).unwrap()
    }

    pub fn remove(env: Env, key: Symbol) -> bool {
        remove_key(&env, &ns(), &key, 0).unwrap()
    }

    pub fn plan(env: Env) -> CompactionPlan {
        plan_compaction(&env, &ns()).unwrap()
    }

    pub fn compact(env: Env) -> CompactionReport {
        apply_compaction(&env, &ns(), true).unwrap()
    }

    pub fn try_compact_unconfirmed(env: Env) -> Result<CompactionReport, Error> {
        apply_compaction(&env, &ns(), false)
    }

    // Authorization gate: only the configured admin may compact. Mirrors how a
    // real contract wires this shared helper behind its own access control.
    pub fn admin_compact(env: Env, caller: Address) -> Result<CompactionReport, Error> {
        auth::require_admin(&env, &caller)?;
        apply_compaction(&env, &ns(), true)
    }

    pub fn set_admin(env: Env, admin: Address) {
        auth::set_admin(&env, &admin);
    }
}

fn setup() -> (Env, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register_contract(None, Harness);
    (env.clone(), id)
}

#[test]
fn append_allocates_pages_at_capacity() {
    let (env, id) = setup();
    env.as_contract(&id, || {
        init_index(&env, &ns(), 4).unwrap();
        for n in 0..10 {
            append(&env, &ns(), &sym(&env, n)).unwrap();
        }
        let dir = get_directory(&env, &ns()).unwrap();
        assert_eq!(dir.live_entries, 10);
        assert_eq!(dir.page_count, 3); // ceil(10/4)
        assert_eq!(dir.capacity, 4);
    });
}

#[test]
fn init_rejects_oversized_capacity_and_double_init() {
    let (env, id) = setup();
    env.as_contract(&id, || {
        assert_eq!(
            init_index(&env, &ns(), MAX_PAGE_CAPACITY + 1).unwrap_err(),
            Error::ConfigInvalid
        );
        init_index(&env, &ns(), 0).unwrap(); // 0 -> default capacity
        assert_eq!(
            get_directory(&env, &ns()).unwrap().capacity,
            DEFAULT_PAGE_CAPACITY
        );
        assert_eq!(
            init_index(&env, &ns(), 8).unwrap_err(),
            Error::AlreadyInitialized
        );
    });
}

#[test]
fn operations_on_missing_namespace_fail_closed() {
    let (env, id) = setup();
    env.as_contract(&id, || {
        let missing = symbol_short!("nope");
        assert_eq!(append(&env, &ns(), &sym(&env, 1)).unwrap_err(), Error::NotFound);
        assert_eq!(
            plan_compaction(&env, &missing).unwrap_err(),
            Error::NotFound
        );
        assert_eq!(
            apply_compaction(&env, &missing, true).unwrap_err(),
            Error::NotFound
        );
        assert!(!contains(&env, &missing, &sym(&env, 1), 0));
    });
}

#[test]
fn compaction_reclaims_fragmented_pages_and_preserves_entries() {
    let (env, id) = setup();
    env.as_contract(&id, || {
        init_index(&env, &ns(), 4).unwrap();
        for n in 0..12 {
            append(&env, &ns(), &sym(&env, n)).unwrap(); // 3 full pages
        }
        // Remove 7 keys, scattering holes across pages.
        for n in [0u32, 1, 4, 5, 8, 9, 10] {
            assert!(remove_key(&env, &ns(), &sym(&env, n), 0).unwrap());
        }
        let before = all_entries(&env, &ns());
        assert_eq!(before.len(), 5);

        let plan = plan_compaction(&env, &ns()).unwrap();
        assert_eq!(plan.current_pages, 3);
        assert_eq!(plan.projected_pages, 2); // ceil(5/4)
        assert_eq!(plan.reclaimable_pages, 1);

        let report = apply_compaction(&env, &ns(), true).unwrap();
        assert_eq!(report.pages_before, 3);
        assert_eq!(report.pages_after, 2);
        assert_eq!(report.pages_reclaimed, 1);
        assert_eq!(report.entries_preserved, 5);

        let dir = get_directory(&env, &ns()).unwrap();
        assert_eq!(dir.page_count, 2);
        assert_eq!(dir.live_entries, 5);

        // Invariant: same multiset of live keys, just repacked densely.
        let after = all_entries(&env, &ns());
        assert_eq!(before, after);
        // First page is now full, trailing page holds the remainder.
        assert_eq!(read_page(&env, &ns(), 0).len(), 4);
        assert_eq!(read_page(&env, &ns(), 1).len(), 1);
    });
}

#[test]
fn compaction_is_idempotent() {
    let (env, id) = setup();
    env.as_contract(&id, || {
        init_index(&env, &ns(), 4).unwrap();
        for n in 0..9 {
            append(&env, &ns(), &sym(&env, n)).unwrap();
        }
        let first = apply_compaction(&env, &ns(), true).unwrap();
        // Already dense (3 pages for 9 entries); nothing to reclaim.
        assert_eq!(first.pages_reclaimed, 0);
        let snapshot = all_entries(&env, &ns());
        let second = apply_compaction(&env, &ns(), true).unwrap();
        assert_eq!(second.pages_reclaimed, 0);
        assert_eq!(second.pages_before, second.pages_after);
        assert_eq!(all_entries(&env, &ns()), snapshot);
    });
}

#[test]
fn compaction_requires_confirmation_and_bounds_size() {
    let (env, id) = setup();
    env.as_contract(&id, || {
        init_index(&env, &ns(), 1).unwrap(); // 1 entry/page => page per entry
        for n in 0..3 {
            append(&env, &ns(), &sym(&env, n)).unwrap();
        }
        // No-confirm is refused and mutates nothing.
        let dir_before = get_directory(&env, &ns()).unwrap();
        assert_eq!(
            apply_compaction(&env, &ns(), false).unwrap_err(),
            Error::InvalidArgument
        );
        assert_eq!(get_directory(&env, &ns()).unwrap(), dir_before);
    });
}

#[test]
fn oversized_index_is_refused_without_mutation() {
    let (env, id) = setup();
    env.as_contract(&id, || {
        init_index(&env, &ns(), 1).unwrap();
        for n in 0..(MAX_COMPACT_PAGES + 1) {
            append(&env, &ns(), &sym(&env, n)).unwrap();
        }
        let dir_before = get_directory(&env, &ns()).unwrap();
        assert_eq!(
            apply_compaction(&env, &ns(), true).unwrap_err(),
            Error::QuotaExceeded
        );
        assert_eq!(get_directory(&env, &ns()).unwrap(), dir_before);
    });
}

#[test]
fn empty_namespace_compaction_is_noop() {
    let (env, id) = setup();
    env.as_contract(&id, || {
        init_index(&env, &ns(), 4).unwrap();
        let report = apply_compaction(&env, &ns(), true).unwrap();
        assert!(!report.destructive);
        assert_eq!(report.pages_before, 0);
        assert_eq!(report.pages_after, 0);
    });
}

#[test]
fn orphan_sweep_removes_only_dead_keys() {
    let (env, id) = setup();
    env.as_contract(&id, || {
        init_index(&env, &ns(), 4).unwrap();
        for n in 0..8 {
            append(&env, &ns(), &sym(&env, n)).unwrap();
        }
        // Liveness predicate: even-numbered keys are live, odd are orphans.
        let is_live = |env: &Env, key: &Symbol| -> bool {
            (0..8u32)
                .filter(|n| n % 2 == 0)
                .any(|n| &sym(env, n) == key)
        };

        let plan = plan_orphan_sweep(&env, &ns(), 0, 0, is_live).unwrap();
        assert_eq!(plan.orphans.len(), 4);
        assert!(plan.complete);
        // Plan did not mutate.
        assert_eq!(get_directory(&env, &ns()).unwrap().live_entries, 8);

        let report = apply_orphan_sweep(&env, &ns(), 0, 0, true, is_live).unwrap();
        assert_eq!(report.removed.len(), 4);
        assert_eq!(report.live_entries_after, 4);
        assert!(report.complete);

        // Only live (even) keys remain.
        let remaining = all_entries(&env, &ns());
        assert_eq!(remaining.len(), 4);
        for key in remaining {
            assert!(is_live(&env, &key));
        }
    });
}

#[test]
fn orphan_sweep_is_resumable_by_cursor() {
    let (env, id) = setup();
    env.as_contract(&id, || {
        init_index(&env, &ns(), 2).unwrap();
        for n in 0..8 {
            append(&env, &ns(), &sym(&env, n)).unwrap(); // 4 pages of 2
        }
        let none_live = |_: &Env, _: &Symbol| false;
        // Sweep at most 2 entries (1 page) per call.
        let first = apply_orphan_sweep(&env, &ns(), 0, 2, true, none_live).unwrap();
        assert!(!first.complete);
        assert_eq!(first.removed.len(), 2);
        let second =
            apply_orphan_sweep(&env, &ns(), first.next_cursor, 2, true, none_live).unwrap();
        assert_eq!(second.removed.len(), 2);
        assert!(!second.complete);
        assert!(second.next_cursor > first.next_cursor);
    });
}

#[test]
fn unconfirmed_sweep_is_rejected() {
    let (env, id) = setup();
    env.as_contract(&id, || {
        init_index(&env, &ns(), 4).unwrap();
        append(&env, &ns(), &sym(&env, 0)).unwrap();
        let always = |_: &Env, _: &Symbol| true;
        assert_eq!(
            apply_orphan_sweep(&env, &ns(), 0, 0, false, always).unwrap_err(),
            Error::InvalidArgument
        );
    });
}

// ----- Authorization path (via the contract harness) -----------------------

#[test]
fn authorized_admin_may_compact() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register_contract(None, Harness);
    let client = HarnessClient::new(&env, &id);
    let admin = Address::generate(&env);

    client.set_admin(&admin);
    client.seed(&1, &3); // 3 single-entry pages
    client.remove(&sym(&env, 1)); // fragment
    let report = client.admin_compact(&admin);
    assert_eq!(report.pages_before, 3);
    assert_eq!(report.pages_after, 2);
}

#[test]
fn non_admin_is_rejected_before_mutation() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register_contract(None, Harness);
    let client = HarnessClient::new(&env, &id);
    let admin = Address::generate(&env);
    let intruder = Address::generate(&env);

    client.set_admin(&admin);
    client.seed(&1, &3);
    client.remove(&sym(&env, 1));
    let before = client.dir();

    assert_eq!(
        client.try_admin_compact(&intruder),
        Err(Ok(Error::Unauthorized))
    );
    // Directory untouched by the rejected call.
    assert_eq!(client.dir(), before);
}

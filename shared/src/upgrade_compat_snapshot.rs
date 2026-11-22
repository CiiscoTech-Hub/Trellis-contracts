//! Deterministic contract upgrade compatibility snapshots (Issue #322).
//!
//! A [`CompatSnapshot`] captures the externally observable surface of a
//! contract version: its entrypoint signatures, the storage key families it
//! reads/writes, and the event topics indexers subscribe to. The snapshot is
//! canonicalised (every list sorted, duplicates rejected) before hashing, so
//! two operators describing the same surface in a different order always
//! obtain the same `surface_hash`.
//!
//! ## Lifecycle
//!
//! 1. [`record_baseline`] registers the currently deployed surface (admin).
//! 2. [`check_upgrade`] compares a candidate against the baseline and returns a
//!    [`CompatReport`] with a [`CompatVerdict`] (read-only, no auth).
//! 3. [`approve_upgrade`] promotes the candidate to baseline (admin). Breaking
//!    candidates are always rejected; candidates that require a storage
//!    migration need an explicit `migration_acknowledged = true`.
//! 4. [`rollback_upgrade`] restores the previous baseline (admin, one level).
//!
//! ## Verdict rules
//!
//! | Change                                        | Verdict             |
//! |-----------------------------------------------|---------------------|
//! | identical surface                             | `Identical`         |
//! | only additions (entrypoints/keys/topics)      | `Compatible`        |
//! | storage key family removed, or schema bumped  | `RequiresMigration` |
//! | entrypoint removed or signature changed       | `Breaking`          |
//! | event topic removed                           | `Breaking`          |
//! | storage schema version decreased              | `Breaking`          |
//!
//! Retrying [`record_baseline`] or [`approve_upgrade`] with a snapshot that is
//! already the baseline is a no-op success, so a transaction that timed out
//! client-side can be safely resubmitted.

use soroban_sdk::{contracttype, symbol_short, xdr::ToXdr, Address, BytesN, Env, Symbol, Vec};

use crate::storage::{persistent_get, persistent_remove, persistent_set};

pub const COMPAT_SNAPSHOT_FORMAT: u32 = 1;
pub const MAX_SNAPSHOT_ENTRYPOINTS: u32 = 64;
pub const MAX_SNAPSHOT_STORAGE_KEYS: u32 = 64;
pub const MAX_SNAPSHOT_EVENT_TOPICS: u32 = 64;
pub const MAX_ENTRYPOINT_ARGS: u32 = 16;

pub const TOPIC_COMPAT_BASELINE: Symbol = symbol_short!("cmp_base");
pub const TOPIC_COMPAT_UPGRADE: Symbol = symbol_short!("cmp_upg");
pub const TOPIC_COMPAT_ROLLBACK: Symbol = symbol_short!("cmp_rb");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single public entrypoint. Argument and return types are described by
/// short type names (e.g. `addr`, `i128`, `sym`) chosen by the contract owner;
/// only equality matters, so any stable naming convention works.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntrypointSig {
    pub name: Symbol,
    pub args: Vec<Symbol>,
    pub returns: Symbol,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompatSnapshot {
    pub contract: Symbol,
    pub version: u32,
    pub storage_schema: u32,
    pub entrypoints: Vec<EntrypointSig>,
    pub storage_keys: Vec<Symbol>,
    pub event_topics: Vec<Symbol>,
    /// sha256 over the canonical surface (excludes `version`, so two versions
    /// with an unchanged surface share the same hash).
    pub surface_hash: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum CompatVerdict {
    Identical = 0,
    Compatible = 1,
    RequiresMigration = 2,
    Breaking = 3,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompatReport {
    pub contract: Symbol,
    pub baseline_version: u32,
    pub candidate_version: u32,
    pub verdict: CompatVerdict,
    pub added_entrypoints: Vec<Symbol>,
    pub removed_entrypoints: Vec<Symbol>,
    pub changed_entrypoints: Vec<Symbol>,
    pub added_storage_keys: Vec<Symbol>,
    pub removed_storage_keys: Vec<Symbol>,
    pub added_event_topics: Vec<Symbol>,
    pub removed_event_topics: Vec<Symbol>,
    pub schema_delta: i64,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum CompatError {
    Unauthorized = 1,
    TooManyItems = 2,
    DuplicateItem = 3,
    NoBaseline = 4,
    VersionNotIncreasing = 5,
    BaselineConflict = 6,
    BreakingChange = 7,
    MigrationNotAcknowledged = 8,
    NoRollbackTarget = 9,
    FingerprintMismatch = 10,
    ContractMismatch = 11,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum CompatKey {
    Baseline(Symbol),
    Previous(Symbol),
}

// ---------------------------------------------------------------------------
// Canonicalisation
// ---------------------------------------------------------------------------

fn sorted_symbols(env: &Env, items: &Vec<Symbol>) -> Result<Vec<Symbol>, CompatError> {
    let mut out: Vec<Symbol> = Vec::new(env);
    for item in items.iter() {
        let mut pos = out.len();
        for i in 0..out.len() {
            let cur = out.get_unchecked(i);
            if cur == item {
                return Err(CompatError::DuplicateItem);
            }
            if item < cur {
                pos = i;
                break;
            }
        }
        out.insert(pos, item);
    }
    Ok(out)
}

fn sorted_entrypoints(
    env: &Env,
    items: &Vec<EntrypointSig>,
) -> Result<Vec<EntrypointSig>, CompatError> {
    let mut out: Vec<EntrypointSig> = Vec::new(env);
    for item in items.iter() {
        if item.args.len() > MAX_ENTRYPOINT_ARGS {
            return Err(CompatError::TooManyItems);
        }
        let mut pos = out.len();
        for i in 0..out.len() {
            let cur = out.get_unchecked(i);
            if cur.name == item.name {
                return Err(CompatError::DuplicateItem);
            }
            if item.name < cur.name {
                pos = i;
                break;
            }
        }
        out.insert(pos, item);
    }
    Ok(out)
}

fn compute_surface_hash(
    env: &Env,
    contract: &Symbol,
    storage_schema: u32,
    entrypoints: &Vec<EntrypointSig>,
    storage_keys: &Vec<Symbol>,
    event_topics: &Vec<Symbol>,
) -> BytesN<32> {
    let payload = (
        symbol_short!("cmp_snap"),
        COMPAT_SNAPSHOT_FORMAT,
        contract.clone(),
        storage_schema,
        entrypoints.clone(),
        storage_keys.clone(),
        event_topics.clone(),
    )
        .to_xdr(env);
    env.crypto().sha256(&payload).into()
}

/// Build a canonical snapshot. Input ordering does not affect the result.
pub fn build_snapshot(
    env: &Env,
    contract: Symbol,
    version: u32,
    storage_schema: u32,
    entrypoints: Vec<EntrypointSig>,
    storage_keys: Vec<Symbol>,
    event_topics: Vec<Symbol>,
) -> Result<CompatSnapshot, CompatError> {
    if entrypoints.len() > MAX_SNAPSHOT_ENTRYPOINTS
        || storage_keys.len() > MAX_SNAPSHOT_STORAGE_KEYS
        || event_topics.len() > MAX_SNAPSHOT_EVENT_TOPICS
    {
        return Err(CompatError::TooManyItems);
    }
    let entrypoints = sorted_entrypoints(env, &entrypoints)?;
    let storage_keys = sorted_symbols(env, &storage_keys)?;
    let event_topics = sorted_symbols(env, &event_topics)?;
    let surface_hash = compute_surface_hash(
        env,
        &contract,
        storage_schema,
        &entrypoints,
        &storage_keys,
        &event_topics,
    );
    Ok(CompatSnapshot {
        contract,
        version,
        storage_schema,
        entrypoints,
        storage_keys,
        event_topics,
        surface_hash,
    })
}

/// Re-canonicalise a (possibly client-supplied) snapshot and check that its
/// lists are sorted and its `surface_hash` matches.
pub fn verify_snapshot(env: &Env, snapshot: &CompatSnapshot) -> Result<(), CompatError> {
    let rebuilt = build_snapshot(
        env,
        snapshot.contract.clone(),
        snapshot.version,
        snapshot.storage_schema,
        snapshot.entrypoints.clone(),
        snapshot.storage_keys.clone(),
        snapshot.event_topics.clone(),
    )?;
    if rebuilt != *snapshot {
        return Err(CompatError::FingerprintMismatch);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

/// Merge-walk two sorted symbol lists, returning (added, removed).
fn diff_symbols(env: &Env, base: &Vec<Symbol>, cand: &Vec<Symbol>) -> (Vec<Symbol>, Vec<Symbol>) {
    let mut added = Vec::new(env);
    let mut removed = Vec::new(env);
    let (mut i, mut j) = (0u32, 0u32);
    while i < base.len() || j < cand.len() {
        if i == base.len() {
            added.push_back(cand.get_unchecked(j));
            j += 1;
        } else if j == cand.len() {
            removed.push_back(base.get_unchecked(i));
            i += 1;
        } else {
            let b = base.get_unchecked(i);
            let c = cand.get_unchecked(j);
            if b == c {
                i += 1;
                j += 1;
            } else if b < c {
                removed.push_back(b);
                i += 1;
            } else {
                added.push_back(c);
                j += 1;
            }
        }
    }
    (added, removed)
}

/// Pure comparison of two canonical snapshots. Does not touch storage.
pub fn compare_snapshots(env: &Env, base: &CompatSnapshot, cand: &CompatSnapshot) -> CompatReport {
    let mut added_eps = Vec::new(env);
    let mut removed_eps = Vec::new(env);
    let mut changed_eps = Vec::new(env);
    let (mut i, mut j) = (0u32, 0u32);
    let (be, ce) = (&base.entrypoints, &cand.entrypoints);
    while i < be.len() || j < ce.len() {
        if i == be.len() {
            added_eps.push_back(ce.get_unchecked(j).name);
            j += 1;
        } else if j == ce.len() {
            removed_eps.push_back(be.get_unchecked(i).name);
            i += 1;
        } else {
            let b = be.get_unchecked(i);
            let c = ce.get_unchecked(j);
            if b.name == c.name {
                if b != c {
                    changed_eps.push_back(c.name);
                }
                i += 1;
                j += 1;
            } else if b.name < c.name {
                removed_eps.push_back(b.name);
                i += 1;
            } else {
                added_eps.push_back(c.name);
                j += 1;
            }
        }
    }

    let (added_keys, removed_keys) = diff_symbols(env, &base.storage_keys, &cand.storage_keys);
    let (added_topics, removed_topics) = diff_symbols(env, &base.event_topics, &cand.event_topics);
    let schema_delta = cand.storage_schema as i64 - base.storage_schema as i64;

    let verdict = if !removed_eps.is_empty()
        || !changed_eps.is_empty()
        || !removed_topics.is_empty()
        || schema_delta < 0
    {
        CompatVerdict::Breaking
    } else if !removed_keys.is_empty() || schema_delta > 0 {
        CompatVerdict::RequiresMigration
    } else if base.surface_hash == cand.surface_hash {
        CompatVerdict::Identical
    } else {
        CompatVerdict::Compatible
    };

    CompatReport {
        contract: cand.contract.clone(),
        baseline_version: base.version,
        candidate_version: cand.version,
        verdict,
        added_entrypoints: added_eps,
        removed_entrypoints: removed_eps,
        changed_entrypoints: changed_eps,
        added_storage_keys: added_keys,
        removed_storage_keys: removed_keys,
        added_event_topics: added_topics,
        removed_event_topics: removed_topics,
        schema_delta,
    }
}

// ---------------------------------------------------------------------------
// Stateful baseline management
// ---------------------------------------------------------------------------

pub fn get_baseline(env: &Env, contract: &Symbol) -> Option<CompatSnapshot> {
    persistent_get(env, &CompatKey::Baseline(contract.clone()))
}

pub fn get_previous(env: &Env, contract: &Symbol) -> Option<CompatSnapshot> {
    persistent_get(env, &CompatKey::Previous(contract.clone()))
}

fn require_admin(env: &Env, caller: &Address) -> Result<(), CompatError> {
    crate::auth::require_admin(env, caller).map_err(|_| CompatError::Unauthorized)
}

/// Register the first baseline for a contract. Re-recording the identical
/// snapshot is an idempotent success; anything else must go through
/// [`approve_upgrade`].
pub fn record_baseline(
    env: &Env,
    caller: &Address,
    snapshot: &CompatSnapshot,
) -> Result<(), CompatError> {
    require_admin(env, caller)?;
    verify_snapshot(env, snapshot)?;
    if let Some(existing) = get_baseline(env, &snapshot.contract) {
        if existing == *snapshot {
            return Ok(());
        }
        return Err(CompatError::BaselineConflict);
    }
    persistent_set(env, &CompatKey::Baseline(snapshot.contract.clone()), snapshot);
    env.events().publish(
        (TOPIC_COMPAT_BASELINE, snapshot.contract.clone()),
        (snapshot.version, snapshot.surface_hash.clone()),
    );
    Ok(())
}

/// Read-only compatibility check of `candidate` against the stored baseline.
pub fn check_upgrade(env: &Env, candidate: &CompatSnapshot) -> Result<CompatReport, CompatError> {
    verify_snapshot(env, candidate)?;
    let base = get_baseline(env, &candidate.contract).ok_or(CompatError::NoBaseline)?;
    Ok(compare_snapshots(env, &base, candidate))
}

/// Promote `candidate` to baseline after a successful compatibility check.
/// The replaced baseline is kept as the rollback target.
pub fn approve_upgrade(
    env: &Env,
    caller: &Address,
    candidate: &CompatSnapshot,
    migration_acknowledged: bool,
) -> Result<CompatReport, CompatError> {
    require_admin(env, caller)?;
    let report = check_upgrade(env, candidate)?;
    let base = get_baseline(env, &candidate.contract).ok_or(CompatError::NoBaseline)?;

    // Retry of an upgrade that already landed.
    if base == *candidate {
        return Ok(report);
    }
    if candidate.version <= base.version {
        return Err(CompatError::VersionNotIncreasing);
    }
    match report.verdict {
        CompatVerdict::Breaking => return Err(CompatError::BreakingChange),
        CompatVerdict::RequiresMigration if !migration_acknowledged => {
            return Err(CompatError::MigrationNotAcknowledged)
        }
        _ => {}
    }

    persistent_set(env, &CompatKey::Previous(candidate.contract.clone()), &base);
    persistent_set(env, &CompatKey::Baseline(candidate.contract.clone()), candidate);
    env.events().publish(
        (TOPIC_COMPAT_UPGRADE, candidate.contract.clone()),
        (base.version, candidate.version, report.verdict, candidate.surface_hash.clone()),
    );
    Ok(report)
}

/// Restore the previous baseline. Only one level of history is retained, so
/// a second consecutive rollback returns [`CompatError::NoRollbackTarget`].
pub fn rollback_upgrade(
    env: &Env,
    caller: &Address,
    contract: &Symbol,
) -> Result<CompatSnapshot, CompatError> {
    require_admin(env, caller)?;
    let previous = get_previous(env, contract).ok_or(CompatError::NoRollbackTarget)?;
    if previous.contract != *contract {
        return Err(CompatError::ContractMismatch);
    }
    let current = get_baseline(env, contract).ok_or(CompatError::NoBaseline)?;
    persistent_set(env, &CompatKey::Baseline(contract.clone()), &previous);
    persistent_remove(env, &CompatKey::Previous(contract.clone()));
    env.events().publish(
        (TOPIC_COMPAT_ROLLBACK, contract.clone()),
        (current.version, previous.version, previous.surface_hash.clone()),
    );
    Ok(previous)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{contract, contractimpl, testutils::Address as _, vec, Address, Env};

    #[contract]
    struct CompatTestContract;
    #[contractimpl]
    impl CompatTestContract {}

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let cid = env.register_contract(None, CompatTestContract);
        let admin = Address::generate(&env);
        env.as_contract(&cid, || crate::auth::set_admin(&env, &admin));
        (env, cid, admin)
    }

    // Each call runs in its own frame, as a real invocation would; Soroban
    // rejects a second `require_auth` for the same address within one frame.
    fn rec(env: &Env, cid: &Address, caller: &Address, s: &CompatSnapshot) -> Result<(), CompatError> {
        env.as_contract(cid, || record_baseline(env, caller, s))
    }

    fn approve(env: &Env, cid: &Address, caller: &Address, s: &CompatSnapshot, ack: bool) -> Result<CompatReport, CompatError> {
        env.as_contract(cid, || approve_upgrade(env, caller, s, ack))
    }

    fn rollback(env: &Env, cid: &Address, caller: &Address, c: &Symbol) -> Result<CompatSnapshot, CompatError> {
        env.as_contract(cid, || rollback_upgrade(env, caller, c))
    }

    fn check(env: &Env, cid: &Address, s: &CompatSnapshot) -> Result<CompatReport, CompatError> {
        env.as_contract(cid, || check_upgrade(env, s))
    }

    fn baseline(env: &Env, cid: &Address, c: &Symbol) -> Option<CompatSnapshot> {
        env.as_contract(cid, || get_baseline(env, c))
    }

    fn previous(env: &Env, cid: &Address, c: &Symbol) -> Option<CompatSnapshot> {
        env.as_contract(cid, || get_previous(env, c))
    }

    fn ep(env: &Env, name: Symbol, args: &[Symbol], returns: Symbol) -> EntrypointSig {
        let mut a = Vec::new(env);
        for s in args {
            a.push_back(s.clone());
        }
        EntrypointSig { name, args: a, returns }
    }

    fn treasury_v1(env: &Env) -> CompatSnapshot {
        build_snapshot(
            env,
            symbol_short!("treasury"),
            1,
            1,
            vec![
                env,
                ep(env, symbol_short!("deposit"), &[symbol_short!("addr"), symbol_short!("i128")], symbol_short!("unit")),
                ep(env, symbol_short!("withdraw"), &[symbol_short!("addr"), symbol_short!("i128")], symbol_short!("unit")),
            ],
            vec![env, symbol_short!("Admin"), symbol_short!("Balance")],
            vec![env, symbol_short!("deposit"), symbol_short!("withdraw")],
        )
        .unwrap()
    }

    #[test]
    fn snapshot_is_order_independent_and_deterministic() {
        let (env, _, _) = setup();
        let a = treasury_v1(&env);
        let b = build_snapshot(
            &env,
            symbol_short!("treasury"),
            1,
            1,
            vec![
                &env,
                ep(&env, symbol_short!("withdraw"), &[symbol_short!("addr"), symbol_short!("i128")], symbol_short!("unit")),
                ep(&env, symbol_short!("deposit"), &[symbol_short!("addr"), symbol_short!("i128")], symbol_short!("unit")),
            ],
            vec![&env, symbol_short!("Balance"), symbol_short!("Admin")],
            vec![&env, symbol_short!("withdraw"), symbol_short!("deposit")],
        )
        .unwrap();
        assert_eq!(a, b);
        assert_eq!(a.surface_hash, b.surface_hash);
        assert!(verify_snapshot(&env, &a).is_ok());

        // Version is not part of the surface hash.
        let mut v2 = a.clone();
        v2.version = 2;
        assert!(verify_snapshot(&env, &v2).is_ok());
    }

    #[test]
    fn failure_duplicates_bounds_and_tampering_rejected() {
        let (env, _, _) = setup();
        let dup = build_snapshot(
            &env,
            symbol_short!("treasury"),
            1,
            1,
            Vec::new(&env),
            vec![&env, symbol_short!("Admin"), symbol_short!("Admin")],
            Vec::new(&env),
        );
        assert_eq!(dup, Err(CompatError::DuplicateItem));

        let mut many = Vec::new(&env);
        for _ in 0..=MAX_SNAPSHOT_EVENT_TOPICS {
            many.push_back(symbol_short!("t"));
        }
        let too_many = build_snapshot(&env, symbol_short!("x"), 1, 1, Vec::new(&env), Vec::new(&env), many);
        assert_eq!(too_many, Err(CompatError::TooManyItems));

        let mut tampered = treasury_v1(&env);
        tampered.storage_keys.push_back(symbol_short!("Zzz"));
        assert_eq!(verify_snapshot(&env, &tampered), Err(CompatError::FingerprintMismatch));
    }

    #[test]
    fn normal_additive_upgrade_is_compatible_and_promoted() {
        let (env, cid, admin) = setup();
        let v1 = treasury_v1(&env);
        rec(&env, &cid, &admin, &v1).unwrap();

        let mut eps = v1.entrypoints.clone();
        eps.push_back(ep(&env, symbol_short!("pause"), &[symbol_short!("addr")], symbol_short!("unit")));
        let mut topics = v1.event_topics.clone();
        topics.push_back(symbol_short!("paused"));
        let v2 = build_snapshot(&env, v1.contract.clone(), 2, 1, eps, v1.storage_keys.clone(), topics).unwrap();

        let report = check(&env, &cid, &v2).unwrap();
        assert_eq!(report.verdict, CompatVerdict::Compatible);
        assert_eq!(report.added_entrypoints, vec![&env, symbol_short!("pause")]);
        assert_eq!(report.added_event_topics, vec![&env, symbol_short!("paused")]);

        approve(&env, &cid, &admin, &v2, false).unwrap();
        assert_eq!(baseline(&env, &cid, &v1.contract), Some(v2));
        assert_eq!(previous(&env, &cid, &v1.contract), Some(v1));
    }

    #[test]
    fn breaking_and_migration_paths() {
        let (env, cid, admin) = setup();
        let v1 = treasury_v1(&env);
        rec(&env, &cid, &admin, &v1).unwrap();

        // Signature change on `withdraw` -> Breaking, never approvable.
        let changed = build_snapshot(
            &env,
            v1.contract.clone(),
            2,
            1,
            vec![
                &env,
                ep(&env, symbol_short!("deposit"), &[symbol_short!("addr"), symbol_short!("i128")], symbol_short!("unit")),
                ep(&env, symbol_short!("withdraw"), &[symbol_short!("addr")], symbol_short!("unit")),
            ],
            v1.storage_keys.clone(),
            v1.event_topics.clone(),
        )
        .unwrap();
        let r = check(&env, &cid, &changed).unwrap();
        assert_eq!(r.verdict, CompatVerdict::Breaking);
        assert_eq!(r.changed_entrypoints, vec![&env, symbol_short!("withdraw")]);
        assert_eq!(approve(&env, &cid, &admin, &changed, true), Err(CompatError::BreakingChange));

        // Schema regression -> Breaking.
        let regress = build_snapshot(&env, v1.contract.clone(), 2, 0, v1.entrypoints.clone(), v1.storage_keys.clone(), v1.event_topics.clone()).unwrap();
        assert_eq!(check(&env, &cid, &regress).unwrap().verdict, CompatVerdict::Breaking);

        // Removed storage family + schema bump -> RequiresMigration.
        let migrate = build_snapshot(&env, v1.contract.clone(), 2, 2, v1.entrypoints.clone(), vec![&env, symbol_short!("Admin")], v1.event_topics.clone()).unwrap();
        let r = check(&env, &cid, &migrate).unwrap();
        assert_eq!(r.verdict, CompatVerdict::RequiresMigration);
        assert_eq!(r.removed_storage_keys, vec![&env, symbol_short!("Balance")]);
        assert_eq!(r.schema_delta, 1);
        assert_eq!(approve(&env, &cid, &admin, &migrate, false), Err(CompatError::MigrationNotAcknowledged));
        // Failed approvals leave the baseline untouched.
        assert_eq!(baseline(&env, &cid, &v1.contract), Some(v1.clone()));
        approve(&env, &cid, &admin, &migrate, true).unwrap();
        assert_eq!(baseline(&env, &cid, &v1.contract), Some(migrate));
    }

    #[test]
    fn retry_paths_are_idempotent_and_versions_monotonic() {
        let (env, cid, admin) = setup();
        let v1 = treasury_v1(&env);
        rec(&env, &cid, &admin, &v1).unwrap();
        // Retrying the identical baseline succeeds; a different one conflicts.
        rec(&env, &cid, &admin, &v1).unwrap();
        let mut other = v1.clone();
        other.version = 9;
        assert_eq!(rec(&env, &cid, &admin, &other), Err(CompatError::BaselineConflict));

        let mut v2 = v1.clone();
        v2.version = 2;
        let r = approve(&env, &cid, &admin, &v2, false).unwrap();
        assert_eq!(r.verdict, CompatVerdict::Identical);
        // Resubmitting the same approval is a no-op success.
        approve(&env, &cid, &admin, &v2, false).unwrap();
        assert_eq!(previous(&env, &cid, &v1.contract), Some(v1.clone()));

        // Downgrade attempt is rejected.
        assert_eq!(approve(&env, &cid, &admin, &v1, false), Err(CompatError::VersionNotIncreasing));
        // Unknown contract has no baseline.
        let mut unknown = v1.clone();
        unknown.contract = symbol_short!("ghost");
        let unknown = build_snapshot(&env, unknown.contract, 1, 1, unknown.entrypoints, unknown.storage_keys, unknown.event_topics).unwrap();
        assert_eq!(check(&env, &cid, &unknown), Err(CompatError::NoBaseline));
    }

    #[test]
    fn rollback_restores_previous_once() {
        let (env, cid, admin) = setup();
        let v1 = treasury_v1(&env);
        rec(&env, &cid, &admin, &v1).unwrap();
        assert_eq!(rollback(&env, &cid, &admin, &v1.contract), Err(CompatError::NoRollbackTarget));

        let mut keys = v1.storage_keys.clone();
        keys.push_back(symbol_short!("Quota"));
        let v2 = build_snapshot(&env, v1.contract.clone(), 2, 1, v1.entrypoints.clone(), keys, v1.event_topics.clone()).unwrap();
        approve(&env, &cid, &admin, &v2, false).unwrap();

        let restored = rollback(&env, &cid, &admin, &v1.contract).unwrap();
        assert_eq!(restored, v1);
        assert_eq!(baseline(&env, &cid, &v1.contract), Some(v1.clone()));
        assert_eq!(rollback(&env, &cid, &admin, &v1.contract), Err(CompatError::NoRollbackTarget));
        // Re-applying the upgrade after a rollback works.
        approve(&env, &cid, &admin, &v2, false).unwrap();
    }

    #[test]
    fn authorization_required_for_mutations() {
        let (env, cid, admin) = setup();
        let intruder = Address::generate(&env);
        let v1 = treasury_v1(&env);
        assert_eq!(rec(&env, &cid, &intruder, &v1), Err(CompatError::Unauthorized));
        rec(&env, &cid, &admin, &v1).unwrap();
        let mut v2 = v1.clone();
        v2.version = 2;
        assert_eq!(approve(&env, &cid, &intruder, &v2, false), Err(CompatError::Unauthorized));
        approve(&env, &cid, &admin, &v2, false).unwrap();
        assert_eq!(rollback(&env, &cid, &intruder, &v1.contract), Err(CompatError::Unauthorized));
        // Read-only checks need no auth.
        assert!(check(&env, &cid, &v2).is_ok());
    }
}

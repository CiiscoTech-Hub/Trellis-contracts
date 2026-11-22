//! Treasury balance conservation ledger and invariant checks (Issue #324).
//!
//! A deterministic accounting model of every treasury state transition
//! (deposit, withdraw, category transfer, strategy allocate/recall, yield
//! harvest, emergency withdraw) with invariants that must hold after **every**
//! operation, successful or not:
//!
//! | Id | Invariant                                                           |
//! |----|---------------------------------------------------------------------|
//! | I1 | `Σ categories + allocated == total_inflow − total_outflow`          |
//! | I2 | every category balance and `allocated` is ≥ 0                       |
//! | I3 | `total_inflow` and `total_outflow` never decrease                   |
//! | I4 | a rejected or duplicate op leaves the state byte-for-byte unchanged |
//! | I5 | `Σ categories` equals the token balance actually held on-contract   |
//!
//! Every op carries a caller-chosen `op_id`. Re-submitting the same op is a
//! no-op [`ApplyOutcome::Duplicate`]; re-using an `op_id` with a different
//! payload is rejected with [`ConservationError::OpIdConflict`]. All checks
//! run before any write, so atomicity does not rely on transaction rollback.

use soroban_sdk::{contracttype, symbol_short, Address, Env, Map, Symbol};

use crate::storage::{persistent_has, persistent_read, persistent_remove, persistent_set};

pub const TOPIC_TREASURY_OP: Symbol = symbol_short!("trs_op");

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum TreasuryOpKind {
    Deposit = 0,
    Withdraw = 1,
    Transfer = 2,
    Allocate = 3,
    Recall = 4,
    Harvest = 5,
    EmergencyWithdraw = 6,
}

/// `from` / `to` are category symbols; unused sides are ignored.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreasuryOp {
    pub op_id: u64,
    pub kind: TreasuryOpKind,
    pub actor: Address,
    pub from: Symbol,
    pub to: Symbol,
    pub amount: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConservationState {
    pub categories: Map<Symbol, i128>,
    /// Funds deployed to reserve strategies: still treasury assets, but not
    /// held by the contract.
    pub allocated: i128,
    pub total_inflow: i128,
    pub total_outflow: i128,
    pub applied_ops: u64,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ApplyOutcome {
    Applied = 0,
    Duplicate = 1,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ConservationError {
    Unauthorized = 1,
    InvalidAmount = 2,
    InsufficientBalance = 3,
    InsufficientAllocation = 4,
    SameCategory = 5,
    Overflow = 6,
    OpIdConflict = 7,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum InvariantBreach {
    SupplyMismatch = 1,
    NegativeBalance = 2,
    FlowDecreased = 3,
    ExternalBalanceMismatch = 4,
    AppliedCountDecreased = 5,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum TcKey {
    State,
    Manager(Address),
    Applied(u64),
}

// ---------------------------------------------------------------------------
// State access
// ---------------------------------------------------------------------------

pub fn empty_state(env: &Env) -> ConservationState {
    ConservationState {
        categories: Map::new(env),
        allocated: 0,
        total_inflow: 0,
        total_outflow: 0,
        applied_ops: 0,
    }
}

pub fn get_state(env: &Env) -> ConservationState {
    persistent_read(env, &TcKey::State).unwrap_or_else(|| empty_state(env))
}

pub fn get_applied_op(env: &Env, op_id: u64) -> Option<TreasuryOp> {
    persistent_read(env, &TcKey::Applied(op_id))
}

pub fn set_manager(
    env: &Env,
    caller: &Address,
    who: &Address,
    allowed: bool,
) -> Result<(), ConservationError> {
    crate::auth::require_admin(env, caller).map_err(|_| ConservationError::Unauthorized)?;
    if allowed {
        persistent_set(env, &TcKey::Manager(who.clone()), &true);
    } else {
        persistent_remove(env, &TcKey::Manager(who.clone()));
    }
    Ok(())
}

fn is_admin(env: &Env, who: &Address) -> bool {
    crate::auth::get_admin(env) == *who
}

fn is_manager(env: &Env, who: &Address) -> bool {
    is_admin(env, who) || persistent_has(env, &TcKey::Manager(who.clone()))
}

// ---------------------------------------------------------------------------
// Transition
// ---------------------------------------------------------------------------

fn add(a: i128, b: i128) -> Result<i128, ConservationError> {
    a.checked_add(b).ok_or(ConservationError::Overflow)
}

fn bal(state: &ConservationState, cat: &Symbol) -> i128 {
    state.categories.get(cat.clone()).unwrap_or(0)
}

/// Pure transition: returns the next state or an error, never a partial one.
pub fn transition(
    env: &Env,
    state: &ConservationState,
    op: &TreasuryOp,
) -> Result<ConservationState, ConservationError> {
    let authorized = match op.kind {
        TreasuryOpKind::Deposit => true,
        TreasuryOpKind::EmergencyWithdraw => is_admin(env, &op.actor),
        _ => is_manager(env, &op.actor),
    };
    if !authorized {
        return Err(ConservationError::Unauthorized);
    }
    if op.amount <= 0 {
        return Err(ConservationError::InvalidAmount);
    }

    let mut next = state.clone();
    let a = op.amount;
    match op.kind {
        TreasuryOpKind::Deposit => {
            next.categories.set(op.to.clone(), add(bal(state, &op.to), a)?);
            next.total_inflow = add(next.total_inflow, a)?;
        }
        TreasuryOpKind::Harvest => {
            next.categories.set(op.to.clone(), add(bal(state, &op.to), a)?);
            next.total_inflow = add(next.total_inflow, a)?;
        }
        TreasuryOpKind::Withdraw | TreasuryOpKind::EmergencyWithdraw => {
            let from = bal(state, &op.from);
            if from < a {
                return Err(ConservationError::InsufficientBalance);
            }
            next.categories.set(op.from.clone(), from - a);
            next.total_outflow = add(next.total_outflow, a)?;
        }
        TreasuryOpKind::Transfer => {
            if op.from == op.to {
                return Err(ConservationError::SameCategory);
            }
            let from = bal(state, &op.from);
            if from < a {
                return Err(ConservationError::InsufficientBalance);
            }
            next.categories.set(op.from.clone(), from - a);
            next.categories.set(op.to.clone(), add(bal(state, &op.to), a)?);
        }
        TreasuryOpKind::Allocate => {
            let from = bal(state, &op.from);
            if from < a {
                return Err(ConservationError::InsufficientBalance);
            }
            next.categories.set(op.from.clone(), from - a);
            next.allocated = add(next.allocated, a)?;
        }
        TreasuryOpKind::Recall => {
            if state.allocated < a {
                return Err(ConservationError::InsufficientAllocation);
            }
            next.allocated -= a;
            next.categories.set(op.to.clone(), add(bal(state, &op.to), a)?);
        }
    }
    next.applied_ops += 1;
    Ok(next)
}

/// Apply `op` to the stored ledger. Idempotent per `op_id`.
pub fn apply_op(env: &Env, op: &TreasuryOp) -> Result<ApplyOutcome, ConservationError> {
    if let Some(prior) = get_applied_op(env, op.op_id) {
        return if prior == *op {
            Ok(ApplyOutcome::Duplicate)
        } else {
            Err(ConservationError::OpIdConflict)
        };
    }
    op.actor.require_auth();
    let state = get_state(env);
    let next = transition(env, &state, op)?;
    persistent_set(env, &TcKey::State, &next);
    persistent_set(env, &TcKey::Applied(op.op_id), op);
    env.events().publish((TOPIC_TREASURY_OP, op.kind), (op.op_id, op.amount));
    Ok(ApplyOutcome::Applied)
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

pub fn held_on_contract(state: &ConservationState) -> i128 {
    let mut sum = 0i128;
    for (_, v) in state.categories.iter() {
        sum = sum.saturating_add(v);
    }
    sum
}

/// I1 + I2 on a single state.
pub fn check_state(state: &ConservationState) -> Result<(), InvariantBreach> {
    if state.allocated < 0 {
        return Err(InvariantBreach::NegativeBalance);
    }
    for (_, v) in state.categories.iter() {
        if v < 0 {
            return Err(InvariantBreach::NegativeBalance);
        }
    }
    let assets = held_on_contract(state).checked_add(state.allocated);
    let net = state.total_inflow.checked_sub(state.total_outflow);
    match (assets, net) {
        (Some(a), Some(n)) if a == n => Ok(()),
        _ => Err(InvariantBreach::SupplyMismatch),
    }
}

/// I3 across a transition, plus I1/I2 on the new state.
pub fn check_transition(
    prev: &ConservationState,
    next: &ConservationState,
) -> Result<(), InvariantBreach> {
    check_state(next)?;
    if next.total_inflow < prev.total_inflow || next.total_outflow < prev.total_outflow {
        return Err(InvariantBreach::FlowDecreased);
    }
    if next.applied_ops < prev.applied_ops {
        return Err(InvariantBreach::AppliedCountDecreased);
    }
    Ok(())
}

/// I5: reconcile the ledger against the token balance the contract holds.
pub fn check_external_balance(
    state: &ConservationState,
    token_balance: i128,
) -> Result<(), InvariantBreach> {
    check_state(state)?;
    if held_on_contract(state) != token_balance {
        return Err(InvariantBreach::ExternalBalanceMismatch);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec::Vec as StdVec;

    use super::*;
    use soroban_sdk::{contract, contractimpl, testutils::Address as _, Address, Env};

    #[contract]
    struct ConservationTestContract;
    #[contractimpl]
    impl ConservationTestContract {}

    struct Fx {
        env: Env,
        cid: Address,
        admin: Address,
        manager: Address,
        outsider: Address,
    }

    fn setup() -> Fx {
        let env = Env::default();
        env.mock_all_auths();
        env.budget().reset_unlimited();
        let cid = env.register_contract(None, ConservationTestContract);
        let admin = Address::generate(&env);
        let manager = Address::generate(&env);
        let outsider = Address::generate(&env);
        env.as_contract(&cid, || crate::auth::set_admin(&env, &admin));
        let fx = Fx { env, cid, admin, manager, outsider };
        manage(&fx, &fx.admin, &fx.manager, true).unwrap();
        fx
    }

    // Each call runs in its own frame, as a real invocation would; Soroban
    // rejects a second `require_auth` for the same address within one frame.
    fn apply(fx: &Fx, o: &TreasuryOp) -> Result<ApplyOutcome, ConservationError> {
        fx.env.as_contract(&fx.cid, || apply_op(&fx.env, o))
    }

    fn manage(fx: &Fx, caller: &Address, who: &Address, allowed: bool) -> Result<(), ConservationError> {
        fx.env.as_contract(&fx.cid, || set_manager(&fx.env, caller, who, allowed))
    }

    fn state(fx: &Fx) -> ConservationState {
        fx.env.as_contract(&fx.cid, || get_state(&fx.env))
    }

    fn applied_op(fx: &Fx, id: u64) -> Option<TreasuryOp> {
        fx.env.as_contract(&fx.cid, || get_applied_op(&fx.env, id))
    }

    fn op(id: u64, kind: TreasuryOpKind, actor: &Address, from: Symbol, to: Symbol, amount: i128) -> TreasuryOp {
        TreasuryOp { op_id: id, kind, actor: actor.clone(), from, to, amount }
    }

    /// Deterministic xorshift64* so failures reproduce from the seed.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    fn random_op(fx: &Fx, rng: &mut Rng, id: u64) -> TreasuryOp {
        let cats = [symbol_short!("ops"), symbol_short!("grants"), symbol_short!("reserve")];
        let kind = match rng.below(7) {
            0 => TreasuryOpKind::Deposit,
            1 => TreasuryOpKind::Withdraw,
            2 => TreasuryOpKind::Transfer,
            3 => TreasuryOpKind::Allocate,
            4 => TreasuryOpKind::Recall,
            5 => TreasuryOpKind::Harvest,
            _ => TreasuryOpKind::EmergencyWithdraw,
        };
        let actor = match rng.below(10) {
            0 => &fx.outsider,
            1 | 2 => &fx.admin,
            _ => &fx.manager,
        };
        let amount = match rng.below(20) {
            0 => 0,
            1 => -((rng.below(1_000) + 1) as i128),
            2 => i128::MAX,
            _ => (rng.below(5_000) + 1) as i128,
        };
        let from = cats[rng.below(3) as usize].clone();
        let to = cats[rng.below(3) as usize].clone();
        op(id, kind, actor, from, to, amount)
    }

    /// Property: across seeded random sequences of valid, invalid,
    /// unauthorized, overflow, duplicate and conflicting operations, I1–I4
    /// hold after every step.
    #[test]
    fn property_conservation_holds_for_random_sequences() {
        for seed in [0x5EED_0001u64, 0xC0FFEE, 0xDEAD_BEEF, 42, 7_777_777] {
            let fx = setup();
            let mut rng = Rng(seed);
            let mut applied: StdVec<TreasuryOp> = StdVec::new();
            let (mut ok, mut rejected, mut dupes) = (0u32, 0u32, 0u32);
            for step in 0..300u64 {
                let candidate = if !applied.is_empty() && rng.below(6) == 0 {
                    let prior = applied[rng.below(applied.len() as u64) as usize].clone();
                    if rng.below(4) == 0 {
                        // Same id, different payload.
                        let mut c = prior;
                        c.amount += 1;
                        c
                    } else {
                        prior
                    }
                } else {
                    random_op(&fx, &mut rng, 1_000 + step)
                };

                let before = state(&fx);
                match apply(&fx, &candidate) {
                    Ok(ApplyOutcome::Applied) => {
                        ok += 1;
                        applied.push(candidate);
                        let after = state(&fx);
                        check_transition(&before, &after)
                            .unwrap_or_else(|b| panic!("seed {seed} step {step}: {b:?}"));
                        assert_eq!(after.applied_ops, before.applied_ops + 1);
                    }
                    Ok(ApplyOutcome::Duplicate) => {
                        dupes += 1;
                        assert_eq!(state(&fx), before, "I4 dup seed {seed} step {step}");
                    }
                    Err(_) => {
                        rejected += 1;
                        assert_eq!(state(&fx), before, "I4 err seed {seed} step {step}");
                    }
                }
            }
            let end = state(&fx);
            check_state(&end).unwrap();
            assert_eq!(end.applied_ops, applied.len() as u64);
            // Sanity: the generator exercised every outcome class.
            assert!(ok > 50 && rejected > 20 && dupes > 5, "seed {seed}: {ok}/{rejected}/{dupes}");

            // Deterministic replay: re-running the accepted ops through the
            // pure transition on a fresh ledger reproduces the final state.
            let replay = setup();
            let replayed = replay.env.as_contract(&replay.cid, || {
                let mut s = empty_state(&replay.env);
                for o in applied.iter() {
                    let mut o = o.clone();
                    o.actor = if o.actor == fx.admin {
                        replay.admin.clone()
                    } else if o.actor == fx.manager {
                        replay.manager.clone()
                    } else {
                        replay.outsider.clone()
                    };
                    s = transition(&replay.env, &s, &o).unwrap();
                }
                s
            });
            assert_eq!(replayed.allocated, end.allocated);
            assert_eq!(replayed.total_inflow, end.total_inflow);
            assert_eq!(replayed.total_outflow, end.total_outflow);
            assert_eq!(replayed.applied_ops, end.applied_ops);
            assert_eq!(held_on_contract(&replayed), held_on_contract(&end));
        }
    }

    #[test]
    fn normal_lifecycle_conserves_and_reconciles() {
        let fx = setup();
        let (ops_c, grants, reserve) = (symbol_short!("ops"), symbol_short!("grants"), symbol_short!("reserve"));
        let m = &fx.manager;
        apply(&fx, &op(1, TreasuryOpKind::Deposit, &fx.outsider, ops_c.clone(), ops_c.clone(), 10_000)).unwrap();
        apply(&fx, &op(2, TreasuryOpKind::Transfer, m, ops_c.clone(), grants.clone(), 3_000)).unwrap();
        apply(&fx, &op(3, TreasuryOpKind::Allocate, m, ops_c.clone(), reserve.clone(), 4_000)).unwrap();
        apply(&fx, &op(4, TreasuryOpKind::Harvest, m, reserve.clone(), reserve.clone(), 250)).unwrap();
        apply(&fx, &op(5, TreasuryOpKind::Recall, m, reserve.clone(), reserve.clone(), 1_000)).unwrap();
        apply(&fx, &op(6, TreasuryOpKind::Withdraw, m, grants.clone(), grants.clone(), 2_000)).unwrap();
        apply(&fx, &op(7, TreasuryOpKind::EmergencyWithdraw, &fx.admin, ops_c.clone(), ops_c.clone(), 500)).unwrap();

        let s = state(&fx);
        check_state(&s).unwrap();
        assert_eq!(s.total_inflow, 10_250);
        assert_eq!(s.total_outflow, 2_500);
        assert_eq!(s.allocated, 3_000);
        assert_eq!(held_on_contract(&s), 4_750);
        // ops 10000-3000-4000-500=2500, grants 3000-2000=1000, reserve 250+1000=1250
        assert_eq!(s.categories.get(ops_c).unwrap(), 2_500);
        assert_eq!(s.categories.get(grants).unwrap(), 1_000);
        assert_eq!(s.categories.get(reserve).unwrap(), 1_250);
        check_external_balance(&s, 4_750).unwrap();
        assert_eq!(check_external_balance(&s, 4_749), Err(InvariantBreach::ExternalBalanceMismatch));
    }

    #[test]
    fn failure_paths_leave_state_unchanged() {
        let fx = setup();
        let c = symbol_short!("ops");
        let m = &fx.manager;
        apply(&fx, &op(1, TreasuryOpKind::Deposit, m, c.clone(), c.clone(), 100)).unwrap();
        let before = state(&fx);
        let cases = [
            (op(2, TreasuryOpKind::Withdraw, m, c.clone(), c.clone(), 101), ConservationError::InsufficientBalance),
            (op(3, TreasuryOpKind::Recall, m, c.clone(), c.clone(), 1), ConservationError::InsufficientAllocation),
            (op(4, TreasuryOpKind::Transfer, m, c.clone(), c.clone(), 1), ConservationError::SameCategory),
            (op(5, TreasuryOpKind::Deposit, m, c.clone(), c.clone(), 0), ConservationError::InvalidAmount),
            (op(6, TreasuryOpKind::Deposit, m, c.clone(), c.clone(), -5), ConservationError::InvalidAmount),
            (op(7, TreasuryOpKind::Deposit, m, c.clone(), c.clone(), i128::MAX), ConservationError::Overflow),
        ];
        for (o, err) in cases.iter() {
            assert_eq!(apply(&fx, o), Err(*err));
            assert_eq!(state(&fx), before);
            // A failed op does not burn its id: it can be fixed and retried.
            assert_eq!(applied_op(&fx, o.op_id), None);
        }
        apply(&fx, &op(2, TreasuryOpKind::Withdraw, m, c.clone(), c.clone(), 100)).unwrap();
        check_state(&state(&fx)).unwrap();
    }

    #[test]
    fn retry_is_idempotent_and_conflicts_rejected() {
        let fx = setup();
        let c = symbol_short!("ops");
        let d = op(1, TreasuryOpKind::Deposit, &fx.manager, c.clone(), c.clone(), 500);
        assert_eq!(apply(&fx, &d), Ok(ApplyOutcome::Applied));
        let s1 = state(&fx);
        for _ in 0..3 {
            assert_eq!(apply(&fx, &d), Ok(ApplyOutcome::Duplicate));
        }
        assert_eq!(state(&fx), s1);
        let mut conflict = d.clone();
        conflict.amount = 501;
        assert_eq!(apply(&fx, &conflict), Err(ConservationError::OpIdConflict));
        assert_eq!(state(&fx), s1);
    }

    #[test]
    fn authorization_paths() {
        let fx = setup();
        let c = symbol_short!("ops");
        apply(&fx, &op(1, TreasuryOpKind::Deposit, &fx.outsider, c.clone(), c.clone(), 1_000)).unwrap();
        for kind in [TreasuryOpKind::Withdraw, TreasuryOpKind::Allocate, TreasuryOpKind::Harvest] {
            assert_eq!(
                apply(&fx, &op(10, kind, &fx.outsider, c.clone(), c.clone(), 1)),
                Err(ConservationError::Unauthorized)
            );
        }
        // Emergency withdraw is admin-only, even for managers.
        assert_eq!(
            apply(&fx, &op(11, TreasuryOpKind::EmergencyWithdraw, &fx.manager, c.clone(), c.clone(), 1)),
            Err(ConservationError::Unauthorized)
        );
        // Revoked managers lose access immediately.
        manage(&fx, &fx.admin, &fx.manager, false).unwrap();
        assert_eq!(
            apply(&fx, &op(12, TreasuryOpKind::Withdraw, &fx.manager, c.clone(), c.clone(), 1)),
            Err(ConservationError::Unauthorized)
        );
        assert_eq!(manage(&fx, &fx.outsider, &fx.outsider, true), Err(ConservationError::Unauthorized));
        assert_eq!(state(&fx).total_outflow, 0);
    }

    #[test]
    #[should_panic]
    fn missing_signature_aborts() {
        let env = Env::default();
        let cid = env.register_contract(None, ConservationTestContract);
        let who = Address::generate(&env);
        env.as_contract(&cid, || {
            let c = symbol_short!("ops");
            let _ = apply_op(&env, &op(1, TreasuryOpKind::Deposit, &who, c.clone(), c, 1));
        });
    }

    #[test]
    fn corrupted_states_are_detected() {
        let fx = setup();
        let c = symbol_short!("ops");
        apply(&fx, &op(1, TreasuryOpKind::Deposit, &fx.manager, c.clone(), c.clone(), 100)).unwrap();
        let good = state(&fx);

        let mut inflated = good.clone();
        inflated.categories.set(c.clone(), 101);
        assert_eq!(check_state(&inflated), Err(InvariantBreach::SupplyMismatch));

        let mut negative = good.clone();
        negative.categories.set(c.clone(), -1);
        negative.categories.set(symbol_short!("x"), 101);
        assert_eq!(check_state(&negative), Err(InvariantBreach::NegativeBalance));

        let mut leaked = good.clone();
        leaked.allocated = 1;
        assert_eq!(check_state(&leaked), Err(InvariantBreach::SupplyMismatch));

        let mut rewound = good.clone();
        rewound.total_inflow = 0;
        rewound.categories.set(c.clone(), 0);
        assert_eq!(check_transition(&good, &rewound), Err(InvariantBreach::FlowDecreased));
    }
}

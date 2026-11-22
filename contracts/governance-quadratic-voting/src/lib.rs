#![no_std]

//! Governance Quadratic Voting Weight Cap & Delegation Snapshot Contract.
//!
//! Provides a focused vertical slice for:
//! - Stake delegation with direct self-delegation and cycle guards
//! - Per-proposal frozen delegation snapshots
//! - Exact integer quadratic voting weight (`floor(sqrt(raw_power))`) with hard weight cap
//! - Idempotent snapshot & vote retries
//! - Admin recovery/rollback (`cancel_proposal`, `reset_snapshot`)

use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, Env, Symbol};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum configurable delegation chain depth for cycle detection.
pub const MAX_DELEGATION_DEPTH: u32 = 8;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    Unauthorized = 3,
    InvalidConfig = 4,
    SelfDelegation = 5,
    DelegationCycle = 6,
    DelegationDepthExceeded = 7,
    NotDelegated = 8,
    AlreadyExists = 9,
    ProposalNotFound = 10,
    InvalidWindow = 11,
    VotingNotOpen = 12,
    ProposalCancelled = 13,
    SnapshotNotFound = 14,
    ZeroVotingPower = 15,
    AlreadyVoted = 16,
    InvalidState = 17,
}

// ---------------------------------------------------------------------------
// Domain Types
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VotingConfig {
    /// Maximum capped quadratic voting weight any single voter can cast per proposal.
    pub max_weight_cap: u128,
    /// Maximum ancestor hops checked when delegating (1..=MAX_DELEGATION_DEPTH).
    pub max_delegation_depth: u32,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposalStatus {
    Active,
    Cancelled,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proposal {
    pub id: Symbol,
    pub snapshot_ledger: u32,
    pub start_ledger: u32,
    pub end_ledger: u32,
    pub for_weight: u128,
    pub against_weight: u128,
    pub status: ProposalStatus,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoterSnapshot {
    pub proposal_id: Symbol,
    pub voter: Address,
    pub raw_power: u128,
    pub quadratic_weight: u128,
    pub capped_weight: u128,
    pub capped: bool,
    pub recorded_ledger: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoteReceipt {
    pub proposal_id: Symbol,
    pub voter: Address,
    pub support: bool,
    pub weight_cast: u128,
    pub idempotency_key: Symbol,
    pub cast_ledger: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum StorageKey {
    Admin,
    Snapshotter,
    Config,
    Stake(Address),
    DelegateOf(Address),
    DelegatedIn(Address),
    Proposal(Symbol),
    Snapshot(Symbol, Address),
    Vote(Symbol, Address),
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct GovernanceQuadraticVotingContract;

#[contractimpl]
impl GovernanceQuadraticVotingContract {
    /// Initialize contract roles and voting configuration. Can only be called once.
    pub fn init(
        env: Env,
        admin: Address,
        snapshotter: Address,
        config: VotingConfig,
    ) -> Result<(), Error> {
        if env.storage().instance().has(&StorageKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        validate_config(&config)?;
        env.storage().instance().set(&StorageKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&StorageKey::Snapshotter, &snapshotter);
        env.storage().instance().set(&StorageKey::Config, &config);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Admin Role & Config Management
    // -----------------------------------------------------------------------

    pub fn set_snapshotter(env: Env, admin: Address, new_snapshotter: Address) -> Result<(), Error> {
        require_admin(&env, &admin)?;
        env.storage()
            .instance()
            .set(&StorageKey::Snapshotter, &new_snapshotter);
        Ok(())
    }

    pub fn transfer_admin(env: Env, admin: Address, new_admin: Address) -> Result<(), Error> {
        require_admin(&env, &admin)?;
        env.storage().instance().set(&StorageKey::Admin, &new_admin);
        Ok(())
    }

    pub fn set_config(env: Env, admin: Address, config: VotingConfig) -> Result<(), Error> {
        require_admin(&env, &admin)?;
        validate_config(&config)?;
        env.storage().instance().set(&StorageKey::Config, &config);
        Ok(())
    }

    pub fn get_config(env: Env) -> Result<VotingConfig, Error> {
        get_config_internal(&env)
    }

    // -----------------------------------------------------------------------
    // Stake & Delegation Management
    // -----------------------------------------------------------------------

    /// Set an account's raw governance stake. Admin or Snapshotter.
    /// Automatically adjusts `DelegatedIn` if `account` has an active delegatee.
    pub fn set_stake(
        env: Env,
        caller: Address,
        account: Address,
        new_stake: u128,
    ) -> Result<(), Error> {
        require_snapshotter_or_admin(&env, &caller)?;
        let stake_key = StorageKey::Stake(account.clone());
        let old_stake: u128 = env.storage().persistent().get(&stake_key).unwrap_or(0);
        env.storage().persistent().set(&stake_key, &new_stake);

        if let Some(delegatee) = env
            .storage()
            .persistent()
            .get::<_, Address>(&StorageKey::DelegateOf(account))
        {
            let del_key = StorageKey::DelegatedIn(delegatee);
            let current_in: u128 = env.storage().persistent().get(&del_key).unwrap_or(0);
            let adjusted = current_in
                .saturating_sub(old_stake)
                .saturating_add(new_stake);
            env.storage().persistent().set(&del_key, &adjusted);
        }
        Ok(())
    }

    /// Delegate `delegator`'s stake to `delegatee`.
    /// Rejects self-delegation and delegation cycles (fail-closed at `max_delegation_depth`).
    pub fn delegate(env: Env, delegator: Address, delegatee: Address) -> Result<(), Error> {
        delegator.require_auth();
        if delegator == delegatee {
            return Err(Error::SelfDelegation);
        }

        let config = get_config_internal(&env)?;

        // Check for delegation cycles up to max_delegation_depth.
        let mut cursor = delegatee.clone();
        for _ in 0..config.max_delegation_depth {
            match env
                .storage()
                .persistent()
                .get::<_, Address>(&StorageKey::DelegateOf(cursor.clone()))
            {
                Some(next) => {
                    if next == delegator {
                        return Err(Error::DelegationCycle);
                    }
                    cursor = next;
                }
                None => break,
            }
        }
        if env
            .storage()
            .persistent()
            .has(&StorageKey::DelegateOf(cursor))
        {
            return Err(Error::DelegationDepthExceeded);
        }

        let own_stake: u128 = env
            .storage()
            .persistent()
            .get(&StorageKey::Stake(delegator.clone()))
            .unwrap_or(0);

        // Remove stake from previous delegatee if re-delegating.
        let del_of_key = StorageKey::DelegateOf(delegator);
        if let Some(prev_delegatee) = env
            .storage()
            .persistent()
            .get::<_, Address>(&del_of_key)
        {
            let prev_in_key = StorageKey::DelegatedIn(prev_delegatee);
            let prev_in: u128 = env.storage().persistent().get(&prev_in_key).unwrap_or(0);
            env.storage()
                .persistent()
                .set(&prev_in_key, &prev_in.saturating_sub(own_stake));
        }

        // Credit new delegatee.
        let new_in_key = StorageKey::DelegatedIn(delegatee.clone());
        let new_in: u128 = env.storage().persistent().get(&new_in_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&new_in_key, &new_in.saturating_add(own_stake));
        env.storage().persistent().set(&del_of_key, &delegatee);
        Ok(())
    }

    /// Remove `delegator`'s active delegation and restore their own voting power.
    pub fn undelegate(env: Env, delegator: Address) -> Result<(), Error> {
        delegator.require_auth();
        let del_of_key = StorageKey::DelegateOf(delegator.clone());
        let delegatee: Address = env
            .storage()
            .persistent()
            .get(&del_of_key)
            .ok_or(Error::NotDelegated)?;

        let own_stake: u128 = env
            .storage()
            .persistent()
            .get(&StorageKey::Stake(delegator))
            .unwrap_or(0);

        let in_key = StorageKey::DelegatedIn(delegatee);
        let current_in: u128 = env.storage().persistent().get(&in_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&in_key, &current_in.saturating_sub(own_stake));
        env.storage().persistent().remove(&del_of_key);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Proposal & Delegation Snapshot
    // -----------------------------------------------------------------------

    /// Create a new governance proposal. Admin or Snapshotter.
    pub fn create_proposal(
        env: Env,
        caller: Address,
        proposal_id: Symbol,
        start_ledger: u32,
        end_ledger: u32,
    ) -> Result<Proposal, Error> {
        require_snapshotter_or_admin(&env, &caller)?;
        if end_ledger <= start_ledger {
            return Err(Error::InvalidWindow);
        }
        let key = StorageKey::Proposal(proposal_id.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        let proposal = Proposal {
            id: proposal_id,
            snapshot_ledger: env.ledger().sequence(),
            start_ledger,
            end_ledger,
            for_weight: 0,
            against_weight: 0,
            status: ProposalStatus::Active,
        };
        env.storage().persistent().set(&key, &proposal);
        Ok(proposal)
    }

    /// Record a voter's frozen quadratic voting snapshot for `proposal_id`.
    ///
    /// - Authorized for `Admin` or `Snapshotter`.
    /// - Idempotent: if a snapshot already exists for `(proposal_id, voter)`, returns it unchanged.
    /// - Computes `raw_power = (own_stake if not delegated else 0) + delegated_in`.
    /// - Computes `quadratic_weight = floor(sqrt(raw_power))`, clamped to `config.max_weight_cap`.
    pub fn record_snapshot(
        env: Env,
        caller: Address,
        proposal_id: Symbol,
        voter: Address,
    ) -> Result<VoterSnapshot, Error> {
        require_snapshotter_or_admin(&env, &caller)?;
        let proposal: Proposal = env
            .storage()
            .persistent()
            .get(&StorageKey::Proposal(proposal_id.clone()))
            .ok_or(Error::ProposalNotFound)?;
        if proposal.status == ProposalStatus::Cancelled {
            return Err(Error::ProposalCancelled);
        }

        let snap_key = StorageKey::Snapshot(proposal_id.clone(), voter.clone());
        if let Some(existing) = env
            .storage()
            .persistent()
            .get::<_, VoterSnapshot>(&snap_key)
        {
            return Ok(existing);
        }

        let config = get_config_internal(&env)?;
        let has_delegated = env
            .storage()
            .persistent()
            .has(&StorageKey::DelegateOf(voter.clone()));
        let own_stake: u128 = if has_delegated {
            0
        } else {
            env.storage()
                .persistent()
                .get(&StorageKey::Stake(voter.clone()))
                .unwrap_or(0)
        };
        let delegated_in: u128 = env
            .storage()
            .persistent()
            .get(&StorageKey::DelegatedIn(voter.clone()))
            .unwrap_or(0);

        let raw_power = own_stake.saturating_add(delegated_in);
        let quadratic_weight = isqrt(raw_power);
        let (capped_weight, capped) = if quadratic_weight > config.max_weight_cap {
            (config.max_weight_cap, true)
        } else {
            (quadratic_weight, false)
        };

        let snapshot = VoterSnapshot {
            proposal_id,
            voter,
            raw_power,
            quadratic_weight,
            capped_weight,
            capped,
            recorded_ledger: env.ledger().sequence(),
        };
        env.storage().persistent().set(&snap_key, &snapshot);
        Ok(snapshot)
    }

    // -----------------------------------------------------------------------
    // Voting & Admin Rollback / Recovery
    // -----------------------------------------------------------------------

    /// Cast a vote using the voter's frozen snapshot weight.
    /// Idempotent when retried with the same `idempotency_key`.
    pub fn cast_vote(
        env: Env,
        voter: Address,
        proposal_id: Symbol,
        support: bool,
        idempotency_key: Symbol,
    ) -> Result<VoteReceipt, Error> {
        voter.require_auth();

        let prop_key = StorageKey::Proposal(proposal_id.clone());
        let mut proposal: Proposal = env
            .storage()
            .persistent()
            .get(&prop_key)
            .ok_or(Error::ProposalNotFound)?;

        if proposal.status == ProposalStatus::Cancelled {
            return Err(Error::ProposalCancelled);
        }

        let vote_key = StorageKey::Vote(proposal_id.clone(), voter.clone());
        if let Some(existing) = env.storage().persistent().get::<_, VoteReceipt>(&vote_key) {
            if existing.idempotency_key == idempotency_key {
                return Ok(existing);
            }
            return Err(Error::AlreadyVoted);
        }

        let now = env.ledger().sequence();
        if now < proposal.start_ledger || now > proposal.end_ledger {
            return Err(Error::VotingNotOpen);
        }

        let snapshot: VoterSnapshot = env
            .storage()
            .persistent()
            .get(&StorageKey::Snapshot(proposal_id.clone(), voter.clone()))
            .ok_or(Error::SnapshotNotFound)?;

        if snapshot.capped_weight == 0 {
            return Err(Error::ZeroVotingPower);
        }

        if support {
            proposal.for_weight = proposal.for_weight.saturating_add(snapshot.capped_weight);
        } else {
            proposal.against_weight = proposal
                .against_weight
                .saturating_add(snapshot.capped_weight);
        }

        let receipt = VoteReceipt {
            proposal_id,
            voter,
            support,
            weight_cast: snapshot.capped_weight,
            idempotency_key,
            cast_ledger: now,
        };

        env.storage().persistent().set(&prop_key, &proposal);
        env.storage().persistent().set(&vote_key, &receipt);
        Ok(receipt)
    }

    /// Admin-only recovery: cancel an active proposal to halt voting.
    pub fn cancel_proposal(
        env: Env,
        admin: Address,
        proposal_id: Symbol,
    ) -> Result<Proposal, Error> {
        require_admin(&env, &admin)?;
        let prop_key = StorageKey::Proposal(proposal_id);
        let mut proposal: Proposal = env
            .storage()
            .persistent()
            .get(&prop_key)
            .ok_or(Error::ProposalNotFound)?;
        if proposal.status == ProposalStatus::Cancelled {
            return Err(Error::InvalidState);
        }
        proposal.status = ProposalStatus::Cancelled;
        env.storage().persistent().set(&prop_key, &proposal);
        Ok(proposal)
    }

    /// Admin-only recovery: reset a voter's snapshot before they have voted
    /// so a corrected snapshot can be re-recorded.
    pub fn reset_snapshot(
        env: Env,
        admin: Address,
        proposal_id: Symbol,
        voter: Address,
    ) -> Result<(), Error> {
        require_admin(&env, &admin)?;
        if env
            .storage()
            .persistent()
            .has(&StorageKey::Vote(proposal_id.clone(), voter.clone()))
        {
            return Err(Error::AlreadyVoted);
        }
        let snap_key = StorageKey::Snapshot(proposal_id, voter);
        if !env.storage().persistent().has(&snap_key) {
            return Err(Error::SnapshotNotFound);
        }
        env.storage().persistent().remove(&snap_key);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Read-Only Queries
    // -----------------------------------------------------------------------

    pub fn get_proposal(env: Env, proposal_id: Symbol) -> Option<Proposal> {
        env.storage()
            .persistent()
            .get(&StorageKey::Proposal(proposal_id))
    }

    pub fn get_snapshot(env: Env, proposal_id: Symbol, voter: Address) -> Option<VoterSnapshot> {
        env.storage()
            .persistent()
            .get(&StorageKey::Snapshot(proposal_id, voter))
    }

    pub fn get_vote(env: Env, proposal_id: Symbol, voter: Address) -> Option<VoteReceipt> {
        env.storage()
            .persistent()
            .get(&StorageKey::Vote(proposal_id, voter))
    }

    pub fn get_delegate(env: Env, delegator: Address) -> Option<Address> {
        env.storage()
            .persistent()
            .get(&StorageKey::DelegateOf(delegator))
    }
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

fn validate_config(config: &VotingConfig) -> Result<(), Error> {
    if config.max_weight_cap == 0 {
        return Err(Error::InvalidConfig);
    }
    if config.max_delegation_depth == 0 || config.max_delegation_depth > MAX_DELEGATION_DEPTH {
        return Err(Error::InvalidConfig);
    }
    Ok(())
}

fn get_config_internal(env: &Env) -> Result<VotingConfig, Error> {
    env.storage()
        .instance()
        .get(&StorageKey::Config)
        .ok_or(Error::NotInitialized)
}

fn require_admin(env: &Env, caller: &Address) -> Result<(), Error> {
    let admin: Address = env
        .storage()
        .instance()
        .get(&StorageKey::Admin)
        .ok_or(Error::NotInitialized)?;
    caller.require_auth();
    if caller != &admin {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

fn require_snapshotter_or_admin(env: &Env, caller: &Address) -> Result<(), Error> {
    let admin: Address = env
        .storage()
        .instance()
        .get(&StorageKey::Admin)
        .ok_or(Error::NotInitialized)?;
    let snapshotter: Address = env
        .storage()
        .instance()
        .get(&StorageKey::Snapshotter)
        .ok_or(Error::NotInitialized)?;
    caller.require_auth();
    if caller != &admin && caller != &snapshotter {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

/// Exact integer square root: `floor(sqrt(n))`.
fn isqrt(n: u128) -> u128 {
    if n < 2 {
        return n;
    }
    let mut x = 1u128 << ((128 - n.leading_zeros()).div_ceil(2));
    loop {
        let next = (x + n / x) >> 1;
        if next >= x {
            return x;
        }
        x = next;
    }
}

// ---------------------------------------------------------------------------
// Automated Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{symbol_short, testutils::Address as _, testutils::Ledger};

    struct Fixture {
        env: Env,
        client: GovernanceQuadraticVotingContractClient<'static>,
        admin: Address,
        snapshotter: Address,
        outsider: Address,
    }

    fn setup() -> Fixture {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_sequence_number(100);

        let contract_id = env.register_contract(None, GovernanceQuadraticVotingContract);
        let client = GovernanceQuadraticVotingContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let snapshotter = Address::generate(&env);
        let outsider = Address::generate(&env);

        client.init(
            &admin,
            &snapshotter,
            &VotingConfig {
                max_weight_cap: 50,
                max_delegation_depth: 4,
            },
        );

        Fixture {
            env,
            client,
            admin,
            snapshotter,
            outsider,
        }
    }

    #[test]
    fn normal_path_delegation_snapshot_quadratic_cap_and_vote() {
        let f = setup();
        let alice = Address::generate(&f.env);
        let bob = Address::generate(&f.env);
        let whale = Address::generate(&f.env);

        // Alice has 400, Bob has 500, Whale has 10_000
        f.client.set_stake(&f.snapshotter, &alice, &400);
        f.client.set_stake(&f.snapshotter, &bob, &500);
        f.client.set_stake(&f.snapshotter, &whale, &10_000);

        // Alice delegates to Bob -> Bob has 500 + 400 = 900 -> sqrt(900) = 30
        f.client.delegate(&alice, &bob);

        let prop_id = symbol_short!("prop_1");
        f.client
            .create_proposal(&f.snapshotter, &prop_id, &110, &200);

        let bob_snap = f.client.record_snapshot(&f.snapshotter, &prop_id, &bob);
        assert_eq!(bob_snap.raw_power, 900);
        assert_eq!(bob_snap.quadratic_weight, 30);
        assert_eq!(bob_snap.capped_weight, 30);
        assert!(!bob_snap.capped);

        // Alice delegated her stake -> 0 voting power
        let alice_snap = f.client.record_snapshot(&f.snapshotter, &prop_id, &alice);
        assert_eq!(alice_snap.raw_power, 0);
        assert_eq!(alice_snap.capped_weight, 0);

        // Whale has 10_000 -> sqrt(10_000) = 100 -> clamped to max_weight_cap = 50
        let whale_snap = f.client.record_snapshot(&f.snapshotter, &prop_id, &whale);
        assert_eq!(whale_snap.quadratic_weight, 100);
        assert_eq!(whale_snap.capped_weight, 50);
        assert!(whale_snap.capped);

        // Post-snapshot undelegation does NOT alter Bob's frozen snapshot
        f.client.undelegate(&alice);
        assert_eq!(
            f.client.get_snapshot(&prop_id, &bob).unwrap().capped_weight,
            30
        );

        // Advance into voting window
        f.env.ledger().set_sequence_number(120);

        let r_bob = f
            .client
            .cast_vote(&bob, &prop_id, &true, &symbol_short!("v_bob"));
        assert_eq!(r_bob.weight_cast, 30);

        let r_whale = f
            .client
            .cast_vote(&whale, &prop_id, &false, &symbol_short!("v_whl"));
        assert_eq!(r_whale.weight_cast, 50);

        // Alice cannot vote with 0 power
        assert_eq!(
            f.client
                .try_cast_vote(&alice, &prop_id, &true, &symbol_short!("v_ali")),
            Err(Ok(Error::ZeroVotingPower))
        );

        let prop = f.client.get_proposal(&prop_id).unwrap();
        assert_eq!(prop.for_weight, 30);
        assert_eq!(prop.against_weight, 50);
    }

    #[test]
    fn delegation_self_and_cycle_guards() {
        let f = setup();
        let a = Address::generate(&f.env);
        let b = Address::generate(&f.env);
        let c = Address::generate(&f.env);

        // Direct self-delegation rejected
        assert_eq!(
            f.client.try_delegate(&a, &a),
            Err(Ok(Error::SelfDelegation))
        );

        // Chain: a -> b -> c
        f.client.delegate(&a, &b);
        f.client.delegate(&b, &c);

        // Cycle: c -> a rejected
        assert_eq!(
            f.client.try_delegate(&c, &a),
            Err(Ok(Error::DelegationCycle))
        );
    }

    #[test]
    fn idempotent_retries_and_duplicate_vote_rejection() {
        let f = setup();
        let voter = Address::generate(&f.env);
        f.client.set_stake(&f.snapshotter, &voter, &100);

        let prop_id = symbol_short!("prop_2");
        f.client
            .create_proposal(&f.snapshotter, &prop_id, &100, &200);

        // Snapshot retry is idempotent
        let s1 = f.client.record_snapshot(&f.snapshotter, &prop_id, &voter);
        let s2 = f.client.record_snapshot(&f.snapshotter, &prop_id, &voter);
        assert_eq!(s1, s2);

        // Vote retry with same idempotency_key returns existing receipt
        let v1 = f
            .client
            .cast_vote(&voter, &prop_id, &true, &symbol_short!("k1"));
        let v1_retry = f
            .client
            .cast_vote(&voter, &prop_id, &true, &symbol_short!("k1"));
        assert_eq!(v1, v1_retry);
        assert_eq!(f.client.get_proposal(&prop_id).unwrap().for_weight, 10);

        // Different idempotency_key rejected as AlreadyVoted
        assert_eq!(
            f.client
                .try_cast_vote(&voter, &prop_id, &false, &symbol_short!("k2")),
            Err(Ok(Error::AlreadyVoted))
        );
    }

    #[test]
    fn recovery_rollback_cancel_proposal_and_reset_snapshot() {
        let f = setup();
        let voter = Address::generate(&f.env);
        f.client.set_stake(&f.snapshotter, &voter, &100);

        let prop_id = symbol_short!("prop_3");
        f.client
            .create_proposal(&f.snapshotter, &prop_id, &100, &200);
        f.client.record_snapshot(&f.snapshotter, &prop_id, &voter);

        // Admin resets snapshot before vote, updates stake, and re-records snapshot
        f.client.reset_snapshot(&f.admin, &prop_id, &voter);
        f.client.set_stake(&f.snapshotter, &voter, &400);
        let updated = f.client.record_snapshot(&f.snapshotter, &prop_id, &voter);
        assert_eq!(updated.capped_weight, 20);

        // Admin cancels proposal -> subsequent votes rejected
        let cancelled = f.client.cancel_proposal(&f.admin, &prop_id);
        assert_eq!(cancelled.status, ProposalStatus::Cancelled);
        assert_eq!(
            f.client
                .try_cast_vote(&voter, &prop_id, &true, &symbol_short!("v_c")),
            Err(Ok(Error::ProposalCancelled))
        );
    }

    #[test]
    fn authorization_and_window_failure_paths() {
        let f = setup();
        let voter = Address::generate(&f.env);

        // Outsider cannot set config or stake or create proposal
        assert_eq!(
            f.client.try_set_config(
                &f.outsider,
                &VotingConfig {
                    max_weight_cap: 100,
                    max_delegation_depth: 4,
                },
            ),
            Err(Ok(Error::Unauthorized))
        );
        assert_eq!(
            f.client.try_set_stake(&f.outsider, &voter, &100),
            Err(Ok(Error::Unauthorized))
        );
        assert_eq!(
            f.client
                .try_create_proposal(&f.outsider, &symbol_short!("p_x"), &110, &200),
            Err(Ok(Error::Unauthorized))
        );

        // Voting before start_ledger fails with VotingNotOpen
        f.client.set_stake(&f.snapshotter, &voter, &100);
        f.client
            .create_proposal(&f.snapshotter, &symbol_short!("p_win"), &150, &200);
        f.client
            .record_snapshot(&f.snapshotter, &symbol_short!("p_win"), &voter);
        assert_eq!(
            f.client
                .try_cast_vote(&voter, &symbol_short!("p_win"), &true, &symbol_short!("early")),
            Err(Ok(Error::VotingNotOpen))
        );

        // Snapshotter cannot cancel proposal (admin-only)
        assert_eq!(
            f.client
                .try_cancel_proposal(&f.snapshotter, &symbol_short!("p_win")),
            Err(Ok(Error::Unauthorized))
        );
    }
}

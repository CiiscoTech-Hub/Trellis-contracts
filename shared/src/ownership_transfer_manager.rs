//! Multi-role ownership transfer manager with configurable delay, acceptance proof, and deterministic expiry (#494).
//!
//! Provides a secure, two-step ownership handover engine for protocol contracts.
//! Supports:
//! - Multi-role ownership targets (SuperAdmin, TreasuryAdmin, GovernanceAdmin, EmergencyAdmin, Custom).
//! - Enforced delay / timelock before transfer becomes acceptable (`effective_after`).
//! - Deterministic expiration timestamp with permissionless expiry cleanup.
//! - Target rejection, owner cancellation, and audit event emissions.

use soroban_sdk::{
    contracttype, symbol_short, Address, Env, Symbol,
};

/// Error codes for ownership transfer operations.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum OwnershipTransferError {
    /// Caller is not authorized for the requested action.
    Unauthorized = 4401,
    /// An unexpired transfer proposal is already pending for this role.
    TransferAlreadyPending = 4402,
    /// No transfer proposal exists for the specified role.
    NoPendingTransfer = 4403,
    /// Caller is not the designated target owner.
    NotPendingOwner = 4404,
    /// The transfer proposal has expired and can no longer be accepted.
    TransferExpired = 4405,
    /// Timelock has not elapsed yet; cannot accept transfer early.
    TimelockNotElapsed = 4406,
    /// Requested validity or timelock duration is invalid or out of allowed bounds.
    InvalidDuration = 4407,
    /// Self-transfer: target owner cannot be identical to the current owner.
    SelfTransfer = 4408,
    /// Operation rejected because proposal is not in Pending status.
    TransferNotPending = 4409,
    /// Configuration parameter is out of bounds.
    ConfigOutOfBounds = 4410,
    /// Proposal ID mismatch.
    ProposalIdMismatch = 4411,
}

/// Identifies the ownership domain or capability being transferred.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnershipRole {
    SuperAdmin,
    TreasuryAdmin,
    GovernanceAdmin,
    EmergencyAdmin,
    Custom(Symbol),
}

/// Lifecycle status of an ownership transfer proposal.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferStatus {
    Pending,
    Accepted,
    Cancelled,
    Rejected,
    Expired,
}

/// Configuration governing transfer timelocks and validity windows.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferConfig {
    /// Minimum required delay in seconds before a proposal can be accepted (default: 300s).
    pub min_delay_seconds: u64,
    /// Maximum allowed duration in seconds before proposal expires (default: 604,800s / 7 days).
    pub max_validity_seconds: u64,
    /// Minimum allowed duration in seconds for validity (default: 600s).
    pub min_validity_seconds: u64,
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            min_delay_seconds: 300,        // 5 minutes timelock
            max_validity_seconds: 604_800, // 7 days max validity
            min_validity_seconds: 600,     // 10 minutes min validity
        }
    }
}

/// A structured record representing a proposed ownership transfer.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnershipTransferProposal {
    pub transfer_id: u64,
    pub role: OwnershipRole,
    pub current_owner: Address,
    pub target_owner: Address,
    pub created_at: u64,
    pub effective_after: u64,
    pub expires_at: u64,
    pub status: TransferStatus,
    pub nonce: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum DataKey {
    Config,
    Owner(OwnershipRole),
    PendingProposal(OwnershipRole),
    NextTransferId,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn get_transfer_config(env: &Env) -> TransferConfig {
    env.storage()
        .instance()
        .get(&DataKey::Config)
        .unwrap_or_else(|| TransferConfig::default())
}

pub fn set_transfer_config(
    env: &Env,
    admin: &Address,
    config: TransferConfig,
) -> Result<(), OwnershipTransferError> {
    let current_super = get_role_owner(env, &OwnershipRole::SuperAdmin);
    if let Some(owner) = current_super {
        if *admin != owner {
            return Err(OwnershipTransferError::Unauthorized);
        }
        admin.require_auth();
    }

    if config.min_validity_seconds <= config.min_delay_seconds
        || config.max_validity_seconds < config.min_validity_seconds
    {
        return Err(OwnershipTransferError::ConfigOutOfBounds);
    }

    env.storage().instance().set(&DataKey::Config, &config);
    Ok(())
}

pub fn initialize_role_owner(
    env: &Env,
    role: &OwnershipRole,
    initial_owner: &Address,
) {
    let key = DataKey::Owner(role.clone());
    if !env.storage().instance().has(&key) {
        env.storage().instance().set(&key, initial_owner);
    }
}

pub fn get_role_owner(env: &Env, role: &OwnershipRole) -> Option<Address> {
    env.storage().instance().get(&DataKey::Owner(role.clone()))
}

pub fn get_pending_proposal(
    env: &Env,
    role: &OwnershipRole,
) -> Option<OwnershipTransferProposal> {
    env.storage()
        .instance()
        .get(&DataKey::PendingProposal(role.clone()))
}

fn next_transfer_id(env: &Env) -> u64 {
    let id: u64 = env
        .storage()
        .instance()
        .get(&DataKey::NextTransferId)
        .unwrap_or(1);
    env.storage()
        .instance()
        .set(&DataKey::NextTransferId, &(id + 1));
    id
}

// ---------------------------------------------------------------------------
// Core Operations
// ---------------------------------------------------------------------------

/// Proposes an ownership transfer for `role` to `target_owner`.
/// Caller must be the current owner of `role`.
pub fn propose_ownership_transfer(
    env: &Env,
    caller: &Address,
    role: OwnershipRole,
    target_owner: Address,
    validity_seconds: u64,
) -> Result<OwnershipTransferProposal, OwnershipTransferError> {
    let current_owner = get_role_owner(env, &role)
        .ok_or(OwnershipTransferError::Unauthorized)?;

    if *caller != current_owner {
        return Err(OwnershipTransferError::Unauthorized);
    }
    caller.require_auth();

    if target_owner == current_owner {
        return Err(OwnershipTransferError::SelfTransfer);
    }

    let config = get_transfer_config(env);
    if validity_seconds < config.min_validity_seconds
        || validity_seconds > config.max_validity_seconds
    {
        return Err(OwnershipTransferError::InvalidDuration);
    }

    let now = env.ledger().timestamp();

    // Check existing pending proposal
    if let Some(existing) = get_pending_proposal(env, &role) {
        if existing.status == TransferStatus::Pending && now <= existing.expires_at {
            return Err(OwnershipTransferError::TransferAlreadyPending);
        }
    }

    let transfer_id = next_transfer_id(env);
    let effective_after = now + config.min_delay_seconds;
    let expires_at = now + validity_seconds;

    let proposal = OwnershipTransferProposal {
        transfer_id,
        role: role.clone(),
        current_owner: current_owner.clone(),
        target_owner: target_owner.clone(),
        created_at: now,
        effective_after,
        expires_at,
        status: TransferStatus::Pending,
        nonce: 1,
    };

    env.storage()
        .instance()
        .set(&DataKey::PendingProposal(role.clone()), &proposal);

    env.events().publish(
        (symbol_short!("own_mgr"), symbol_short!("prop")),
        (transfer_id, current_owner, target_owner, expires_at),
    );

    Ok(proposal)
}

/// Accepts a pending ownership transfer proposal.
/// Caller must be the designated `target_owner`, timelock must be elapsed, and proposal must not be expired.
pub fn accept_ownership_transfer(
    env: &Env,
    caller: &Address,
    role: OwnershipRole,
    transfer_id: u64,
) -> Result<(), OwnershipTransferError> {
    caller.require_auth();

    let mut proposal = get_pending_proposal(env, &role)
        .ok_or(OwnershipTransferError::NoPendingTransfer)?;

    if proposal.transfer_id != transfer_id {
        return Err(OwnershipTransferError::ProposalIdMismatch);
    }
    if proposal.status != TransferStatus::Pending {
        return Err(OwnershipTransferError::TransferNotPending);
    }
    if *caller != proposal.target_owner {
        return Err(OwnershipTransferError::NotPendingOwner);
    }

    let now = env.ledger().timestamp();
    if now < proposal.effective_after {
        return Err(OwnershipTransferError::TimelockNotElapsed);
    }
    if now > proposal.expires_at {
        proposal.status = TransferStatus::Expired;
        env.storage()
            .instance()
            .set(&DataKey::PendingProposal(role.clone()), &proposal);
        return Err(OwnershipTransferError::TransferExpired);
    }

    // Execute transfer
    proposal.status = TransferStatus::Accepted;
    env.storage()
        .instance()
        .set(&DataKey::PendingProposal(role.clone()), &proposal);
    env.storage()
        .instance()
        .set(&DataKey::Owner(role.clone()), caller);

    env.events().publish(
        (symbol_short!("own_mgr"), symbol_short!("acpt")),
        (transfer_id, proposal.current_owner, caller.clone()),
    );

    Ok(())
}

/// Cancels an active pending ownership transfer.
/// Caller must be the current owner of `role`.
pub fn cancel_ownership_transfer(
    env: &Env,
    caller: &Address,
    role: OwnershipRole,
    transfer_id: u64,
) -> Result<(), OwnershipTransferError> {
    let current_owner = get_role_owner(env, &role)
        .ok_or(OwnershipTransferError::Unauthorized)?;

    if *caller != current_owner {
        return Err(OwnershipTransferError::Unauthorized);
    }
    caller.require_auth();

    let mut proposal = get_pending_proposal(env, &role)
        .ok_or(OwnershipTransferError::NoPendingTransfer)?;

    if proposal.transfer_id != transfer_id {
        return Err(OwnershipTransferError::ProposalIdMismatch);
    }
    if proposal.status != TransferStatus::Pending {
        return Err(OwnershipTransferError::TransferNotPending);
    }

    proposal.status = TransferStatus::Cancelled;
    env.storage()
        .instance()
        .set(&DataKey::PendingProposal(role.clone()), &proposal);

    env.events().publish(
        (symbol_short!("own_mgr"), symbol_short!("canc")),
        (transfer_id, caller.clone(), proposal.target_owner),
    );

    Ok(())
}

/// Rejects an active pending ownership transfer.
/// Caller must be the designated `target_owner`.
pub fn reject_ownership_transfer(
    env: &Env,
    caller: &Address,
    role: OwnershipRole,
    transfer_id: u64,
) -> Result<(), OwnershipTransferError> {
    caller.require_auth();

    let mut proposal = get_pending_proposal(env, &role)
        .ok_or(OwnershipTransferError::NoPendingTransfer)?;

    if proposal.transfer_id != transfer_id {
        return Err(OwnershipTransferError::ProposalIdMismatch);
    }
    if proposal.status != TransferStatus::Pending {
        return Err(OwnershipTransferError::TransferNotPending);
    }
    if *caller != proposal.target_owner {
        return Err(OwnershipTransferError::NotPendingOwner);
    }

    proposal.status = TransferStatus::Rejected;
    env.storage()
        .instance()
        .set(&DataKey::PendingProposal(role.clone()), &proposal);

    env.events().publish(
        (symbol_short!("own_mgr"), symbol_short!("rej")),
        (transfer_id, proposal.current_owner, caller.clone()),
    );

    Ok(())
}

/// Permissionlessly marks an expired transfer as Expired and clears the active slot.
pub fn expire_ownership_transfer(
    env: &Env,
    role: OwnershipRole,
    transfer_id: u64,
) -> Result<(), OwnershipTransferError> {
    let mut proposal = get_pending_proposal(env, &role)
        .ok_or(OwnershipTransferError::NoPendingTransfer)?;

    if proposal.transfer_id != transfer_id {
        return Err(OwnershipTransferError::ProposalIdMismatch);
    }
    if proposal.status != TransferStatus::Pending && proposal.status != TransferStatus::Expired {
        return Err(OwnershipTransferError::TransferNotPending);
    }

    let now = env.ledger().timestamp();
    if now <= proposal.expires_at {
        return Err(OwnershipTransferError::InvalidDuration);
    }

    proposal.status = TransferStatus::Expired;
    env.storage()
        .instance()
        .set(&DataKey::PendingProposal(role.clone()), &proposal);

    env.events().publish(
        (symbol_short!("own_mgr"), symbol_short!("exp")),
        (transfer_id, proposal.current_owner, proposal.target_owner),
    );

    Ok(())
}

/// Queries whether the pending proposal for `role` has expired.
pub fn is_proposal_expired(env: &Env, role: &OwnershipRole) -> Option<bool> {
    get_pending_proposal(env, role).map(|p| env.ledger().timestamp() > p.expires_at)
}

/// Returns seconds remaining until proposal expiry, or 0 if expired.
pub fn time_until_expiry(env: &Env, role: &OwnershipRole) -> Option<u64> {
    get_pending_proposal(env, role).map(|p| p.expires_at.saturating_sub(env.ledger().timestamp()))
}

/// Returns seconds remaining until proposal becomes effective (timelock expires).
pub fn time_until_effective(env: &Env, role: &OwnershipRole) -> Option<u64> {
    get_pending_proposal(env, role).map(|p| p.effective_after.saturating_sub(env.ledger().timestamp()))
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
pub mod tests {
    use super::*;
    use soroban_sdk::{
        contract, contractimpl,
        testutils::{Address as _, Ledger as _},
        Env,
    };

    #[contract]
    pub struct OwnershipTestContract;

    #[contractimpl]
    impl OwnershipTestContract {}

    fn setup_test() -> (Env, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, OwnershipTestContract);
        let owner = Address::generate(&env);
        let target = Address::generate(&env);
        (env, contract_id, owner, target)
    }

    fn init_owner(env: &Env, cid: &Address, role: &OwnershipRole, owner: &Address) {
        env.as_contract(cid, || initialize_role_owner(env, role, owner));
    }

    fn propose(
        env: &Env,
        cid: &Address,
        caller: &Address,
        role: OwnershipRole,
        target: Address,
        v: u64,
    ) -> Result<OwnershipTransferProposal, OwnershipTransferError> {
        env.as_contract(cid, || propose_ownership_transfer(env, caller, role, target, v))
    }

    fn accept(
        env: &Env,
        cid: &Address,
        caller: &Address,
        role: OwnershipRole,
        id: u64,
    ) -> Result<(), OwnershipTransferError> {
        env.as_contract(cid, || accept_ownership_transfer(env, caller, role, id))
    }

    fn cancel(
        env: &Env,
        cid: &Address,
        caller: &Address,
        role: OwnershipRole,
        id: u64,
    ) -> Result<(), OwnershipTransferError> {
        env.as_contract(cid, || cancel_ownership_transfer(env, caller, role, id))
    }

    fn reject(
        env: &Env,
        cid: &Address,
        caller: &Address,
        role: OwnershipRole,
        id: u64,
    ) -> Result<(), OwnershipTransferError> {
        env.as_contract(cid, || reject_ownership_transfer(env, caller, role, id))
    }

    fn expire(
        env: &Env,
        cid: &Address,
        role: OwnershipRole,
        id: u64,
    ) -> Result<(), OwnershipTransferError> {
        env.as_contract(cid, || expire_ownership_transfer(env, role, id))
    }

    fn get_owner(env: &Env, cid: &Address, role: &OwnershipRole) -> Option<Address> {
        env.as_contract(cid, || get_role_owner(env, role))
    }

    fn get_pending(env: &Env, cid: &Address, role: &OwnershipRole) -> Option<OwnershipTransferProposal> {
        env.as_contract(cid, || get_pending_proposal(env, role))
    }

    fn is_expired(env: &Env, cid: &Address, role: &OwnershipRole) -> Option<bool> {
        env.as_contract(cid, || is_proposal_expired(env, role))
    }

    fn time_left(env: &Env, cid: &Address, role: &OwnershipRole) -> Option<u64> {
        env.as_contract(cid, || time_until_expiry(env, role))
    }

    #[test]
    fn test_normal_ownership_transfer_with_timelock_and_acceptance() {
        let (env, contract_id, owner, target) = setup_test();
        env.ledger().set_timestamp(1000);
        let role = OwnershipRole::SuperAdmin;

        init_owner(&env, &contract_id, &role, &owner);
        assert_eq!(get_owner(&env, &contract_id, &role), Some(owner.clone()));

        // Propose transfer with 1000s validity (timelock default = 300s)
        let proposal = propose(&env, &contract_id, &owner, role.clone(), target.clone(), 1000)
            .expect("proposal should succeed");

        assert_eq!(proposal.transfer_id, 1);
        assert_eq!(proposal.status, TransferStatus::Pending);
        assert_eq!(proposal.effective_after, 1300);
        assert_eq!(proposal.expires_at, 2000);

        // Attempting to accept before timelock elapses fails
        env.ledger().set_timestamp(1200);
        let res = accept(&env, &contract_id, &target, role.clone(), 1);
        assert_eq!(res, Err(OwnershipTransferError::TimelockNotElapsed));
        assert_eq!(get_owner(&env, &contract_id, &role), Some(owner.clone()));

        // Fast forward past timelock (e.g. at 1400s)
        env.ledger().set_timestamp(1400);
        let res2 = accept(&env, &contract_id, &target, role.clone(), 1);
        assert_eq!(res2, Ok(()));

        // Owner is now updated to target
        assert_eq!(get_owner(&env, &contract_id, &role), Some(target.clone()));
        let pending = get_pending(&env, &contract_id, &role).unwrap();
        assert_eq!(pending.status, TransferStatus::Accepted);
    }

    #[test]
    fn test_failure_expired_proposal_cannot_be_accepted() {
        let (env, contract_id, owner, target) = setup_test();
        env.ledger().set_timestamp(1000);
        let role = OwnershipRole::TreasuryAdmin;

        init_owner(&env, &contract_id, &role, &owner);
        propose(&env, &contract_id, &owner, role.clone(), target.clone(), 800)
            .expect("proposal ok");

        // Advance beyond expiry (expires_at = 1800)
        env.ledger().set_timestamp(1801);
        assert_eq!(is_expired(&env, &contract_id, &role), Some(true));
        assert_eq!(time_left(&env, &contract_id, &role), Some(0));

        let res = accept(&env, &contract_id, &target, role.clone(), 1);
        assert_eq!(res, Err(OwnershipTransferError::TransferExpired));
        assert_eq!(get_owner(&env, &contract_id, &role), Some(owner.clone()));

        // Permissionless cleanup
        let exp_res = expire(&env, &contract_id, role.clone(), 1);
        assert_eq!(exp_res, Ok(()));
        let p = get_pending(&env, &contract_id, &role).unwrap();
        assert_eq!(p.status, TransferStatus::Expired);
    }

    #[test]
    fn test_cancellation_and_rejection_paths() {
        let (env, contract_id, owner, target) = setup_test();
        env.ledger().set_timestamp(1000);
        let role = OwnershipRole::GovernanceAdmin;

        init_owner(&env, &contract_id, &role, &owner);
        propose(&env, &contract_id, &owner, role.clone(), target.clone(), 1000).unwrap();

        // Owner cancels proposal
        cancel(&env, &contract_id, &owner, role.clone(), 1).unwrap();
        let p = get_pending(&env, &contract_id, &role).unwrap();
        assert_eq!(p.status, TransferStatus::Cancelled);

        // Target cannot accept cancelled proposal
        let acc_res = accept(&env, &contract_id, &target, role.clone(), 1);
        assert_eq!(acc_res, Err(OwnershipTransferError::TransferNotPending));

        // Owner can now propose again (retry path)
        let new_prop = propose(&env, &contract_id, &owner, role.clone(), target.clone(), 1000).unwrap();
        assert_eq!(new_prop.transfer_id, 2);

        // Target explicitly rejects proposal
        reject(&env, &contract_id, &target, role.clone(), 2).unwrap();
        let p2 = get_pending(&env, &contract_id, &role).unwrap();
        assert_eq!(p2.status, TransferStatus::Rejected);
    }

    #[test]
    fn test_authorization_checks_reject_unauthorized_callers() {
        let (env, contract_id, owner, target) = setup_test();
        let stranger = Address::generate(&env);
        env.ledger().set_timestamp(1000);
        let role = OwnershipRole::EmergencyAdmin;

        init_owner(&env, &contract_id, &role, &owner);

        // Stranger cannot propose transfer
        let res = propose(&env, &contract_id, &stranger, role.clone(), target.clone(), 1000);
        assert_eq!(res, Err(OwnershipTransferError::Unauthorized));

        // Owner proposes valid transfer
        propose(&env, &contract_id, &owner, role.clone(), target.clone(), 1000).unwrap();

        // Stranger cannot cancel transfer
        let cancel_res = cancel(&env, &contract_id, &stranger, role.clone(), 1);
        assert_eq!(cancel_res, Err(OwnershipTransferError::Unauthorized));

        // Stranger cannot reject transfer
        let rej_res = reject(&env, &contract_id, &stranger, role.clone(), 1);
        assert_eq!(rej_res, Err(OwnershipTransferError::NotPendingOwner));

        // Self-transfer on fresh role is rejected
        let role2 = OwnershipRole::Custom(symbol_short!("auditor"));
        init_owner(&env, &contract_id, &role2, &owner);
        let self_res = propose(&env, &contract_id, &owner, role2, owner.clone(), 1000);
        assert_eq!(self_res, Err(OwnershipTransferError::SelfTransfer));
    }

    #[test]
    fn test_config_bounds_and_duration_validation() {
        let (env, contract_id, owner, target) = setup_test();
        env.ledger().set_timestamp(1000);
        let role = OwnershipRole::Custom(symbol_short!("fee_mgr"));

        init_owner(&env, &contract_id, &role, &owner);

        // Validity less than minimum (default 600s)
        let res = propose(&env, &contract_id, &owner, role.clone(), target.clone(), 500);
        assert_eq!(res, Err(OwnershipTransferError::InvalidDuration));

        // Validity greater than maximum (default 604,800s)
        let res2 = propose(&env, &contract_id, &owner, role.clone(), target.clone(), 1_000_000);
        assert_eq!(res2, Err(OwnershipTransferError::InvalidDuration));
    }
}

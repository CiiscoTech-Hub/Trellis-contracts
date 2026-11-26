//! # Governance Proposal Timelock Cancellation & Veto Quorum (Issue #521)
//!
//! Multi-sig governance timelock cancellation and collective veto quorum
//! protection for the Trellis Soroban suite.
//!
//! ## Overview
//!
//! Timelocks protect protocol users by introducing an intentional execution delay
//! (`execution_delay_secs`) between when a proposal passes voting and when its actions
//! actually land on-chain. During this critical timelock window:
//!
//! 1. **Timelock Cancellation**: The original proposer or super-admin can cancel the
//!    proposal if an error, race condition, or unintended parameter was discovered.
//! 2. **Collective Veto Quorum**: If a proposal is suspected to be compromised, malicious,
//!    or economically dangerous, active multi-sig admins can cast individual **Veto** votes.
//!    Once the number of distinct admin vetoes meets or exceeds the configured `veto_quorum`,
//!    the proposal is immediately and permanently vetoed, cancelling its scheduled execution.
//!
//! ## Complexity
//! - Time Complexity: $O(N)$ where $N$ is the number of active admins casting vetoes ($N \le 32$).
//! - Space Complexity: $O(N)$ bounded vetoer list per proposal.

#![allow(clippy::too_many_arguments)]

use soroban_sdk::{contracterror, contracttype, Address, Env, Vec};

pub const DEFAULT_EXECUTION_DELAY_SECS: u64 = 86_400; // 24 hours
pub const DEFAULT_GRACE_PERIOD_SECS: u64 = 172_800; // 48 hours
pub const DEFAULT_VETO_QUORUM: u32 = 2; // Default 2 admins required to veto

// ===========================================================================
// Error taxonomy (650–659 in Governance domain)
// ===========================================================================

#[contracterror(export = false)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum GovernanceTimelockError {
    /// Caller is not authorized (must be admin, proposer, or super-admin).
    Unauthorized = 650,
    /// Proposal is not currently queued in the timelock.
    ProposalNotQueued = 651,
    /// Timelock execution delay has not yet passed.
    TimelockTooEarly = 652,
    /// Timelock execution grace period has expired; proposal is stale.
    TimelockExpired = 653,
    /// The admin has already cast a veto on this proposal.
    AlreadyVetoed = 654,
    /// Proposal has already been executed.
    ProposalAlreadyExecuted = 655,
    /// Proposal has already been cancelled.
    ProposalAlreadyCancelled = 656,
    /// Invalid veto quorum supplied (must be >= 1).
    InvalidVetoQuorum = 657,
    /// Proposal was vetoed by governance veto quorum and cannot execute.
    ProposalVetoed = 658,
    /// Math overflow in timestamp calculation.
    MathOverflow = 659,
}

// ===========================================================================
// Data Structures
// ===========================================================================

/// Lifecycle status of a proposal in the timelock.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum TimelockLifecycleStatus {
    Queued = 0,
    Executed = 1,
    Cancelled = 2,
    Vetoed = 3,
    Expired = 4,
}

/// Timelock tracking entry for a queued proposal.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimelockEntry {
    pub proposal_id: u64,
    pub queued_at: u64,
    pub eta: u64,
    pub expires_at: u64,
    pub status: TimelockLifecycleStatus,
}

/// Veto accounting record for a proposal.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VetoRecord {
    pub proposal_id: u64,
    pub veto_count: u32,
    pub veto_quorum: u32,
    pub is_vetoed: bool,
    pub vetoed_at: u64,
    pub vetoers: Vec<Address>,
}

impl VetoRecord {
    pub fn new(env: &Env, proposal_id: u64, veto_quorum: u32) -> Self {
        Self {
            proposal_id,
            veto_count: 0,
            veto_quorum,
            is_vetoed: false,
            vetoed_at: 0,
            vetoers: Vec::new(env),
        }
    }
}

/// Result of casting a veto vote.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VetoOutcome {
    /// Veto recorded; quorum not yet reached.
    Recorded { current_vetoes: u32, required: u32 },
    /// Veto quorum reached; proposal has been cancelled via veto.
    VetoQuorumReached { total_vetoes: u32 },
}

// ===========================================================================
// Core Logic
// ===========================================================================

/// Queues an approved proposal into the timelock.
pub fn queue_proposal_timelock(
    proposal_id: u64,
    now: u64,
    delay_secs: u64,
    grace_secs: u64,
) -> Result<TimelockEntry, GovernanceTimelockError> {
    let eta = now
        .checked_add(delay_secs)
        .ok_or(GovernanceTimelockError::MathOverflow)?;

    let expires_at = eta
        .checked_add(grace_secs)
        .ok_or(GovernanceTimelockError::MathOverflow)?;

    Ok(TimelockEntry {
        proposal_id,
        queued_at: now,
        eta,
        expires_at,
        status: TimelockLifecycleStatus::Queued,
    })
}

/// Validates whether a queued proposal is ready to execute.
pub fn validate_timelock_execution(
    entry: &mut TimelockEntry,
    now: u64,
) -> Result<(), GovernanceTimelockError> {
    match entry.status {
        TimelockLifecycleStatus::Executed => {
            return Err(GovernanceTimelockError::ProposalAlreadyExecuted);
        }
        TimelockLifecycleStatus::Cancelled => {
            return Err(GovernanceTimelockError::ProposalAlreadyCancelled);
        }
        TimelockLifecycleStatus::Vetoed => {
            return Err(GovernanceTimelockError::ProposalVetoed);
        }
        TimelockLifecycleStatus::Expired => {
            return Err(GovernanceTimelockError::TimelockExpired);
        }
        TimelockLifecycleStatus::Queued => {}
    }

    if now < entry.eta {
        return Err(GovernanceTimelockError::TimelockTooEarly);
    }
    if now > entry.expires_at {
        entry.status = TimelockLifecycleStatus::Expired;
        return Err(GovernanceTimelockError::TimelockExpired);
    }

    Ok(())
}

/// Allows the original proposer or super-admin to cancel a queued proposal during timelock.
pub fn cancel_queued_timelock(
    entry: &mut TimelockEntry,
    caller: &Address,
    proposer: &Address,
    super_admin: &Address,
) -> Result<(), GovernanceTimelockError> {
    if caller != proposer && caller != super_admin {
        return Err(GovernanceTimelockError::Unauthorized);
    }

    if entry.status != TimelockLifecycleStatus::Queued {
        return Err(GovernanceTimelockError::ProposalAlreadyCancelled);
    }

    entry.status = TimelockLifecycleStatus::Cancelled;
    Ok(())
}

/// Casts an administrative veto vote against a queued proposal.
///
/// If `veto_count >= veto_quorum`, transitions the proposal to `Vetoed`.
pub fn cast_proposal_veto(
    veto_record: &mut VetoRecord,
    timelock_entry: &mut TimelockEntry,
    admin_caller: Address,
    is_active_admin: bool,
    now: u64,
) -> Result<VetoOutcome, GovernanceTimelockError> {
    if !is_active_admin {
        return Err(GovernanceTimelockError::Unauthorized);
    }

    if timelock_entry.status != TimelockLifecycleStatus::Queued {
        if timelock_entry.status == TimelockLifecycleStatus::Vetoed {
            return Err(GovernanceTimelockError::ProposalVetoed);
        }
        if timelock_entry.status == TimelockLifecycleStatus::Executed {
            return Err(GovernanceTimelockError::ProposalAlreadyExecuted);
        }
        return Err(GovernanceTimelockError::ProposalAlreadyCancelled);
    }

    // Check for duplicate veto
    for existing in veto_record.vetoers.iter() {
        if existing == admin_caller {
            return Err(GovernanceTimelockError::AlreadyVetoed);
        }
    }

    veto_record.vetoers.push_back(admin_caller);
    veto_record.veto_count = veto_record
        .veto_count
        .checked_add(1)
        .ok_or(GovernanceTimelockError::MathOverflow)?;

    if veto_record.veto_count >= veto_record.veto_quorum {
        veto_record.is_vetoed = true;
        veto_record.vetoed_at = now;
        timelock_entry.status = TimelockLifecycleStatus::Vetoed;

        Ok(VetoOutcome::VetoQuorumReached {
            total_vetoes: veto_record.veto_count,
        })
    } else {
        Ok(VetoOutcome::Recorded {
            current_vetoes: veto_record.veto_count,
            required: veto_record.veto_quorum,
        })
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::Env;

    #[test]
    fn test_normal_timelock_flow() {
        let mut entry = queue_proposal_timelock(1, 1000, 3600, 7200).unwrap();
        assert_eq!(entry.eta, 4600);
        assert_eq!(entry.expires_at, 11800);

        // Before ETA: too early
        assert_eq!(
            validate_timelock_execution(&mut entry, 3000).unwrap_err(),
            GovernanceTimelockError::TimelockTooEarly
        );

        // At or after ETA: valid
        assert!(validate_timelock_execution(&mut entry, 4600).is_ok());
        assert!(validate_timelock_execution(&mut entry, 6000).is_ok());

        // After expires_at: expired
        assert_eq!(
            validate_timelock_execution(&mut entry, 12000).unwrap_err(),
            GovernanceTimelockError::TimelockExpired
        );
        assert_eq!(entry.status, TimelockLifecycleStatus::Expired);
    }

    #[test]
    fn test_timelock_cancellation_by_proposer_and_superadmin() {
        let env = Env::default();
        let proposer = Address::generate(&env);
        let super_admin = Address::generate(&env);
        let random_user = Address::generate(&env);

        let mut entry = queue_proposal_timelock(2, 1000, 3600, 7200).unwrap();

        // Random user cannot cancel
        assert_eq!(
            cancel_queued_timelock(&mut entry, &random_user, &proposer, &super_admin).unwrap_err(),
            GovernanceTimelockError::Unauthorized
        );

        // Proposer can cancel
        assert!(cancel_queued_timelock(&mut entry, &proposer, &proposer, &super_admin).is_ok());
        assert_eq!(entry.status, TimelockLifecycleStatus::Cancelled);

        // Attempting to execute cancelled proposal fails
        assert_eq!(
            validate_timelock_execution(&mut entry, 5000).unwrap_err(),
            GovernanceTimelockError::ProposalAlreadyCancelled
        );
    }

    #[test]
    fn test_veto_quorum_collective_action() {
        let env = Env::default();
        let admin1 = Address::generate(&env);
        let admin2 = Address::generate(&env);
        let non_admin = Address::generate(&env);

        let mut entry = queue_proposal_timelock(3, 1000, 3600, 7200).unwrap();
        let mut veto_rec = VetoRecord::new(&env, 3, 2); // Quorum = 2

        // Non-admin veto rejected
        assert_eq!(
            cast_proposal_veto(&mut veto_rec, &mut entry, non_admin, false, 1200).unwrap_err(),
            GovernanceTimelockError::Unauthorized
        );

        // Admin 1 casts veto
        let outcome1 = cast_proposal_veto(&mut veto_rec, &mut entry, admin1.clone(), true, 1300).unwrap();
        assert_eq!(
            outcome1,
            VetoOutcome::Recorded {
                current_vetoes: 1,
                required: 2
            }
        );
        assert_eq!(entry.status, TimelockLifecycleStatus::Queued);

        // Duplicate veto by Admin 1 rejected
        assert_eq!(
            cast_proposal_veto(&mut veto_rec, &mut entry, admin1, true, 1350).unwrap_err(),
            GovernanceTimelockError::AlreadyVetoed
        );

        // Admin 2 casts veto -> Quorum reached!
        let outcome2 = cast_proposal_veto(&mut veto_rec, &mut entry, admin2, true, 1400).unwrap();
        assert_eq!(
            outcome2,
            VetoOutcome::VetoQuorumReached { total_vetoes: 2 }
        );
        assert_eq!(entry.status, TimelockLifecycleStatus::Vetoed);
        assert!(veto_rec.is_vetoed);

        // Execution of vetoed proposal strictly blocked even after ETA
        assert_eq!(
            validate_timelock_execution(&mut entry, 5000).unwrap_err(),
            GovernanceTimelockError::ProposalVetoed
        );
    }
}

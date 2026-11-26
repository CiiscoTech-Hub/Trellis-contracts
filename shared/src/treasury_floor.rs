//! # Multi-Asset Treasury Reserve Floor and Auto-Pause Guard (Issue #520)
//!
//! Production-grade reserve floor enforcement and auto-pause guardrails for
//! multi-asset treasuries on Soroban.
//!
//! ## Overview
//!
//! To protect protocol reserves and prevent liquidity exhaustion or malicious drain,
//! each token/asset in the treasury can be protected by:
//! 1. **Multi-Asset Reserve Floor (`min_reserve_floor`)**: A hard minimum balance
//!    that cannot be withdrawn by ordinary operations or reward distributions.
//! 2. **Auto-Pause Guard (`ReserveAutoPauseState`)**: If an outflow or unexpected
//!    accounting variance causes a token's reserve to breach the floor, the guard
//!    automatically trips into a paused state (`is_paused = true`), halting all further
//!    outflows of that asset.
//! 3. **Replenishment & Unpause Governance**: The auto-pause state can only be unpaused
//!    once the reserve is replenished back above the floor level by authorized admins.
//!
//! ## Complexity
//! - Time Complexity: $O(1)$ arithmetic check per outflow.
//! - Space Complexity: $O(1)$ persistent record per token.

#![allow(clippy::too_many_arguments)]

use soroban_sdk::{contracterror, contracttype, symbol_short, Address, Symbol};

// ===========================================================================
// Error taxonomy (143–151 in Treasury domain)
// ===========================================================================

#[contracterror(export = false)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum TreasuryFloorError {
    /// Outflow would cause reserve balance to drop below configured floor.
    ReserveFloorBreached = 143,
    /// The reserve is currently auto-paused due to floor breach; outflows are locked.
    ReserveAutoPaused = 144,
    /// Insufficient surplus available above reserve floor for requested operation.
    InsufficientSurplus = 145,
    /// Invalid reserve floor amount (e.g. negative floor).
    InvalidFloorAmount = 146,
    /// Caller is not authorized to configure floors or reset auto-pause guard.
    Unauthorized = 147,
    /// Cannot unpause while reserve balance remains strictly below floor level.
    ReserveBalanceBelowFloor = 148,
    /// The guard is not currently in a paused state.
    GuardNotPaused = 149,
    /// Arithmetic overflow in balance, floor, or surplus calculations.
    MathOverflow = 150,
    /// Invalid outflow amount (zero or negative).
    InvalidAmount = 151,
}

// ===========================================================================
// Data Structures
// ===========================================================================

/// Configuration for a specific token's reserve floor.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReserveFloorConfig {
    pub token: Address,
    /// Minimum reserve balance required to remain untouched.
    pub min_reserve_floor: i128,
    /// Threshold at or below which auto-pause immediately activates.
    pub emergency_pause_threshold: i128,
    /// Whether reserve floor enforcement is active.
    pub enabled: bool,
}

/// Dynamic auto-pause state for a token's reserve.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReserveAutoPauseState {
    pub is_paused: bool,
    pub tripped_at: u64,
    pub tripped_by: Address,
    pub tripped_amount: i128,
    pub current_balance: i128,
    pub floor_level: i128,
    pub trip_reason: Symbol,
}

impl ReserveAutoPauseState {
    pub fn default_active(token_admin: Address) -> Self {
        Self {
            is_paused: false,
            tripped_at: 0,
            tripped_by: token_admin,
            tripped_amount: 0,
            current_balance: 0,
            floor_level: 0,
            trip_reason: symbol_short!("active"),
        }
    }
}

// ===========================================================================
// Core Logic
// ===========================================================================

/// Calculates available surplus of a token reserve above its floor.
pub fn get_reserve_surplus(current_balance: i128, floor: i128) -> i128 {
    current_balance.saturating_sub(floor).max(0)
}

/// Evaluates a candidate outflow against reserve floor and auto-pause status.
///
/// If post-balance drops below floor, trips auto-pause and returns `Err(ReserveFloorBreached)`.
/// If already auto-paused, returns `Err(ReserveAutoPaused)`.
pub fn evaluate_reserve_outflow(
    current_balance: i128,
    outflow_amount: i128,
    config: &ReserveFloorConfig,
    state: &mut ReserveAutoPauseState,
    actor: &Address,
    now: u64,
) -> Result<i128, TreasuryFloorError> {
    if outflow_amount <= 0 {
        return Err(TreasuryFloorError::InvalidAmount);
    }

    // 1. Guard check: if already paused, reject all outflows immediately
    if state.is_paused {
        return Err(TreasuryFloorError::ReserveAutoPaused);
    }

    // If floor enforcement is disabled for this token, proceed with basic balance check
    if !config.enabled {
        let post_balance = current_balance
            .checked_sub(outflow_amount)
            .ok_or(TreasuryFloorError::MathOverflow)?;
        if post_balance < 0 {
            return Err(TreasuryFloorError::InsufficientSurplus);
        }
        return Ok(post_balance);
    }

    let post_balance = current_balance
        .checked_sub(outflow_amount)
        .ok_or(TreasuryFloorError::MathOverflow)?;

    // 2. Check floor breach condition
    if post_balance < config.min_reserve_floor {
        // Auto-pause guard trips!
        state.is_paused = true;
        state.tripped_at = now;
        state.tripped_by = actor.clone();
        state.tripped_amount = outflow_amount;
        state.current_balance = current_balance;
        state.floor_level = config.min_reserve_floor;
        state.trip_reason = symbol_short!("flr_brch");

        return Err(TreasuryFloorError::ReserveFloorBreached);
    }

    // 3. Check emergency threshold condition
    if post_balance <= config.emergency_pause_threshold {
        state.is_paused = true;
        state.tripped_at = now;
        state.tripped_by = actor.clone();
        state.tripped_amount = outflow_amount;
        state.current_balance = post_balance;
        state.floor_level = config.emergency_pause_threshold;
        state.trip_reason = symbol_short!("emg_trig");
    }

    Ok(post_balance)
}

/// Allows admin to configure or update the reserve floor for a token.
pub fn configure_reserve_floor(
    config: &mut ReserveFloorConfig,
    min_floor: i128,
    emergency_threshold: i128,
    enabled: bool,
) -> Result<(), TreasuryFloorError> {
    if min_floor < 0 || emergency_threshold < 0 {
        return Err(TreasuryFloorError::InvalidFloorAmount);
    }
    if emergency_threshold > min_floor {
        return Err(TreasuryFloorError::InvalidFloorAmount);
    }

    config.min_reserve_floor = min_floor;
    config.emergency_pause_threshold = emergency_threshold;
    config.enabled = enabled;

    Ok(())
}

/// Unpauses the auto-pause guard after verifying that reserve balance is replenished.
pub fn unpause_reserve_guard(
    state: &mut ReserveAutoPauseState,
    current_balance: i128,
    floor: i128,
    force_override: bool,
) -> Result<(), TreasuryFloorError> {
    if !state.is_paused {
        return Err(TreasuryFloorError::GuardNotPaused);
    }

    // Invariant: cannot unpause unless balance is at or above floor level,
    // or governance explicitly passes force_override.
    if !force_override && current_balance < floor {
        return Err(TreasuryFloorError::ReserveBalanceBelowFloor);
    }

    state.is_paused = false;
    state.tripped_amount = 0;
    state.trip_reason = symbol_short!("unpaused");

    Ok(())
}

/// Allows admin to manually pause a token's reserve in an incident.
pub fn manual_pause_reserve_guard(
    state: &mut ReserveAutoPauseState,
    actor: &Address,
    current_balance: i128,
    floor: i128,
    now: u64,
    reason: Symbol,
) -> Result<(), TreasuryFloorError> {
    state.is_paused = true;
    state.tripped_at = now;
    state.tripped_by = actor.clone();
    state.current_balance = current_balance;
    state.floor_level = floor;
    state.trip_reason = reason;

    Ok(())
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
    fn test_normal_outflow_above_floor() {
        let env = Env::default();
        let token = Address::generate(&env);
        let actor = Address::generate(&env);

        let config = ReserveFloorConfig {
            token: token.clone(),
            min_reserve_floor: 10_000,
            emergency_pause_threshold: 8_000,
            enabled: true,
        };
        let mut state = ReserveAutoPauseState::default_active(actor.clone());

        // Initial balance 50,000, withdraw 20,000 -> post 30,000 >= 10,000 floor
        let post = evaluate_reserve_outflow(50_000, 20_000, &config, &mut state, &actor, 1000).unwrap();
        assert_eq!(post, 30_000);
        assert!(!state.is_paused);

        // Surplus is 30,000 - 10,000 = 20,000
        assert_eq!(get_reserve_surplus(post, config.min_reserve_floor), 20_000);
    }

    #[test]
    fn test_floor_breach_auto_pauses_guard() {
        let env = Env::default();
        let token = Address::generate(&env);
        let actor = Address::generate(&env);

        let config = ReserveFloorConfig {
            token: token.clone(),
            min_reserve_floor: 10_000,
            emergency_pause_threshold: 5_000,
            enabled: true,
        };
        let mut state = ReserveAutoPauseState::default_active(actor.clone());

        // Balance 15,000, withdraw 8,000 -> post 7,000 < 10,000 floor -> trips auto-pause!
        let err = evaluate_reserve_outflow(15_000, 8_000, &config, &mut state, &actor, 1200).unwrap_err();
        assert_eq!(err, TreasuryFloorError::ReserveFloorBreached);
        assert!(state.is_paused);
        assert_eq!(state.tripped_amount, 8_000);
        assert_eq!(state.floor_level, 10_000);

        // Subsequent outflow immediately blocked by auto-pause
        let err2 = evaluate_reserve_outflow(15_000, 100, &config, &mut state, &actor, 1205).unwrap_err();
        assert_eq!(err2, TreasuryFloorError::ReserveAutoPaused);
    }

    #[test]
    fn test_replenishment_and_unpause_lifecycle() {
        let env = Env::default();
        let token = Address::generate(&env);
        let actor = Address::generate(&env);

        let mut config = ReserveFloorConfig {
            token: token.clone(),
            min_reserve_floor: 10_000,
            emergency_pause_threshold: 5_000,
            enabled: true,
        };
        let mut state = ReserveAutoPauseState::default_active(actor.clone());

        // Trip pause
        let _ = evaluate_reserve_outflow(12_000, 5_000, &config, &mut state, &actor, 1000);
        assert!(state.is_paused);

        // Attempting to unpause while balance remains below floor (e.g. 7,000 < 10,000) fails!
        let unpause_err = unpause_reserve_guard(&mut state, 7_000, config.min_reserve_floor, false).unwrap_err();
        assert_eq!(unpause_err, TreasuryFloorError::ReserveBalanceBelowFloor);
        assert!(state.is_paused);

        // Replenish deposit: balance increases to 25,000 >= 10,000 floor -> unpause succeeds!
        assert!(unpause_reserve_guard(&mut state, 25_000, config.min_reserve_floor, false).is_ok());
        assert!(!state.is_paused);

        // Outflows resume normally
        let post = evaluate_reserve_outflow(25_000, 5_000, &config, &mut state, &actor, 1100).unwrap();
        assert_eq!(post, 20_000);
    }

    #[test]
    fn test_manual_pause_and_config_validation() {
        let env = Env::default();
        let token = Address::generate(&env);
        let actor = Address::generate(&env);

        let mut config = ReserveFloorConfig {
            token: token.clone(),
            min_reserve_floor: 10_000,
            emergency_pause_threshold: 5_000,
            enabled: true,
        };
        let mut state = ReserveAutoPauseState::default_active(actor.clone());

        // Negative floor is rejected
        assert_eq!(
            configure_reserve_floor(&mut config, -100, 0, true).unwrap_err(),
            TreasuryFloorError::InvalidFloorAmount
        );
        // Emergency threshold > min floor rejected
        assert_eq!(
            configure_reserve_floor(&mut config, 5_000, 10_000, true).unwrap_err(),
            TreasuryFloorError::InvalidFloorAmount
        );

        // Manual pause by Admin
        manual_pause_reserve_guard(&mut state, &actor, 30_000, 10_000, 2000, symbol_short!("incident")).unwrap();
        assert!(state.is_paused);
        assert_eq!(state.trip_reason, symbol_short!("incident"));
    }
}

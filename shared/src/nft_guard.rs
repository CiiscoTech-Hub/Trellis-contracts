//! # NFT Collection Floor Price Guard & Wash-Trade Filter (Issue #543)
//!
//! Production-grade floor price protection and wash-trade detection for NFT
//! marketplaces on Soroban.
//!
//! ## Architecture
//!
//! | Component | Detail |
//! |-----------|--------|
//! | **Floor Price Guard** | Enforces minimum collection floor prices, sliding TWAP tracking, and bounded downward deviation caps (`max_floor_drop_bps`). |
//! | **Wash-Trade Filter** | Detects self-dealing (`buyer == seller`), circular recycling (`A -> B -> A`), and minimum holding period violations within bounded history. |
//! | **Bounded Complexity**| Time complexity: $O(1)$ floor price check, $O(K)$ wash-trade cycle check where $K \le 8$. Space complexity: $O(1)$ auxiliary. |
//!
//! ## Security & Threat Model
//!
//! - **Flash Dumps**: Attackers cannot list or execute trades drastically below prevailing market floor to trigger cascading liquidations.
//! - **Wash Volume Inflation**: Colluding or self-dealing addresses cannot flip tokens back and forth in rapid succession to game trading rewards.

#![allow(clippy::too_many_arguments)]

use soroban_sdk::{contracterror, contracttype, Address, Env, Vec};

// ===========================================================================
// Error Codes & Types
// ===========================================================================

#[contracterror(export = false)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum MarketGuardError {
    /// Listing or trade price is below the hard collection minimum floor.
    FloorPriceBelowMinimum = 2100,
    /// Price drop exceeds the maximum permitted basis-point deviation.
    FloorPriceDropExceeded = 2101,
    /// Buyer and seller are identical addresses (direct self-dealing).
    WashTradeSelfDealing = 2102,
    /// Token was previously owned by the buyer within the active cooldown window.
    WashTradeCircularCycle = 2103,
    /// Seller has not held the token for the required minimum holding period.
    WashTradeHoldingPeriodActive = 2104,
    /// Caller is not authorized to update collection guard configuration.
    Unauthorized = 2105,
    /// Invalid configuration parameters (e.g., basis points > 10,000 or zero ceiling).
    InvalidGuardConfig = 2106,
    /// Guard is temporarily paused or disabled.
    GuardDisabled = 2107,
}

// ===========================================================================
// Floor Price Guard Data Structures
// ===========================================================================

/// Configuration for a collection's floor price guard.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FloorPriceGuardConfig {
    /// Hard minimum price below which no listing or sale is permitted.
    pub min_floor_price: i128,
    /// Maximum permitted downward price drop in basis points (10,000 = 100%).
    /// E.g. 1,500 bps = max 15% drop per transaction.
    pub max_floor_drop_bps: u32,
    /// Sliding window length in ledgers for TWAP smoothing.
    pub twap_window_ledgers: u32,
    /// Whether the floor guard is actively enforced.
    pub guard_enabled: bool,
}

/// Dynamic state tracking the current floor price of an NFT collection.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FloorPriceState {
    /// Lowest currently active listing or verified sale price.
    pub current_floor: i128,
    /// Time-weighted or sample-weighted average floor price.
    pub twap_floor: i128,
    /// Ledger sequence when the floor price was last updated.
    pub last_updated_ledger: u32,
    /// Number of verified trades evaluated in the current window.
    pub trade_count: u32,
}

// ===========================================================================
// Wash-Trade Filter Data Structures
// ===========================================================================

/// Maximum number of historical previous owners tracked per token.
pub const MAX_CYCLE_HISTORY_DEPTH: u32 = 8;

/// Configuration for the wash-trade detection filter.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WashTradeConfig {
    /// Minimum number of ledgers an account must hold an NFT before selling back to a prior owner.
    pub min_holding_period_ledgers: u32,
    /// Depth of previous owners checked for circular trading cycles (capped at 8).
    pub max_cycle_depth: u32,
    /// Whether direct self-dealing (buyer == seller) is strictly blocked.
    pub block_self_dealing: bool,
    /// Whether the wash trade filter is actively enforced.
    pub filter_enabled: bool,
}

/// Token ownership history used to detect circular wash-trading loops.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenOwnershipHistory {
    /// Token identifier.
    pub token_id: u32,
    /// Current verified owner of the NFT.
    pub current_owner: Address,
    /// Ledger sequence when the current owner acquired the NFT.
    pub acquired_ledger: u32,
    /// Chronological list of previous owners (oldest to newest, bounded to MAX_CYCLE_HISTORY_DEPTH).
    pub previous_owners: Vec<Address>,
}

/// Wash trade inspection verdict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WashTradeVerdict {
    /// Clean trade; no wash trading detected.
    Passed,
    /// Direct self-dealing detected (buyer == seller).
    SelfDealingBlocked,
    /// Circular ownership loop detected within the holding cooldown window.
    CircularCycleBlocked { cycle_depth: u32, cooldown_remaining: u32 },
    /// Minimum holding period not yet elapsed for the current seller.
    HoldingPeriodViolation { elapsed_ledgers: u32, required_ledgers: u32 },
}

// ===========================================================================
// Floor Price Guard Core Logic
// ===========================================================================

/// Validates whether a proposed listing or sale price satisfies the collection's floor price guard.
///
/// # Invariants
/// - Price must be strictly positive and >= `config.min_floor_price`.
/// - If current floor > 0, price drop cannot exceed `config.max_floor_drop_bps`.
/// - Time complexity: $O(1)$. Space complexity: $O(1)$.
pub fn verify_floor_price(
    config: &FloorPriceGuardConfig,
    state: &FloorPriceState,
    proposed_price: i128,
    current_ledger: u32,
) -> Result<FloorPriceState, MarketGuardError> {
    if !config.guard_enabled {
        let mut updated = state.clone();
        updated.current_floor = proposed_price;
        updated.last_updated_ledger = current_ledger;
        return Ok(updated);
    }

    if proposed_price <= 0 || proposed_price < config.min_floor_price {
        return Err(MarketGuardError::FloorPriceBelowMinimum);
    }

    if config.max_floor_drop_bps > 10_000 {
        return Err(MarketGuardError::InvalidGuardConfig);
    }

    let mut next_state = state.clone();

    // If a floor price is already established, check deviation limit
    if state.current_floor > 0 && proposed_price < state.current_floor {
        let price_drop = state.current_floor - proposed_price;
        // drop_bps = (price_drop * 10,000) / current_floor
        let drop_bps = (price_drop * 10_000) / state.current_floor;

        if drop_bps > config.max_floor_drop_bps as i128 {
            return Err(MarketGuardError::FloorPriceDropExceeded);
        }
    }

    // Update current floor and smoothed TWAP
    next_state.current_floor = proposed_price;
    if next_state.twap_floor == 0 {
        next_state.twap_floor = proposed_price;
    } else {
        // Simple moving average weighting: 75% previous TWAP + 25% new price
        next_state.twap_floor = (next_state.twap_floor * 3 + proposed_price) / 4;
    }
    next_state.last_updated_ledger = current_ledger;
    next_state.trade_count += 1;

    Ok(next_state)
}

// ===========================================================================
// Wash-Trade Filter Core Logic
// ===========================================================================

/// Evaluates a trade for wash-trading patterns (self-dealing, circular transfers, and rapid flips).
///
/// # Invariants
/// - Buyer and seller must not be identical if `block_self_dealing` is enabled.
/// - Buyer must not match any of the previous $K$ owners if within the cooldown window.
/// - Bounded history depth guarantees deterministic execution and strictly bounded gas.
/// - Time complexity: $O(K)$ where $K \le 8$. Space complexity: $O(1)$ auxiliary.
pub fn evaluate_wash_trade(
    env: &Env,
    config: &WashTradeConfig,
    history: &TokenOwnershipHistory,
    seller: &Address,
    buyer: &Address,
    current_ledger: u32,
) -> WashTradeVerdict {
    if !config.filter_enabled {
        return WashTradeVerdict::Passed;
    }

    // 1. Check direct self-dealing
    if config.block_self_dealing && seller == buyer {
        return WashTradeVerdict::SelfDealingBlocked;
    }

    // 2. Check minimum holding period for seller
    if current_ledger >= history.acquired_ledger {
        let elapsed = current_ledger - history.acquired_ledger;
        if config.min_holding_period_ledgers > 0 && elapsed < config.min_holding_period_ledgers {
            return WashTradeVerdict::HoldingPeriodViolation {
                elapsed_ledgers: elapsed,
                required_ledgers: config.min_holding_period_ledgers,
            };
        }
    }

    // 3. Check circular cycle: has the buyer owned this token recently?
    let depth_limit = config.max_cycle_depth.min(MAX_CYCLE_HISTORY_DEPTH);
    let history_len = history.previous_owners.len();
    let scan_count = history_len.min(depth_limit);

    for idx in 0..scan_count {
        // Check from most recent previous owner backward
        let check_idx = history_len - 1 - idx;
        if let Some(prev_owner) = history.previous_owners.get(check_idx) {
            if &prev_owner == buyer {
                let elapsed = if current_ledger >= history.acquired_ledger {
                    current_ledger - history.acquired_ledger
                } else {
                    0
                };
                let cooldown = config.min_holding_period_ledgers;
                let cooldown_remaining = if cooldown > elapsed { cooldown - elapsed } else { 0 };

                if cooldown_remaining > 0 {
                    return WashTradeVerdict::CircularCycleBlocked {
                        cycle_depth: idx + 1,
                        cooldown_remaining,
                    };
                }
            }
        }
    }

    WashTradeVerdict::Passed
}

/// Applies a clean trade to update the token's ownership history ring buffer.
/// Bounded to `MAX_CYCLE_HISTORY_DEPTH` entries.
pub fn record_clean_trade(
    env: &Env,
    history: &TokenOwnershipHistory,
    new_owner: &Address,
    current_ledger: u32,
) -> TokenOwnershipHistory {
    let mut updated_history = history.clone();
    let mut prev_owners = Vec::new(env);

    // Keep up to MAX_CYCLE_HISTORY_DEPTH - 1 previous owners
    let start_idx = if history.previous_owners.len() >= MAX_CYCLE_HISTORY_DEPTH {
        history.previous_owners.len() - (MAX_CYCLE_HISTORY_DEPTH - 1)
    } else {
        0
    };

    for idx in start_idx..history.previous_owners.len() {
        if let Some(owner) = history.previous_owners.get(idx) {
            prev_owners.push_back(owner);
        }
    }

    // Append the seller (current_owner) to previous_owners
    prev_owners.push_back(history.current_owner.clone());

    updated_history.current_owner = new_owner.clone();
    updated_history.acquired_ledger = current_ledger;
    updated_history.previous_owners = prev_owners;

    updated_history
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    #[test]
    fn test_floor_price_normal_progression() {
        let config = FloorPriceGuardConfig {
            min_floor_price: 100,
            max_floor_drop_bps: 2_000, // max 20% drop
            twap_window_ledgers: 100,
            guard_enabled: true,
        };

        let initial_state = FloorPriceState {
            current_floor: 500,
            twap_floor: 500,
            last_updated_ledger: 10,
            trade_count: 1,
        };

        // Price increases: perfectly valid
        let res1 = verify_floor_price(&config, &initial_state, 600, 15);
        assert!(res1.is_ok());
        let state1 = res1.unwrap();
        assert_eq!(state1.current_floor, 600);
        assert_eq!(state1.twap_floor, (500 * 3 + 600) / 4); // 525

        // Price drops within 20% (e.g. from 600 to 500 is 16.6% drop): valid
        let res2 = verify_floor_price(&config, &state1, 500, 20);
        assert!(res2.is_ok());
        assert_eq!(res2.unwrap().current_floor, 500);
    }

    #[test]
    fn test_floor_price_drop_exceeded_rejected() {
        let config = FloorPriceGuardConfig {
            min_floor_price: 100,
            max_floor_drop_bps: 1_000, // max 10% drop
            twap_window_ledgers: 100,
            guard_enabled: true,
        };

        let state = FloorPriceState {
            current_floor: 1_000,
            twap_floor: 1_000,
            last_updated_ledger: 50,
            trade_count: 5,
        };

        // Attempting to list at 800 (20% drop) exceeds 10% limit
        let res = verify_floor_price(&config, &state, 800, 60);
        assert_eq!(res, Err(MarketGuardError::FloorPriceDropExceeded));
    }

    #[test]
    fn test_floor_price_below_minimum_rejected() {
        let config = FloorPriceGuardConfig {
            min_floor_price: 500,
            max_floor_drop_bps: 5_000,
            twap_window_ledgers: 100,
            guard_enabled: true,
        };

        let state = FloorPriceState {
            current_floor: 600,
            twap_floor: 600,
            last_updated_ledger: 50,
            trade_count: 2,
        };

        let res = verify_floor_price(&config, &state, 400, 60);
        assert_eq!(res, Err(MarketGuardError::FloorPriceBelowMinimum));
    }

    #[test]
    fn test_wash_trade_direct_self_dealing_blocked() {
        let env = Env::default();
        let alice = Address::generate(&env);

        let config = WashTradeConfig {
            min_holding_period_ledgers: 10,
            max_cycle_depth: 4,
            block_self_dealing: true,
            filter_enabled: true,
        };

        let history = TokenOwnershipHistory {
            token_id: 1,
            current_owner: alice.clone(),
            acquired_ledger: 100,
            previous_owners: Vec::new(&env),
        };

        let verdict = evaluate_wash_trade(&env, &config, &history, &alice, &alice, 105);
        assert_eq!(verdict, WashTradeVerdict::SelfDealingBlocked);
    }

    #[test]
    fn test_wash_trade_circular_cycle_blocked_and_cooldown_recovery() {
        let env = Env::default();
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        let config = WashTradeConfig {
            min_holding_period_ledgers: 50,
            max_cycle_depth: 4,
            block_self_dealing: true,
            filter_enabled: true,
        };

        // Token currently owned by Bob, previously owned by Alice
        let mut prev = Vec::new(&env);
        prev.push_back(alice.clone());

        let history = TokenOwnershipHistory {
            token_id: 42,
            current_owner: bob.clone(),
            acquired_ledger: 100,
            previous_owners: prev,
        };

        // Bob tries to sell back to Alice at ledger 120 (only 20 ledgers passed, < 50)
        let verdict = evaluate_wash_trade(&env, &config, &history, &bob, &alice, 120);
        match verdict {
            WashTradeVerdict::CircularCycleBlocked { cooldown_remaining, .. } => {
                assert_eq!(cooldown_remaining, 30);
            }
            _ => panic!("Expected CircularCycleBlocked"),
        }

        // At ledger 160 (60 ledgers passed, > 50 cooldown), circular trade is now allowed!
        let verdict_after = evaluate_wash_trade(&env, &config, &history, &bob, &alice, 160);
        assert_eq!(verdict_after, WashTradeVerdict::Passed);
    }

    #[test]
    fn test_record_clean_trade_ring_buffer_bounds() {
        let env = Env::default();
        let u1 = Address::generate(&env);
        let u2 = Address::generate(&env);
        let u3 = Address::generate(&env);

        let history0 = TokenOwnershipHistory {
            token_id: 7,
            current_owner: u1.clone(),
            acquired_ledger: 10,
            previous_owners: Vec::new(&env),
        };

        let history1 = record_clean_trade(&env, &history0, &u2, 20);
        assert_eq!(history1.current_owner, u2);
        assert_eq!(history1.acquired_ledger, 20);
        assert_eq!(history1.previous_owners.len(), 1);
        assert_eq!(history1.previous_owners.get(0).unwrap(), u1);

        let history2 = record_clean_trade(&env, &history1, &u3, 30);
        assert_eq!(history2.current_owner, u3);
        assert_eq!(history2.previous_owners.len(), 2);
        assert_eq!(history2.previous_owners.get(0).unwrap(), u1);
        assert_eq!(history2.previous_owners.get(1).unwrap(), u2);
    }
}

//! # Oracle Price Feed Heartbeat & L2 Deviation Quarantine (Issue #518)
//!
//! Production-grade heartbeat validation and L2 price deviation quarantine
//! module for the Trellis Soroban oracle infrastructure.
//!
//! ## Overview
//!
//! Oracle feeds on L2 and high-speed networks face two critical operational risks:
//! 1. **Heartbeat Failures**: Submissions stall due to sequencer outages, network partitions,
//!    or submitter node crashes. Downstream financial contracts must not consume frozen, stale data.
//! 2. **L2 Deviation Anomalies**: Erroneous data spikes, flash-loan price manipulation, or
//!    sequencer reordering anomalies can inject extreme price movements. Rather than propagating
//!    poisoned prices directly to liquidations or aid conversions, the feed is placed into
//!    a protective **Quarantine State**.
//!
//! ## Architecture & Quarantine Lifecycle
//!
//! ```text
//! Price Submission
//!        │
//!        ▼
//! [ Heartbeat Check ] ── (now > last_updated + heartbeat) ──► Error (HeartbeatMissed)
//!        │ Pass
//!        ▼
//! [ Deviation Check ] ── (|price - ref| / ref > max_bps) ──► Place in Quarantine (PriceDeviationQuarantined)
//!        │ Pass (or auto-recovers after cooldown)
//!        ▼
//! [ Active / Valid Price ] ──► Update Reference & Feed State
//! ```
//!
//! ## Complexity
//! - Time Complexity: $O(1)$ arithmetic evaluation
//! - Space Complexity: $O(1)$ state footprint per feed

#![allow(clippy::too_many_arguments)]

use soroban_sdk::{contracterror, contracttype, symbol_short, Symbol};

pub const BPS_DIVISOR: i128 = 10_000;
pub const DEFAULT_MAX_DEVIATION_BPS: u32 = 1_000; // 10%
pub const DEFAULT_QUARANTINE_DURATION_SECS: u64 = 1_800; // 30 minutes
pub const DEFAULT_HEARTBEAT_SECS: u64 = 300; // 5 minutes

// ===========================================================================
// Error taxonomy (524–532 in Oracle domain)
// ===========================================================================

#[contracterror(export = false)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum OracleQuarantineError {
    /// The feed update missed its expected heartbeat deadline.
    HeartbeatMissed = 524,
    /// Price deviation exceeded the configured quarantine threshold.
    PriceDeviationQuarantined = 525,
    /// The feed is currently in quarantine and cannot be queried for live settlement.
    QuarantineActive = 526,
    /// Configuration parameter is invalid (e.g. 0 duration or bps > 10,000).
    InvalidQuarantineConfig = 527,
    /// Caller is not authorized to configure or release feed quarantine.
    Unauthorized = 528,
    /// Arithmetic overflow in deviation or timestamp calculation.
    MathOverflow = 529,
    /// The feed is already quarantined.
    FeedAlreadyQuarantined = 530,
    /// The feed is not currently quarantined.
    FeedNotQuarantined = 531,
    /// Invalid price supplied (negative or zero).
    InvalidPrice = 532,
}

// ===========================================================================
// Data Structures
// ===========================================================================

/// Heartbeat configuration for a price feed.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeartbeatConfig {
    pub feed_id: Symbol,
    /// Maximum allowed seconds between updates before feed is declared dead.
    pub heartbeat_secs: u64,
    /// Buffer for sequencer skew or block timestamp tolerance.
    pub tolerance_secs: u64,
}

/// L2 Deviation Quarantine configuration for a price feed.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantineConfig {
    pub feed_id: Symbol,
    /// Maximum allowed deviation from reference price in basis points (10,000 = 100%).
    pub max_deviation_bps: u32,
    /// Minimum duration (in seconds) the feed remains quarantined before auto-recovery.
    pub quarantine_duration_secs: u64,
    /// Required consecutive valid observations within threshold to auto-recover.
    pub required_recovery_ticks: u32,
    /// Whether quarantine enforcement is enabled.
    pub enabled: bool,
}

/// Dynamic quarantine status for an oracle feed.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantineStatus {
    pub is_quarantined: bool,
    pub quarantined_price: i128,
    pub reference_price: i128,
    pub deviation_bps: u32,
    pub quarantined_at: u64,
    pub quarantine_until: u64,
    pub recovery_ticks_counted: u32,
    pub reason: Symbol,
}

impl QuarantineStatus {
    pub fn default_active(ref_price: i128) -> Self {
        Self {
            is_quarantined: false,
            quarantined_price: 0,
            reference_price: ref_price,
            deviation_bps: 0,
            quarantined_at: 0,
            quarantine_until: 0,
            recovery_ticks_counted: 0,
            reason: symbol_short!("active"),
        }
    }
}

/// Outcome of evaluating a price update against heartbeat and quarantine rules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuarantineEvaluation {
    /// Price is healthy, within heartbeat, and within deviation limits.
    Accepted {
        deviation_bps: u32,
        is_recovered: bool,
    },
    /// Price deviated significantly and the feed has been placed in quarantine.
    Quarantined {
        deviation_bps: u32,
        quarantine_until: u64,
    },
}

// ===========================================================================
// Core Logic
// ===========================================================================

/// Validates whether a feed has adhered to its required heartbeat.
pub fn validate_heartbeat(
    now: u64,
    last_update_ts: u64,
    config: &HeartbeatConfig,
) -> Result<(), OracleQuarantineError> {
    if config.heartbeat_secs == 0 {
        return Ok(()); // Heartbeat validation disabled
    }
    let max_interval = config
        .heartbeat_secs
        .checked_add(config.tolerance_secs)
        .ok_or(OracleQuarantineError::MathOverflow)?;

    let deadline = last_update_ts
        .checked_add(max_interval)
        .ok_or(OracleQuarantineError::MathOverflow)?;

    if now > deadline {
        Err(OracleQuarantineError::HeartbeatMissed)
    } else {
        Ok(())
    }
}

/// Calculates the basis points deviation between candidate price and reference price.
pub fn compute_deviation_bps(
    candidate_price: i128,
    reference_price: i128,
) -> Result<u32, OracleQuarantineError> {
    if candidate_price <= 0 {
        return Err(OracleQuarantineError::InvalidPrice);
    }
    if reference_price <= 0 {
        // Initial observation: no reference to deviate from
        return Ok(0);
    }

    let diff = (candidate_price - reference_price).abs();
    let deviation_product = diff
        .checked_mul(BPS_DIVISOR)
        .ok_or(OracleQuarantineError::MathOverflow)?;

    let bps = deviation_product
        .checked_div(reference_price)
        .ok_or(OracleQuarantineError::MathOverflow)?;

    if bps > (u32::MAX as i128) {
        Ok(u32::MAX)
    } else {
        Ok(bps as u32)
    }
}

/// Evaluates a candidate price against the feed's quarantine state and rules.
///
/// Updates the `QuarantineStatus` in place.
pub fn evaluate_price_update(
    now: u64,
    candidate_price: i128,
    last_update_ts: u64,
    hb_config: &HeartbeatConfig,
    q_config: &QuarantineConfig,
    status: &mut QuarantineStatus,
) -> Result<QuarantineEvaluation, OracleQuarantineError> {
    if candidate_price <= 0 {
        return Err(OracleQuarantineError::InvalidPrice);
    }

    // 1. Check heartbeat if there is a recorded previous update
    if last_update_ts > 0 {
        validate_heartbeat(now, last_update_ts, hb_config)?;
    }

    // If quarantine is disabled, accept price directly
    if !q_config.enabled {
        status.reference_price = candidate_price;
        return Ok(QuarantineEvaluation::Accepted {
            deviation_bps: 0,
            is_recovered: false,
        });
    }

    // 2. Check deviation from reference price
    let deviation = compute_deviation_bps(candidate_price, status.reference_price)?;

    // 3. If currently quarantined:
    if status.is_quarantined {
        // Check if cooldown has elapsed
        let cooldown_passed = now >= status.quarantine_until;
        let within_limits = deviation <= q_config.max_deviation_bps;

        if cooldown_passed && within_limits {
            status.recovery_ticks_counted = status
                .recovery_ticks_counted
                .saturating_add(1);

            if status.recovery_ticks_counted >= q_config.required_recovery_ticks {
                // Auto-recovery condition met!
                status.is_quarantined = false;
                status.reference_price = candidate_price;
                status.deviation_bps = deviation;
                status.reason = symbol_short!("recovered");
                return Ok(QuarantineEvaluation::Accepted {
                    deviation_bps: deviation,
                    is_recovered: true,
                });
            }
        } else if !within_limits {
            // Reset recovery tick counter on persistent deviation
            status.recovery_ticks_counted = 0;
        }

        // Still quarantined
        return Err(OracleQuarantineError::QuarantineActive);
    }

    // 4. If not currently quarantined, check if candidate price trips deviation bound:
    if status.reference_price > 0 && deviation > q_config.max_deviation_bps {
        // Trip quarantine!
        let quarantine_until = now
            .checked_add(q_config.quarantine_duration_secs)
            .ok_or(OracleQuarantineError::MathOverflow)?;

        status.is_quarantined = true;
        status.quarantined_price = candidate_price;
        status.deviation_bps = deviation;
        status.quarantined_at = now;
        status.quarantine_until = quarantine_until;
        status.recovery_ticks_counted = 0;
        status.reason = symbol_short!("dev_spike");

        return Ok(QuarantineEvaluation::Quarantined {
            deviation_bps: deviation,
            quarantine_until,
        });
    }

    // 5. Normal healthy price within tolerance
    status.reference_price = candidate_price;
    status.deviation_bps = deviation;
    status.reason = symbol_short!("healthy");

    Ok(QuarantineEvaluation::Accepted {
        deviation_bps: deviation,
        is_recovered: false,
    })
}

/// Allows governance or emergency administrator to release a feed from quarantine.
pub fn release_quarantine_override(
    status: &mut QuarantineStatus,
    new_reference_price: i128,
) -> Result<(), OracleQuarantineError> {
    if !status.is_quarantined {
        return Err(OracleQuarantineError::FeedNotQuarantined);
    }
    if new_reference_price <= 0 {
        return Err(OracleQuarantineError::InvalidPrice);
    }

    status.is_quarantined = false;
    status.reference_price = new_reference_price;
    status.quarantined_price = 0;
    status.recovery_ticks_counted = 0;
    status.reason = symbol_short!("adm_rel");

    Ok(())
}

/// Allows governance to manually quarantine a suspicious feed immediately.
pub fn force_quarantine_feed(
    now: u64,
    status: &mut QuarantineStatus,
    duration_secs: u64,
    reason: Symbol,
) -> Result<(), OracleQuarantineError> {
    if status.is_quarantined {
        return Err(OracleQuarantineError::FeedAlreadyQuarantined);
    }
    if duration_secs == 0 {
        return Err(OracleQuarantineError::InvalidQuarantineConfig);
    }

    let quarantine_until = now
        .checked_add(duration_secs)
        .ok_or(OracleQuarantineError::MathOverflow)?;

    status.is_quarantined = true;
    status.quarantined_at = now;
    status.quarantine_until = quarantine_until;
    status.recovery_ticks_counted = 0;
    status.reason = reason;

    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    #[test]
    fn test_heartbeat_normal_and_missed() {
        let _env = Env::default();
        let feed = symbol_short!("XLM_USD");
        let hb_config = HeartbeatConfig {
            feed_id: feed,
            heartbeat_secs: 300,
            tolerance_secs: 15,
        };

        let now = 1000;
        // Normal within heartbeat (now - last = 250s <= 315s)
        assert!(validate_heartbeat(now, 750, &hb_config).is_ok());

        // Exact boundary (now - last = 315s)
        assert!(validate_heartbeat(now, 685, &hb_config).is_ok());

        // Heartbeat missed (now - last = 320s > 315s)
        let err = validate_heartbeat(now, 680, &hb_config).unwrap_err();
        assert_eq!(err, OracleQuarantineError::HeartbeatMissed);
    }

    #[test]
    fn test_deviation_calculation() {
        // 100 to 110 => 10% = 1000 bps
        let bps = compute_deviation_bps(110_0000000, 100_0000000).unwrap();
        assert_eq!(bps, 1000);

        // 100 to 90 => 10% = 1000 bps
        let bps2 = compute_deviation_bps(90_0000000, 100_0000000).unwrap();
        assert_eq!(bps2, 1000);

        // Zero reference (first observation) => 0 bps
        let bps_init = compute_deviation_bps(100_0000000, 0).unwrap();
        assert_eq!(bps_init, 0);

        // Negative price rejected
        assert_eq!(
            compute_deviation_bps(-5, 100).unwrap_err(),
            OracleQuarantineError::InvalidPrice
        );
    }

    #[test]
    fn test_quarantine_trip_and_active_rejection() {
        let feed = symbol_short!("BTC_USD");
        let hb_config = HeartbeatConfig {
            feed_id: feed.clone(),
            heartbeat_secs: 300,
            tolerance_secs: 0,
        };
        let q_config = QuarantineConfig {
            feed_id: feed,
            max_deviation_bps: 1_000, // 10% max
            quarantine_duration_secs: 1_800,
            required_recovery_ticks: 2,
            enabled: true,
        };

        let mut status = QuarantineStatus::default_active(50_000_0000000);

        // Normal price: 52_000 (+4% deviation <= 10%)
        let eval = evaluate_price_update(1000, 52_000_0000000, 900, &hb_config, &q_config, &mut status)
            .unwrap();
        assert!(matches!(eval, QuarantineEvaluation::Accepted { .. }));
        assert!(!status.is_quarantined);

        // Anomalous L2 price spike: 65_000 (from 52_000 is 25% deviation > 10%)
        let eval_spike = evaluate_price_update(1100, 65_000_0000000, 1000, &hb_config, &q_config, &mut status)
            .unwrap();
        assert!(matches!(eval_spike, QuarantineEvaluation::Quarantined { .. }));
        assert!(status.is_quarantined);
        assert_eq!(status.quarantined_price, 65_000_0000000);
        assert_eq!(status.quarantine_until, 1100 + 1_800);

        // Next read/submission while in cooldown should fail with QuarantineActive
        let eval_rejected = evaluate_price_update(1200, 53_000_0000000, 1100, &hb_config, &q_config, &mut status);
        assert_eq!(eval_rejected.unwrap_err(), OracleQuarantineError::QuarantineActive);
    }

    #[test]
    fn test_quarantine_auto_recovery_and_manual_release() {
        let feed = symbol_short!("ETH_USD");
        let hb_config = HeartbeatConfig {
            feed_id: feed.clone(),
            heartbeat_secs: 1_000,
            tolerance_secs: 0,
        };
        let q_config = QuarantineConfig {
            feed_id: feed,
            max_deviation_bps: 1_000, // 10%
            quarantine_duration_secs: 1_800,
            required_recovery_ticks: 2,
            enabled: true,
        };

        let mut status = QuarantineStatus::default_active(3_000_0000000);

        // Spike trips quarantine at t = 1000, until 2800
        let _ = evaluate_price_update(1000, 4_000_0000000, 900, &hb_config, &q_config, &mut status).unwrap();
        assert!(status.is_quarantined);

        // Manual Admin Override Release
        release_quarantine_override(&mut status, 3_050_0000000).unwrap();
        assert!(!status.is_quarantined);
        assert_eq!(status.reference_price, 3_050_0000000);

        // Force quarantine manually by Admin
        force_quarantine_feed(1500, &mut status, 600, symbol_short!("drill")).unwrap();
        assert!(status.is_quarantined);
        assert_eq!(status.quarantine_until, 2100);

        // After cooldown passes (t = 2200), consecutive valid observations auto-recover feed
        let eval_tick1 = evaluate_price_update(2200, 3_080_0000000, 1500, &hb_config, &q_config, &mut status);
        // First tick recorded, still quarantined until required ticks (2) reached
        assert_eq!(eval_tick1.unwrap_err(), OracleQuarantineError::QuarantineActive);

        // Second tick at 2250 meets required ticks -> auto-recovers!
        let eval_tick2 = evaluate_price_update(2250, 3_090_0000000, 2200, &hb_config, &q_config, &mut status).unwrap();
        assert!(matches!(eval_tick2, QuarantineEvaluation::Accepted { is_recovered: true, .. }));
        assert!(!status.is_quarantined);
    }
}

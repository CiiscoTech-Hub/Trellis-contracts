use soroban_sdk::{contracterror, contracttype, Address, Symbol};

extern crate alloc;
use alloc::vec::Vec;

/// Represents a single price feed submission.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PriceSubmission {
    /// Unique identifier for this submission.
    pub id: u64,
    /// The submitter address (must be authorised).
    pub submitter: Address,
    /// Feed identifier (e.g., "BTC/USD", "ETH/USD").
    pub feed_id: Symbol,
    /// The price value (fixed-point; e.g., 50000 x 10^8 for $50,000 BTC).
    pub price: i128,
    /// Number of decimal places in the price (typically 8 for USD pairs).
    pub decimals: u32,
    /// Timestamp when the price was observed off-chain.
    pub timestamp: u64,
    /// Nonce for replay protection (incremented per submitter per feed).
    pub nonce: u64,
}

/// Represents the latest value for a feed with metadata.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeedLatest {
    /// Feed identifier.
    pub feed_id: Symbol,
    /// Latest price.
    pub price: i128,
    /// Decimal places.
    pub decimals: u32,
    /// Timestamp of the latest submission.
    pub timestamp: u64,
    /// Number of submissions for this feed.
    pub submission_count: u64,
}

/// Represents a registered submitter with permissions.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmitterInfo {
    /// Submitter address.
    pub address: Address,
    /// Whether this submitter is currently active.
    pub active: bool,
    /// When the submitter was registered (timestamp).
    pub registered_at: u64,
}

/// Configuration for a TWAP window calculation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TwapConfig {
    /// Window length in seconds over which the time-weighted average is taken.
    pub window_secs: u64,
    /// Maximum gap (seconds) between consecutive observations that may be
    /// bridged by linear interpolation. Larger gaps fail rather than extrapolate.
    pub max_interpolation_gap_secs: u64,
    /// Minimum number of observations required inside the window.
    pub min_observations: u32,
}

/// A single observation used as input to the TWAP calculator.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PriceObservation {
    /// Price at the observation time (fixed-point).
    pub price: i128,
    /// Observation timestamp in seconds.
    pub timestamp: u64,
}

/// Result of a TWAP computation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TwapResult {
    /// Time-weighted average price (fixed-point, same decimals as inputs).
    pub twap: i128,
    /// Window start timestamp (inclusive).
    pub window_start: u64,
    /// Window end timestamp (inclusive).
    pub window_end: u64,
    /// Number of seconds in the window that were bridged by interpolation.
    pub interpolated_secs: u64,
}

/// Errors produced by the TWAP window calculator.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum TwapError {
    /// The configuration is invalid (zero window or zero minimum observations).
    InvalidConfig = 1,
    /// Observations are not ordered by non-decreasing timestamp.
    UnorderedObservations = 2,
    /// Fewer observations than required fall inside the window.
    InsufficientObservations = 3,
    /// A gap between observations exceeds the interpolation limit.
    GapTooLarge = 4,
    /// No observation at or before the window start anchors the calculation.
    WindowNotCovered = 5,
    /// Arithmetic overflow during computation.
    Overflow = 6,
}

/// Computes a TWAP over `[now - config.window_secs, now]` from ordered
/// observations, linearly interpolating price across missing ledgers whose
/// gaps are within `config.max_interpolation_gap_secs`.
///
/// Edge-case behaviour:
/// - Observations must be sorted by non-decreasing timestamp; otherwise
///   `UnorderedObservations` is returned (no silent reordering).
/// - Observations before the window serve only as the left anchor; the
///   anchor is the last observation at or before the window start.
/// - If no such anchor exists, `WindowNotCovered` is returned.
/// - Gaps larger than `max_interpolation_gap_secs` return `GapTooLarge` so
///   callers can retry after fresh submissions arrive; nothing is extrapolated.
/// - Fewer than `min_observations` inside the window returns
///   `InsufficientObservations` (retryable).
/// - The function is pure: no storage writes, so a failed call needs no rollback.
/// - No authorization is performed here; callers must enforce it.
pub fn compute_twap(
    config: &TwapConfig,
    observations: &[PriceObservation],
    now: u64,
) -> Result<TwapResult, TwapError> {
    if config.window_secs == 0 || config.min_observations == 0 {
        return Err(TwapError::InvalidConfig);
    }
    for pair in observations.windows(2) {
        if pair[1].timestamp < pair[0].timestamp {
            return Err(TwapError::UnorderedObservations);
        }
    }

    let window_end = now;
    let window_start = now.saturating_sub(config.window_secs);

    let anchor_idx = observations
        .iter()
        .rposition(|o| o.timestamp <= window_start)
        .ok_or(TwapError::WindowNotCovered)?;

    let inside: Vec<&PriceObservation> = observations[anchor_idx..]
        .iter()
        .filter(|o| o.timestamp > window_start && o.timestamp <= window_end)
        .collect();
    if (inside.len() as u32) < config.min_observations {
        return Err(TwapError::InsufficientObservations);
    }

    // Knots: window-start anchor, in-window observations, window-end hold.
    let mut knots: Vec<(u64, i128, bool)> = Vec::new();
    knots.push((window_start, observations[anchor_idx].price, false));
    for o in &inside {
        knots.push((o.timestamp, o.price, true));
    }
    let last = *knots.last().unwrap();
    if last.0 < window_end {
        knots.push((window_end, last.1, false));
    }

    let mut weighted: i128 = 0;
    let mut interpolated_secs: u64 = 0;
    for pair in knots.windows(2) {
        let (t0, p0, _) = pair[0];
        let (t1, p1, t1_real) = pair[1];
        let dt = t1 - t0;
        if dt == 0 {
            continue;
        }
        if dt > config.max_interpolation_gap_secs {
            return Err(TwapError::GapTooLarge);
        }
        if !t1_real {
            interpolated_secs = interpolated_secs
                .checked_add(dt)
                .ok_or(TwapError::Overflow)?;
        }
        // Trapezoidal area under the linear segment between knots.
        let area = p0
            .checked_add(p1)
            .and_then(|s| s.checked_mul(dt as i128))
            .ok_or(TwapError::Overflow)?;
        weighted = weighted.checked_add(area).ok_or(TwapError::Overflow)?;
    }

    let total = (window_end - window_start) as i128;
    let twap = weighted / (2 * total);

    Ok(TwapResult {
        twap,
        window_start,
        window_end,
        interpolated_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(window: u64, gap: u64, min: u32) -> TwapConfig {
        TwapConfig {
            window_secs: window,
            max_interpolation_gap_secs: gap,
            min_observations: min,
        }
    }

    fn obs(p: i128, t: u64) -> PriceObservation {
        PriceObservation { price: p, timestamp: t }
    }

    #[test]
    fn normal_constant_price() {
        let o = [obs(100, 0), obs(100, 50), obs(100, 90)];
        let r = compute_twap(&cfg(100, 60, 1), &o, 100).unwrap();
        assert_eq!(r.twap, 100);
        assert_eq!(r.window_start, 0);
        assert_eq!(r.window_end, 100);
    }

    #[test]
    fn normal_linear_interpolation_across_gap() {
        let o = [obs(100, 0), obs(200, 100)];
        let r = compute_twap(&cfg(100, 200, 1), &o, 100).unwrap();
        assert_eq!(r.twap, 150);
    }

    #[test]
    fn missing_ledger_interpolation_counted() {
        let o = [obs(100, 0), obs(200, 100)];
        let r = compute_twap(&cfg(100, 200, 1), &o, 100).unwrap();
        assert!(r.interpolated_secs > 0);
    }

    #[test]
    fn failure_invalid_config() {
        let o = [obs(100, 0)];
        assert_eq!(
            compute_twap(&cfg(0, 10, 1), &o, 10),
            Err(TwapError::InvalidConfig)
        );
        assert_eq!(
            compute_twap(&cfg(10, 10, 0), &o, 10),
            Err(TwapError::InvalidConfig)
        );
    }

    #[test]
    fn failure_unordered_observations() {
        let o = [obs(100, 50), obs(100, 10)];
        assert_eq!(
            compute_twap(&cfg(100, 100, 1), &o, 100),
            Err(TwapError::UnorderedObservations)
        );
    }

    #[test]
    fn failure_window_not_covered() {
        let o = [obs(100, 50), obs(100, 90)];
        assert_eq!(
            compute_twap(&cfg(100, 100, 1), &o, 100),
            Err(TwapError::WindowNotCovered)
        );
    }

    #[test]
    fn failure_gap_too_large() {
        let o = [obs(100, 0), obs(200, 500)];
        assert_eq!(
            compute_twap(&cfg(500, 100, 1), &o, 500),
            Err(TwapError::GapTooLarge)
        );
    }

    #[test]
    fn retry_after_insufficient_observations_succeeds_with_more_data() {
        let c = cfg(100, 200, 3);
        let few = [obs(100, 0), obs(100, 50)];
        assert_eq!(
            compute_twap(&c, &few, 100),
            Err(TwapError::InsufficientObservations)
        );
        let more = [obs(100, 0), obs(100, 30), obs(100, 60), obs(100, 90)];
        assert!(compute_twap(&c, &more, 100).is_ok());
    }

    #[test]
    fn authorization_not_applicable_pure_computation() {
        let o = [obs(100, 0), obs(200, 100)];
        let a = compute_twap(&cfg(100, 200, 1), &o, 100);
        let b = compute_twap(&cfg(100, 200, 1), &o, 100);
        assert_eq!(a, b);
    }
}

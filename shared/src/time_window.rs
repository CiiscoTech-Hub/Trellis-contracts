use soroban_sdk::{contracterror, contracttype, symbol_short, Env};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum TimeWindowError {
    TooEarly = 1,
    Expired = 2,
    Stale = 3,
    Invalid = 4,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeWindow {
    pub start: u64,
    pub end: u64,
}

/// Anti-sniping configuration for auctions.
///
/// - `extension_window`: if a bid lands within this many seconds of `end`,
///   the auction end is extended.
/// - `extension_duration`: number of seconds the end is pushed out by
///   when the extension window is triggered.
/// - `min_bid_increment`: minimum amount a new bid must exceed the current
///   highest bid by (absolute units of the auction currency).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AntiSnipeConfig {
    pub extension_window: u64,
    pub extension_duration: u64,
    pub min_bid_increment: i128,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AntiSnipeError {
    Invalid,
    BidTooLow,
    Window(TimeWindowError),
}

impl From<TimeWindowError> for AntiSnipeError {
    fn from(e: TimeWindowError) -> Self {
        AntiSnipeError::Window(e)
    }
}

pub fn validate_time_window(env: &Env, window: &TimeWindow) -> Result<(), TimeWindowError> {
    if window.end < window.start {
        return Err(TimeWindowError::Stale);
    }
    let now = env.ledger().timestamp();
    if now < window.start {
        env.events().publish(
            (symbol_short!("timewin"), symbol_short!("early")),
            (now, window.start, window.end),
        );
        return Err(TimeWindowError::TooEarly);
    }
    if now > window.end {
        env.events().publish(
            (symbol_short!("timewin"), symbol_short!("expired")),
            (now, window.start, window.end),
        );
        return Err(TimeWindowError::Expired);
    }
    Ok(())
}

/// Validates a config before use. `extension_window` must not exceed
/// `extension_duration` range sanity-wise (both must be non-zero when
/// extensions are enabled) and the increment must be non-negative.
pub fn validate_anti_snipe_config(cfg: &AntiSnipeConfig) -> Result<(), AntiSnipeError> {
    if cfg.min_bid_increment < 0 {
        return Err(AntiSnipeError::Invalid);
    }
    if cfg.extension_window > 0 && cfg.extension_duration == 0 {
        return Err(AntiSnipeError::Invalid);
    }
    Ok(())
}

/// Checks that a new bid satisfies the minimum increment over the current
/// highest bid. A `current_highest` of 0 means there is no prior bid, in
/// which case any positive bid is accepted.
pub fn validate_bid_increment(
    cfg: &AntiSnipeConfig,
    current_highest: i128,
    new_bid: i128,
) -> Result<(), AntiSnipeError> {
    if new_bid <= 0 {
        return Err(AntiSnipeError::BidTooLow);
    }
    if current_highest < 0 {
        return Err(AntiSnipeError::Invalid);
    }
    if current_highest == 0 {
        return Ok(());
    }
    let min_required = current_highest
        .checked_add(cfg.min_bid_increment)
        .ok_or(AntiSnipeError::Invalid)?;
    if new_bid < min_required {
        return Err(AntiSnipeError::BidTooLow);
    }
    Ok(())
}

/// Computes the auction end after applying anti-sniping. If the bid arrives
/// inside the extension window (`end - now <= extension_window` and `now <= end`),
/// the end is pushed to `now + extension_duration`, but never shortened.
/// Returns the (possibly unchanged) new end timestamp and whether an
/// extension occurred.
pub fn apply_anti_snipe(
    env: &Env,
    cfg: &AntiSnipeConfig,
    window: &TimeWindow,
) -> Result<(u64, bool), AntiSnipeError> {
    validate_anti_snipe_config(cfg)?;
    let now = env.ledger().timestamp();
    if now > window.end {
        return Err(AntiSnipeError::Window(TimeWindowError::Expired));
    }
    if now < window.start {
        return Err(AntiSnipeError::Window(TimeWindowError::TooEarly));
    }
    if cfg.extension_window == 0 || cfg.extension_duration == 0 {
        return Ok((window.end, false));
    }
    let remaining = window.end - now;
    if remaining > cfg.extension_window {
        return Ok((window.end, false));
    }
    let candidate = now
        .checked_add(cfg.extension_duration)
        .ok_or(AntiSnipeError::Invalid)?;
    if candidate <= window.end {
        return Ok((window.end, false));
    }
    env.events().publish(
        (symbol_short!("timewin"), symbol_short!("extend")),
        (now, window.end, candidate),
    );
    Ok((candidate, true))
}

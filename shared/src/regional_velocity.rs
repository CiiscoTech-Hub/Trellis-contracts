//! Regional disbursement quota and velocity circuit breaker (Issue #539).
//!
//! # Problem
//!
//! Aid disbursement must be throttled per **region** on two independent axes:
//!
//! 1. **Volume quota** — a region may receive at most `max_amount_per_window`
//!    over a rolling `quota_window_secs` (e.g. "no more than X per day to the
//!    Sahel"). This protects against a single region draining the programme.
//! 2. **Velocity** — an abnormal *burst* of disbursements in a short window is
//!    a classic signature of a compromised key, a buggy integration, or fraud.
//!    A **circuit breaker** latches when the burst threshold is crossed and
//!    stays open (blocking further disbursement) until a cooldown elapses or an
//!    operator resets it — exactly like an electrical breaker, it does not
//!    silently re-close on the next window.
//!
//! # Soroban transactional-revert constraint (important)
//!
//! A Soroban transaction that ultimately returns `Err` has **all** of its
//! storage writes reverted. A breaker therefore cannot be "tripped and then
//! rejected" in the same call — the trip would be rolled back with the
//! rejection. The only writes that survive are those on a **committing**
//! (success-returning) path. This module is designed around that fact:
//!
//! - The op that reaches the velocity threshold is **allowed** (its call
//!   commits) and that same commit **arms** the breaker. Subsequent ops, in a
//!   later call, see the armed breaker and are rejected with
//!   [`Error::OperationPaused`]. Net effect: at most `max_ops` disbursements
//!   clear per velocity window, after which the region is latched off.
//! - A rejected op (quota exceeded, breaker already armed) performs no
//!   surviving write, so there is nothing to roll back and no partial state.
//!
//! # Fail-open by default
//!
//! A region with no [`RegionLimit`] configured is **unconstrained**
//! ([`guard_disbursement`] returns `configured: false` and allows the op), so
//! adopting this module never changes behaviour for regions an operator has not
//! opted in. This mirrors `quota::check_and_consume`.
//!
//! # Paths covered (acceptance criteria)
//!
//! - **Normal:** configure a region, disburse under both limits.
//! - **Failure:** volume over quota ([`Error::QuotaExceeded`]); velocity burst
//!   latches the breaker ([`Error::OperationPaused`]); invalid config
//!   ([`Error::ConfigInvalid`]); non-positive amount ([`Error::InvalidAmount`]).
//! - **Retry:** a rejected disbursement writes nothing, so a retry behaves as
//!   if the rejected attempt never happened; a quota/velocity window that has
//!   elapsed rolls over and admits traffic again.
//! - **Authorization:** config and breaker-reset are not self-authenticating by
//!   design (same convention as `quota`); the calling contract gates them. The
//!   test module proves an unauthorized caller is rejected before mutation.
//! - **Recovery / rollback:** [`reset_breaker`] clears a latched breaker and
//!   restarts the velocity window; a cooldown auto-recovers without operator
//!   action. Because the engine only writes on success, a trapped host call
//!   leaves region state untouched.
//!
//! See `implementation.md` for the operator runbook and complexity analysis.

use soroban_sdk::{contracttype, Env, Symbol};

use crate::errors::Error;
use crate::storage::{instance_get, instance_set, persistent_get, persistent_set};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Per-region disbursement limits. Lives in **instance** storage: small,
/// contract-level configuration that must always be readable.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegionLimit {
    /// Rolling volume window length, in seconds.
    pub quota_window_secs: u64,
    /// Maximum cumulative disbursed amount per volume window.
    pub max_amount_per_window: i128,
    /// Velocity window length, in seconds.
    pub velocity_window_secs: u64,
    /// Operations allowed per velocity window before the breaker latches.
    pub max_ops_per_velocity_window: u32,
    /// Seconds a latched breaker stays open before auto-recovery. `0` means the
    /// breaker only clears via an explicit [`reset_breaker`].
    pub cooldown_secs: u64,
}

impl RegionLimit {
    /// Validate ranges before persisting.
    pub fn validate(&self) -> Result<(), Error> {
        if self.quota_window_secs == 0 || self.velocity_window_secs == 0 {
            return Err(Error::ConfigInvalid);
        }
        if self.max_amount_per_window < 0 || self.max_ops_per_velocity_window == 0 {
            return Err(Error::ConfigInvalid);
        }
        Ok(())
    }
}

/// Mutable per-region counters. Lives in **persistent** storage: per-region
/// data that must outlive a single transaction.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegionState {
    /// Start timestamp of the current volume window.
    pub quota_window_start: u64,
    /// Cumulative amount disbursed in the current volume window.
    pub quota_amount: i128,
    /// Start timestamp of the current velocity window.
    pub vel_window_start: u64,
    /// Operations recorded in the current velocity window.
    pub vel_ops: u32,
    /// Timestamp the breaker latched at; `0` means closed (healthy).
    pub breaker_tripped_at: u64,
}

impl RegionState {
    fn fresh(now: u64) -> Self {
        Self {
            quota_window_start: now,
            quota_amount: 0,
            vel_window_start: now,
            vel_ops: 0,
            breaker_tripped_at: 0,
        }
    }
}

/// Outcome of a successful [`guard_disbursement`] (the committing path).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardReceipt {
    pub region: Symbol,
    /// `false` when the region has no configured limit (the op was allowed
    /// unconditionally).
    pub configured: bool,
    pub amount: i128,
    /// Cumulative volume in the window after recording this op.
    pub quota_amount_after: i128,
    /// Velocity count in the window after recording this op.
    pub vel_ops_after: u32,
    /// `true` when this very op armed the breaker (it still committed).
    pub breaker_armed: bool,
}

/// Maintainer-facing snapshot of a region.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegionStatus {
    pub region: Symbol,
    pub configured: bool,
    pub limit: RegionLimit,
    pub state: RegionState,
    /// `true` when the breaker is currently blocking disbursement at `now`.
    pub breaker_active: bool,
    /// Remaining volume in the current window (saturating at 0).
    pub quota_remaining: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum RegionKey {
    Limit(Symbol),
    State(Symbol),
}

fn limit_key(region: &Symbol) -> RegionKey {
    RegionKey::Limit(region.clone())
}

fn state_key(region: &Symbol) -> RegionKey {
    RegionKey::State(region.clone())
}

/// Default used by `RegionStatus` when a region has no configured limit.
fn zero_limit() -> RegionLimit {
    RegionLimit {
        quota_window_secs: 0,
        max_amount_per_window: 0,
        velocity_window_secs: 0,
        max_ops_per_velocity_window: 0,
        cooldown_secs: 0,
    }
}

// ---------------------------------------------------------------------------
// Configuration administration (caller enforces authorization)
// ---------------------------------------------------------------------------

/// Set (or replace) the limit for a region. Caller must gate on admin.
pub fn set_region_limit(env: &Env, region: &Symbol, limit: &RegionLimit) -> Result<(), Error> {
    limit.validate()?;
    instance_set(env, &limit_key(region), limit);
    Ok(())
}

/// Configured limit for a region, or `None` (fail-open).
pub fn get_region_limit(env: &Env, region: &Symbol) -> Option<RegionLimit> {
    instance_get(env, &limit_key(region))
}

/// Current stored state for a region, if any disbursement has been recorded.
pub fn get_region_state(env: &Env, region: &Symbol) -> Option<RegionState> {
    persistent_get(env, &state_key(region))
}

/// Returns whether a breaker is actively blocking at `now` given `limit`.
fn breaker_active_at(limit: &RegionLimit, state: &RegionState, now: u64) -> bool {
    if state.breaker_tripped_at == 0 {
        return false;
    }
    if limit.cooldown_secs == 0 {
        return true; // latched until manual reset
    }
    // Active until the cooldown elapses.
    now < state.breaker_tripped_at.saturating_add(limit.cooldown_secs)
}

// ---------------------------------------------------------------------------
// Core guard
// ---------------------------------------------------------------------------

/// Evaluate and record a disbursement of `amount` to `region`.
///
/// Returns `Ok(GuardReceipt)` when the op is allowed (and records it), or an
/// error when it is refused:
/// - [`Error::InvalidAmount`] — `amount <= 0`.
/// - [`Error::OperationPaused`] — the breaker is latched (burst protection).
/// - [`Error::QuotaExceeded`] — the volume window cap would be exceeded.
///
/// A region without a configured limit is allowed unconditionally
/// (`configured: false`) and records no state.
///
/// Complexity: O(1) — one config read, at most one state read and one state
/// write. No loops, no scans.
pub fn guard_disbursement(
    env: &Env,
    region: &Symbol,
    amount: i128,
) -> Result<GuardReceipt, Error> {
    if amount <= 0 {
        return Err(Error::InvalidAmount);
    }

    let limit = match get_region_limit(env, region) {
        Some(l) => l,
        None => {
            // Fail-open: unconfigured regions are unconstrained.
            return Ok(GuardReceipt {
                region: region.clone(),
                configured: false,
                amount,
                quota_amount_after: 0,
                vel_ops_after: 0,
                breaker_armed: false,
            });
        }
    };

    let now = env.ledger().timestamp();
    let mut state = get_region_state(env, region).unwrap_or_else(|| RegionState::fresh(now));

    // 1. Breaker check (cheapest; latched state blocks immediately).
    if state.breaker_tripped_at != 0 {
        if breaker_active_at(&limit, &state, now) {
            return Err(Error::OperationPaused);
        }
        // Cooldown elapsed: clear the breaker and start a fresh velocity window.
        // This write survives only if the call ultimately commits (Ok).
        state.breaker_tripped_at = 0;
        state.vel_window_start = now;
        state.vel_ops = 0;
    }

    // 2. Volume quota (rolling window). Roll first, then test the cap.
    if now.saturating_sub(state.quota_window_start) >= limit.quota_window_secs {
        state.quota_window_start = now;
        state.quota_amount = 0;
    }
    let projected_amount = state
        .quota_amount
        .checked_add(amount)
        .ok_or(Error::Overflow)?;
    if projected_amount > limit.max_amount_per_window {
        // Reject before any surviving write (the tx will revert regardless).
        return Err(Error::QuotaExceeded);
    }

    // 3. Velocity (rolling window). Roll, then record this op.
    if now.saturating_sub(state.vel_window_start) >= limit.velocity_window_secs {
        state.vel_window_start = now;
        state.vel_ops = 0;
    }
    let vel_ops_after = state.vel_ops.checked_add(1).ok_or(Error::Overflow)?;

    // Commit the op's effects.
    state.quota_amount = projected_amount;
    state.vel_ops = vel_ops_after;

    // Arm the breaker on the threshold op. This op is allowed so that the
    // commit persists the latch; the NEXT op (separate call) will be blocked.
    let breaker_armed = vel_ops_after >= limit.max_ops_per_velocity_window;
    if breaker_armed {
        state.breaker_tripped_at = now;
    }

    persistent_set(env, &state_key(region), &state);

    Ok(GuardReceipt {
        region: region.clone(),
        configured: true,
        amount,
        quota_amount_after: state.quota_amount,
        vel_ops_after,
        breaker_armed,
    })
}

// ---------------------------------------------------------------------------
// Operator surface
// ---------------------------------------------------------------------------

/// Snapshot a region at the current ledger time. Read-only.
pub fn region_status(env: &Env, region: &Symbol) -> RegionStatus {
    let now = env.ledger().timestamp();
    match get_region_limit(env, region) {
        None => RegionStatus {
            region: region.clone(),
            configured: false,
            limit: zero_limit(),
            state: get_region_state(env, region).unwrap_or_else(|| RegionState::fresh(now)),
            breaker_active: false,
            quota_remaining: 0,
        },
        Some(limit) => {
            let state = get_region_state(env, region).unwrap_or_else(|| RegionState::fresh(now));
            let in_window = now.saturating_sub(state.quota_window_start) < limit.quota_window_secs;
            let used = if in_window { state.quota_amount } else { 0 };
            let quota_remaining = (limit.max_amount_per_window - used).max(0);
            let breaker_active = breaker_active_at(&limit, &state, now);
            RegionStatus {
                region: region.clone(),
                configured: true,
                limit,
                state,
                breaker_active,
                quota_remaining,
            }
        }
    }
}

/// Manually clear a latched breaker and restart the velocity window.
/// Idempotent: resetting a closed breaker is a no-op success. Caller gates on
/// admin. [`Error::NotFound`] when the region was never configured.
pub fn reset_breaker(env: &Env, region: &Symbol) -> Result<(), Error> {
    if get_region_limit(env, region).is_none() {
        return Err(Error::NotFound);
    }
    let now = env.ledger().timestamp();
    let mut state = get_region_state(env, region).unwrap_or_else(|| RegionState::fresh(now));
    state.breaker_tripped_at = 0;
    state.vel_window_start = now;
    state.vel_ops = 0;
    persistent_set(env, &state_key(region), &state);
    Ok(())
}

/// Manually latch the breaker for a region (operator "big red button").
/// Caller gates on admin. [`Error::NotFound`] when unconfigured.
pub fn trip_breaker(env: &Env, region: &Symbol) -> Result<(), Error> {
    if get_region_limit(env, region).is_none() {
        return Err(Error::NotFound);
    }
    let now = env.ledger().timestamp();
    let mut state = get_region_state(env, region).unwrap_or_else(|| RegionState::fresh(now));
    state.breaker_tripped_at = now;
    persistent_set(env, &state_key(region), &state);
    Ok(())
}

#[cfg(test)]
mod tests;

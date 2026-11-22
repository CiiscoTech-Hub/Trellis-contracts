//! # Recurring Pull-Authorization with Spend Ceiling
//!
//! Production-grade recurring pull payment primitives for the Trellis Soroban suite.
//!
//! ## Key Capabilities
//! - **Recurring Pull Authorizations**: Payer grants recurring pull rights to Payee.
//! - **Per-Period Limit (`amount_per_period`)**: Enforces non-cumulative interval caps.
//! - **Lifetime Spend Ceiling (`total_spend_ceiling`)**: Hard cap across all periods.
//! - **Deterministic Window Roll-Forward**: Auto-advances interval windows without accumulating unused budget.
//! - **Lifecycle Controls**: Active, Paused, and Revoked states with caller authorization verification.
//! - **Complexity**: $O(1)$ execution time, $O(1)$ storage footprint.

use soroban_sdk::{contracterror, contracttype, Address};

// ── Error taxonomy ─────────────────────────────────────────────────────────────

#[contracterror(export = false)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RecurringPaymentError {
    /// Caller is not authorized for this operation.
    Unauthorized = 721,
    /// The specified recurring authorization was not found.
    NotFound = 722,
    /// Pull amount or period allowance must be strictly positive.
    InvalidAmount = 723,
    /// Period duration must be strictly positive.
    InvalidPeriod = 724,
    /// Spend ceiling cannot be less than per-period allowance or less than total spent.
    InvalidCeiling = 725,
    /// The authorization has expired.
    AuthorizationExpired = 726,
    /// The authorization is paused and cannot execute pulls.
    AuthorizationPaused = 727,
    /// The authorization has been revoked and is permanently inactive.
    AuthorizationRevoked = 728,
    /// Pull amount exceeds the remaining lifetime spend ceiling.
    SpendCeilingExceeded = 729,
    /// Pull amount exceeds the remaining allowance for the current period.
    PeriodAllowanceExceeded = 730,
    /// Payer and payee addresses cannot be identical.
    PayerCannotEqualPayee = 731,
    /// Arithmetic overflow occurred during balance or ceiling calculation.
    ArithmeticOverflow = 732,
    /// New spend ceiling is lower than the amount already spent.
    CeilingBelowSpent = 733,
}

// ── Status enum ────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RecurringPullStatus {
    Active = 0,
    Paused = 1,
    Revoked = 2,
}

// ── Data structures ────────────────────────────────────────────────────────────

/// Represents a recurring pull authorization granting a payee permission to pull funds.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecurringPullAuth {
    /// Unique identifier for this authorization.
    pub id: u64,
    /// Account from which funds are pulled.
    pub payer: Address,
    /// Authorized recipient of the pulled funds.
    pub payee: Address,
    /// Token contract address.
    pub token: Address,
    /// Maximum allowable pull per recurring period.
    pub amount_per_period: i128,
    /// Duration of each period in ledgers or seconds.
    pub period_duration: u64,
    /// Lifetime maximum pull allowed across all periods combined.
    pub total_spend_ceiling: i128,
    /// Cumulative amount successfully pulled to date.
    pub total_spent: i128,
    /// Ledger/timestamp when the current period began.
    pub current_period_start: u64,
    /// Amount pulled within the current period.
    pub current_period_spent: i128,
    /// Current lifecycle status (Active, Paused, Revoked).
    pub status: RecurringPullStatus,
    /// Timestamp/ledger of authorization creation.
    pub created_at: u64,
    /// Timestamp/ledger of the most recent pull.
    pub last_pull_timestamp: u64,
    /// Expiration timestamp/ledger (0 indicates no expiration).
    pub expires_at: u64,
}

/// Execution receipt returned on successful pull.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecurringPullExecutionResult {
    pub auth_id: u64,
    pub pulled_amount: i128,
    pub total_spent: i128,
    pub remaining_ceiling: i128,
    pub period_spent: i128,
    pub remaining_period_allowance: i128,
    pub timestamp: u64,
}

// ── Core Operations ────────────────────────────────────────────────────────────

/// Creates a new recurring pull authorization after strict parameter validation.
pub fn create_recurring_authorization(
    id: u64,
    payer: Address,
    payee: Address,
    token: Address,
    amount_per_period: i128,
    period_duration: u64,
    total_spend_ceiling: i128,
    expires_at: u64,
    current_time: u64,
) -> Result<RecurringPullAuth, RecurringPaymentError> {
    if payer == payee {
        return Err(RecurringPaymentError::PayerCannotEqualPayee);
    }
    if amount_per_period <= 0 {
        return Err(RecurringPaymentError::InvalidAmount);
    }
    if period_duration == 0 {
        return Err(RecurringPaymentError::InvalidPeriod);
    }
    if total_spend_ceiling < amount_per_period {
        return Err(RecurringPaymentError::InvalidCeiling);
    }
    if expires_at > 0 && expires_at <= current_time {
        return Err(RecurringPaymentError::AuthorizationExpired);
    }

    Ok(RecurringPullAuth {
        id,
        payer,
        payee,
        token,
        amount_per_period,
        period_duration,
        total_spend_ceiling,
        total_spent: 0,
        current_period_start: current_time,
        current_period_spent: 0,
        status: RecurringPullStatus::Active,
        created_at: current_time,
        last_pull_timestamp: 0,
        expires_at,
    })
}

/// Executes a pull against the recurring authorization.
///
/// Handles non-cumulative interval window roll-forwards, spend ceiling checks,
/// and authorization state validations in $O(1)$ time and $O(1)$ space.
pub fn execute_recurring_pull(
    auth: &mut RecurringPullAuth,
    pull_amount: i128,
    current_time: u64,
) -> Result<RecurringPullExecutionResult, RecurringPaymentError> {
    if pull_amount <= 0 {
        return Err(RecurringPaymentError::InvalidAmount);
    }

    match auth.status {
        RecurringPullStatus::Active => {}
        RecurringPullStatus::Paused => return Err(RecurringPaymentError::AuthorizationPaused),
        RecurringPullStatus::Revoked => return Err(RecurringPaymentError::AuthorizationRevoked),
    }

    if auth.expires_at > 0 && current_time >= auth.expires_at {
        return Err(RecurringPaymentError::AuthorizationExpired);
    }

    // 1. Advance period window if current time has moved past current period
    let elapsed = current_time.saturating_sub(auth.current_period_start);
    if elapsed >= auth.period_duration {
        let periods_passed = elapsed / auth.period_duration;
        let shift = periods_passed.checked_mul(auth.period_duration)
            .ok_or(RecurringPaymentError::ArithmeticOverflow)?;
        auth.current_period_start = auth.current_period_start.checked_add(shift)
            .ok_or(RecurringPaymentError::ArithmeticOverflow)?;
        // Non-cumulative rollover: past unused allowance is reset
        auth.current_period_spent = 0;
    }

    // 2. Check remaining period allowance
    let new_period_spent = auth.current_period_spent.checked_add(pull_amount)
        .ok_or(RecurringPaymentError::ArithmeticOverflow)?;
    if new_period_spent > auth.amount_per_period {
        return Err(RecurringPaymentError::PeriodAllowanceExceeded);
    }

    // 3. Check remaining lifetime spend ceiling
    let new_total_spent = auth.total_spent.checked_add(pull_amount)
        .ok_or(RecurringPaymentError::ArithmeticOverflow)?;
    if new_total_spent > auth.total_spend_ceiling {
        return Err(RecurringPaymentError::SpendCeilingExceeded);
    }

    // 4. Commit state updates (Checks-Effects)
    auth.current_period_spent = new_period_spent;
    auth.total_spent = new_total_spent;
    auth.last_pull_timestamp = current_time;

    let remaining_ceiling = auth.total_spend_ceiling - auth.total_spent;
    let remaining_period_allowance = auth.amount_per_period - auth.current_period_spent;

    Ok(RecurringPullExecutionResult {
        auth_id: auth.id,
        pulled_amount: pull_amount,
        total_spent: auth.total_spent,
        remaining_ceiling,
        period_spent: auth.current_period_spent,
        remaining_period_allowance,
        timestamp: current_time,
    })
}

/// Pauses an active authorization.
pub fn pause_recurring_authorization(
    auth: &mut RecurringPullAuth,
    caller: &Address,
) -> Result<(), RecurringPaymentError> {
    if auth.payer != *caller {
        return Err(RecurringPaymentError::Unauthorized);
    }
    if auth.status == RecurringPullStatus::Revoked {
        return Err(RecurringPaymentError::AuthorizationRevoked);
    }
    auth.status = RecurringPullStatus::Paused;
    Ok(())
}

/// Resumes a paused authorization.
pub fn resume_recurring_authorization(
    auth: &mut RecurringPullAuth,
    caller: &Address,
    current_time: u64,
) -> Result<(), RecurringPaymentError> {
    if auth.payer != *caller {
        return Err(RecurringPaymentError::Unauthorized);
    }
    if auth.status == RecurringPullStatus::Revoked {
        return Err(RecurringPaymentError::AuthorizationRevoked);
    }
    if auth.expires_at > 0 && current_time >= auth.expires_at {
        return Err(RecurringPaymentError::AuthorizationExpired);
    }
    if auth.total_spent >= auth.total_spend_ceiling {
        return Err(RecurringPaymentError::SpendCeilingExceeded);
    }
    auth.status = RecurringPullStatus::Active;
    Ok(())
}

/// Permanently revokes an authorization.
pub fn revoke_recurring_authorization(
    auth: &mut RecurringPullAuth,
    caller: &Address,
) -> Result<(), RecurringPaymentError> {
    if auth.payer != *caller {
        return Err(RecurringPaymentError::Unauthorized);
    }
    auth.status = RecurringPullStatus::Revoked;
    Ok(())
}

/// Updates the lifetime spend ceiling.
///
/// New ceiling cannot be set below the amount already pulled.
pub fn update_spend_ceiling(
    auth: &mut RecurringPullAuth,
    caller: &Address,
    new_ceiling: i128,
) -> Result<(), RecurringPaymentError> {
    if auth.payer != *caller {
        return Err(RecurringPaymentError::Unauthorized);
    }
    if auth.status == RecurringPullStatus::Revoked {
        return Err(RecurringPaymentError::AuthorizationRevoked);
    }
    if new_ceiling < auth.total_spent {
        return Err(RecurringPaymentError::CeilingBelowSpent);
    }
    if new_ceiling < auth.amount_per_period {
        return Err(RecurringPaymentError::InvalidCeiling);
    }
    auth.total_spend_ceiling = new_ceiling;
    Ok(())
}

/// Computes current remaining allowances in $O(1)$ time without mutating state.
pub fn get_remaining_budgets(auth: &RecurringPullAuth, current_time: u64) -> (i128, i128) {
    let remaining_lifetime = (auth.total_spend_ceiling - auth.total_spent).max(0);

    let elapsed = current_time.saturating_sub(auth.current_period_start);
    let remaining_period = if elapsed >= auth.period_duration {
        // Interval has rolled over
        auth.amount_per_period.min(remaining_lifetime)
    } else {
        (auth.amount_per_period - auth.current_period_spent).max(0).min(remaining_lifetime)
    };

    (remaining_period, remaining_lifetime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env};

    #[test]
    fn test_normal_recurring_pull_flow() {
        let env = Env::default();
        let payer = Address::generate(&env);
        let payee = Address::generate(&env);
        let token = Address::generate(&env);

        let mut auth = create_recurring_authorization(
            1,
            payer.clone(),
            payee.clone(),
            token.clone(),
            100,  // amount_per_period
            10,   // period_duration
            500,  // total_spend_ceiling
            0,    // no expiration
            1000, // current_time
        ).unwrap();

        assert_eq!(auth.status, RecurringPullStatus::Active);

        // Pull 60 in period 1
        let res1 = execute_recurring_pull(&mut auth, 60, 1002).unwrap();
        assert_eq!(res1.pulled_amount, 60);
        assert_eq!(res1.total_spent, 60);
        assert_eq!(res1.remaining_ceiling, 440);
        assert_eq!(res1.period_spent, 60);
        assert_eq!(res1.remaining_period_allowance, 40);

        // Pull remaining 40 in period 1
        let res2 = execute_recurring_pull(&mut auth, 40, 1005).unwrap();
        assert_eq!(res2.pulled_amount, 40);
        assert_eq!(res2.total_spent, 100);
        assert_eq!(res2.remaining_period_allowance, 0);

        // Pulling more in period 1 fails
        let err1 = execute_recurring_pull(&mut auth, 10, 1008);
        assert_eq!(err1, Err(RecurringPaymentError::PeriodAllowanceExceeded));

        // Advance to next period (time 1012 >= 1000 + 10)
        let res3 = execute_recurring_pull(&mut auth, 80, 1012).unwrap();
        assert_eq!(res3.pulled_amount, 80);
        assert_eq!(res3.total_spent, 180);
        assert_eq!(res3.period_spent, 80);
        assert_eq!(res3.remaining_period_allowance, 20);
    }

    #[test]
    fn test_spend_ceiling_enforcement_and_retry() {
        let env = Env::default();
        let payer = Address::generate(&env);
        let payee = Address::generate(&env);
        let token = Address::generate(&env);

        let mut auth = create_recurring_authorization(
            2,
            payer.clone(),
            payee.clone(),
            token.clone(),
            100,
            10,
            150, // Ceiling is 150
            0,
            1000,
        ).unwrap();

        // Pull 100 in period 1
        execute_recurring_pull(&mut auth, 100, 1001).unwrap();

        // Advance to period 2: Payee tries to pull 100, but ceiling has only 50 left
        let err = execute_recurring_pull(&mut auth, 100, 1011);
        assert_eq!(err, Err(RecurringPaymentError::SpendCeilingExceeded));

        // State was not modified on failure (rollback/safety)
        assert_eq!(auth.total_spent, 100);

        // Retry with remaining ceiling of 50 -> succeeds
        let retry_res = execute_recurring_pull(&mut auth, 50, 1011).unwrap();
        assert_eq!(retry_res.pulled_amount, 50);
        assert_eq!(retry_res.total_spent, 150);
        assert_eq!(retry_res.remaining_ceiling, 0);

        // Any subsequent pull fails with ceiling exceeded
        let err_sub = execute_recurring_pull(&mut auth, 1, 1025);
        assert_eq!(err_sub, Err(RecurringPaymentError::SpendCeilingExceeded));
    }

    #[test]
    fn test_pause_resume_revoke_lifecycle_and_auth() {
        let env = Env::default();
        let payer = Address::generate(&env);
        let payee = Address::generate(&env);
        let rogue = Address::generate(&env);
        let token = Address::generate(&env);

        let mut auth = create_recurring_authorization(
            3,
            payer.clone(),
            payee.clone(),
            token.clone(),
            100,
            10,
            1000,
            0,
            1000,
        ).unwrap();

        // Unauthorized actor cannot pause
        assert_eq!(
            pause_recurring_authorization(&mut auth, &rogue),
            Err(RecurringPaymentError::Unauthorized)
        );

        // Payer pauses
        pause_recurring_authorization(&mut auth, &payer).unwrap();
        assert_eq!(auth.status, RecurringPullStatus::Paused);

        // Pull rejected while paused
        let err_pause = execute_recurring_pull(&mut auth, 50, 1002);
        assert_eq!(err_pause, Err(RecurringPaymentError::AuthorizationPaused));

        // Payer resumes
        resume_recurring_authorization(&mut auth, &payer, 1003).unwrap();
        assert_eq!(auth.status, RecurringPullStatus::Active);

        // Pull succeeds after resume
        let res = execute_recurring_pull(&mut auth, 50, 1003).unwrap();
        assert_eq!(res.pulled_amount, 50);

        // Payer revokes
        revoke_recurring_authorization(&mut auth, &payer).unwrap();
        assert_eq!(auth.status, RecurringPullStatus::Revoked);

        // Pull rejected after revocation
        assert_eq!(
            execute_recurring_pull(&mut auth, 10, 1004),
            Err(RecurringPaymentError::AuthorizationRevoked)
        );

        // Revoked authorization cannot be resumed
        assert_eq!(
            resume_recurring_authorization(&mut auth, &payer, 1005),
            Err(RecurringPaymentError::AuthorizationRevoked)
        );
    }

    #[test]
    fn test_spend_ceiling_adjustment() {
        let env = Env::default();
        let payer = Address::generate(&env);
        let payee = Address::generate(&env);
        let token = Address::generate(&env);

        let mut auth = create_recurring_authorization(
            4,
            payer.clone(),
            payee.clone(),
            token.clone(),
            100,
            10,
            200,
            0,
            1000,
        ).unwrap();

        execute_recurring_pull(&mut auth, 100, 1001).unwrap();

        // Cannot decrease ceiling below spent amount
        assert_eq!(
            update_spend_ceiling(&mut auth, &payer, 80),
            Err(RecurringPaymentError::CeilingBelowSpent)
        );

        // Increase ceiling to 500
        update_spend_ceiling(&mut auth, &payer, 500).unwrap();
        assert_eq!(auth.total_spend_ceiling, 500);

        let (rem_period, rem_total) = get_remaining_budgets(&auth, 1002);
        assert_eq!(rem_period, 0); // period spent 100 / 100
        assert_eq!(rem_total, 400); // 500 - 100
    }
}

# Payments Recurring Pull-Authorization with Spend Ceiling (#544)

## Overview

The Recurring Pull-Authorization module (`shared::recurring_payments`) enables subscription, recurring invoicing, and periodic pull payment models on Stellar/Soroban with strict payer protections:

1. **Recurring Interval Caps (`amount_per_period`)**:
   - Caps the maximum withdrawal within any single period window.
   - Non-cumulative: unused allowance in period $N$ does not roll over to period $N+1$, preventing surprise accumulated multi-period withdrawals.
2. **Cumulative Spend Ceiling (`total_spend_ceiling`)**:
   - Absolute lifetime cap across all periods combined.
   - Once total withdrawals reach the spend ceiling, all subsequent pull attempts are blocked.
3. **Payer Lifecycle Management**:
   - `pause_recurring_authorization`: Payer temporarily freezes pulls.
   - `resume_recurring_authorization`: Payer reactivates a paused schedule.
   - `revoke_recurring_authorization`: Permanently terminates the authorization.
   - `update_spend_ceiling`: Payer adjusts the lifetime cap (cannot set ceiling below amount already pulled).

## Flow of Funds & Execution

```text
1. Payer calls create_recurring_authorization()
   - Sets: payee, token, amount_per_period, period_duration, total_spend_ceiling, expires_at

2. Payee calls execute_recurring_pull(pull_amount)
   - Checks:
     a) Status == Active
     b) Current time < expires_at
     c) If period elapsed -> auto-advances current_period_start and resets current_period_spent
     d) current_period_spent + pull_amount <= amount_per_period
     e) total_spent + pull_amount <= total_spend_ceiling
   - Commits state updates and emits execution receipt
```

## Algorithmic Complexity

- **Time Complexity**: $O(1)$ constant time arithmetic and state checks.
- **Space Complexity**: $O(1)$ fixed-size Soroban storage record.

## Edge Cases and Recovery

- **Partial Remaining Allowance**: If a payee requests more than remaining period allowance, `PeriodAllowanceExceeded` is returned; payee can immediately retry with the exact remaining allowance.
- **Transient Exceedances & Ceiling Exhaustion**: Payee retry with an amount $\le$ remaining ceiling succeeds.
- **Rollback Behavior**: Validation runs prior to token transfer or state commit (Checks-Effects-Interactions); rejected pulls cause no balance or status changes.

# Multi-Asset Treasury Reserve Floor and Auto-Pause Guard (#520)

## Overview

The Multi-Asset Treasury Reserve Floor and Auto-Pause Guard module (`shared::treasury_floor`) enforces balance protection invariants for all assets held within protocol reserves:

1. **Multi-Asset Reserve Floor (`min_reserve_floor`)**:
   - Each token/asset managed by the Treasury can be assigned an independent minimum reserve balance floor.
   - Outflows that would cause the reserve balance to dip below this floor are strictly blocked.
   - Preserves protocol solvency and emergency liquidity.

2. **Auto-Pause Guard (`ReserveAutoPauseState`)**:
   - If an outflow or severe variance attempts to breach the reserve floor, the auto-pause guard automatically trips (`is_paused = true`).
   - While paused, all further sensitive withdrawals and transfers of that asset are completely halted with `ReserveAutoPaused` (code 144).
   - Prevents cascading drainage or race-condition exploit attacks.

3. **Replenishment Invariant**:
   - The auto-pause guard cannot be unpaused by administrators unless the asset's reserve balance has been replenished back above the floor level (`current_balance >= floor`), ensuring the underlying deficit is resolved before operations resume.

---

## Architecture & State Machine

```text
Outflow Request (amount)
         │
         ▼
[ Auto-Pause State Check ] ── (is_paused == true) ──► Fail: ReserveAutoPaused (144)
         │ Not Paused
         ▼
[ Compute Post-Balance ] ── (current_balance - amount)
         │
    ┌────┴──────────────────────────┐
    ▼                               ▼
Post >= min_floor               Post < min_floor
    │                               │
    ▼                               ▼
Check Emergency Threshold       Trip Auto-Pause Guard!
    │ (Post <= emergency_threshold)   Set is_paused = true
    ▼                                 Record tripped_amount, floor, actor
Execute Outflow Cleanly               Fail: ReserveFloorBreached (143)
```

---

## Operational Paths

### 1. Normal Path
- Treasury manager or authorized contract requests a withdrawal that leaves `balance >= floor`.
- Evaluator returns `Ok(post_balance)`, balances are updated, and transfers proceed normally.
- Surplus can be queried via `get_reserve_surplus(balance, floor)`.

### 2. Failure Path
- An outflow would cause the reserve to drop below `min_reserve_floor`.
- Evaluator rejects the operation with `TreasuryFloorError::ReserveFloorBreached` and records the breach details in `ReserveAutoPauseState`.
- Any subsequent withdrawal of this asset is rejected with `TreasuryFloorError::ReserveAutoPaused`.

### 3. Retry and Recovery Path
- **Replenishment**: Donors or protocol administrators deposit funds into the reserve to restore balance above the configured floor.
- **Unpause Verification**: Administrator invokes `unpause_reserve_guard`. The invariant check verifies `balance >= floor` and unlocks the reserve guard.
- Normal withdrawals resume safely.

### 4. Authorization Path
- Setting reserve floors and unpausing/pausing guards requires administrative authorization.
- Unauthorized callers attempting configuration or guard resets are rejected with `TreasuryFloorError::Unauthorized`.

---

## Error Taxonomy

| Code | Variant | Description | Remediation |
|---|---|---|---|
| `143` | `ReserveFloorBreached` | Outflow would drop reserve below configured floor | Reduce withdrawal amount or deposit additional reserves |
| `144` | `ReserveAutoPaused` | Reserve is auto-paused due to prior breach | Replenish reserve balance above floor and have admin unpause |
| `145` | `InsufficientSurplus` | Insufficient funds available above reserve floor | Query available surplus before initiating withdrawal |
| `146` | `InvalidFloorAmount` | Negative floor or emergency threshold > floor | Provide valid non-negative floor parameters |
| `147` | `Unauthorized` | Caller lacks administrative role | Authenticate with authorized treasury admin |
| `148` | `ReserveBalanceBelowFloor` | Attempted unpause while balance remains below floor | Deposit additional funds before unpausing |
| `149` | `GuardNotPaused` | Attempted unpause on already active reserve | No action needed; reserve is already active |

---

## Edge Cases and Rollback Behavior

- **Exact Floor Boundary**: Withdrawing down to the exact floor level (`post_balance == min_reserve_floor`) is permitted without error.
- **Zero Floor**: Setting `min_reserve_floor = 0` allows unconstrained withdrawals up to available balance without tripping floor guards.
- **Emergency Force Override**: In critical governance migrations, administrators can pass an explicit force override flag to unpause in exceptional disaster recovery scenarios.

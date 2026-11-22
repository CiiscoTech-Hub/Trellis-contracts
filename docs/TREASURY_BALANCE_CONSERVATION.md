# Treasury Balance Conservation Invariants (Issue #324)

Module: `shared/src/treasury_conservation.rs`

## Invariants

| Id | Invariant | Checked by |
|----|-----------|------------|
| I1 | `Σ categories + allocated == total_inflow − total_outflow` | `check_state` |
| I2 | every category balance and `allocated` is ≥ 0 | `check_state` |
| I3 | `total_inflow` and `total_outflow` never decrease | `check_transition` |
| I4 | a rejected or duplicate op leaves the state byte-for-byte unchanged | property test |
| I5 | `Σ categories` equals the token balance held by the contract | `check_external_balance` |

## Modelled operations

| Op | Effect | Who |
|----|--------|-----|
| `Deposit` | category += a, inflow += a | anyone (`require_auth`) |
| `Harvest` | category += a, inflow += a | manager/admin |
| `Withdraw` | category −= a, outflow += a | manager/admin |
| `EmergencyWithdraw` | category −= a, outflow += a | admin only |
| `Transfer` | from −= a, to += a | manager/admin |
| `Allocate` | category −= a, allocated += a | manager/admin |
| `Recall` | allocated −= a, category += a | manager/admin |

`transition` is pure and checks everything before it writes anything. A failed
op therefore can never leave a partial update, even without transaction
rollback.

## Tests

`property_conservation_holds_for_random_sequences` runs 5 fixed seeds × 300
steps through a deterministic xorshift generator. The steps mix:

- valid ops of every kind
- zero, negative and `i128::MAX` amounts (`InvalidAmount`, `Overflow`)
- overdraws (`InsufficientBalance`, `InsufficientAllocation`)
- outsider and manager-on-emergency calls (`Unauthorized`)
- exact retries of applied ops (`Duplicate`) and same-id/different-payload
  resubmissions (`OpIdConflict`)

After every step it asserts I1–I4. At the end it replays the accepted ops on a
fresh ledger and checks that the totals come out identical. Each seed must hit
every outcome class, so the test fails if the generator stops covering one.
Targeted tests cover the normal lifecycle with reconciliation (I5), every
failure path, idempotent retries, authorization, a missing signature (panics),
and detection of hand-corrupted states.

## Recovery and rollback

- **Retry**: resubmitting an applied `op_id` returns `Duplicate` and changes
  nothing. A failed op does not record its `op_id`, so the caller can correct
  it and resubmit with the same id.
- **Conflict**: reusing an `op_id` with a different payload returns
  `OpIdConflict`. Use a new id.
- **Breach detected** (I1/I2/I5 fails during reconciliation): pause the
  treasury contract to stop further outflows, export the state
  and the `trs_op` events, and recompute with `transition` from the event log.
  The replay test shows this recomputation is deterministic.
- **No rollback entrypoint by design.** You correct a mistake with a
  compensating op (for example a `Deposit` that offsets a mistaken `Withdraw`),
  so the history stays append-only.

## Migration plan

This change only adds a new module. `contracts/treasury-contract` is not
modified, and its existing `invariants_test.rs` still applies. To adopt it,
the treasury entrypoints call `apply_op` with their own operation id. Seed the
ledger once with a single `Deposit` per category equal to its current balance,
then check `check_external_balance` against the token balance before turning
the checks on.

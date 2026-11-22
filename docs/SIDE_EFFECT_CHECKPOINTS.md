# Recovery Checkpoints Around External Side Effects (Issue #275)

## Overview

`shared::side_effect_checkpoint` wraps every individual external side effect (`TokenTransfer`, `CrossContractCall`, `WebhookDispatch`, `OraclePublish`, `SettlementPayout`) in a deterministic pre-effect / post-effect checkpoint (`SideEffectCheckpoint`) so retried or interrupted operations never duplicate an already-committed external call.

## State Machine

```text
  begin_side_effect() -> Prepared --(commit_side_effect)--> Committed (terminal; retries return AlreadyCommitted)
                            |
                     (fail_side_effect)
                            v
                          Failed --(begin_side_effect)--> Prepared (Retry, up to DEFAULT_MAX_EFFECT_RETRIES)
                            |
                    (rollback_side_effect by admin)
                            v
                        RolledBack (terminal; further begins return Error::AlreadyExecuted)
```

Each `effect_id` is deterministically derived from `(contract_address, op_id, step_index, kind, target, payload_hash)` using canonical Soroban XDR SHA-256 (`derive_effect_id`).

## Operational Edge Cases

1. **Duplicate invocation after commit:** Calling `begin_side_effect` for an already-`Committed` `effect_id` returns `Ok(BeginEffectOutcome::AlreadyCommitted(cp))`. Callers must short-circuit and skip the external call.
2. **Interrupted `Prepared` state:** If a previous attempt left the checkpoint in `Prepared` without committing or failing, `begin_side_effect` returns `BeginEffectOutcome::Retry(cp)` and increments `attempts`. The same operation id, step, kind, target, payload hash, and contract address must be reused to find that checkpoint.
3. **Retry exhaustion:** Once `attempts >= DEFAULT_MAX_EFFECT_RETRIES` (5), `begin_side_effect` returns `Err(Error::QuotaExceeded)`.
4. **Zero error code:** `fail_side_effect` rejects `error_code == 0` with `Err(Error::InvalidArgument)`.
5. **Actor isolation:** Only the originating `actor` can retry, commit, or fail a checkpoint (`Error::Unauthorized` otherwise).

## Verification

Run the focused automated tests with:

```bash
cargo test -p shared side_effect_checkpoint
```

The tests cover first execution and commit, an interruption after persisting `Prepared`, deterministic resume of that checkpoint, failure and retry, retry exhaustion, actor/admin authorization, rollback, and the post-commit `AlreadyCommitted` short-circuit.

## Recovery and Rollback Behavior

- **Transient external failure:** Call `fail_side_effect(&env, &actor, &effect_id, err_code)`, then retry via `begin_side_effect`.
- **Permanent failure / manual compensation:** An administrator calls `rollback_side_effect(&env, &admin, &effect_id, reason)` from `Prepared` or `Failed` to transition to `RolledBack`, permanently blocking future retries of that `effect_id`. This records a terminal rollback decision; it does not itself reverse an external action.
- **Already committed:** `rollback_side_effect` rejects `Committed` checkpoints with `Err(Error::AlreadyExecuted)`; compensation for a committed external effect must be issued as a new compensating operation with a fresh `op_id`.
- **External action succeeded but commit was interrupted:** The checkpoint may still be `Prepared`, so a retry can invoke the action again. Use `effect_id` as the downstream idempotency key (or reconcile the external system before retrying) to prevent a duplicate effect across this unavoidable cross-system interruption window. Checkpoint state alone cannot atomically commit both contract storage and an external system.

## Contract Preservation

`shared::side_effect_checkpoint` is an additive module alongside `shared::recovery` and `shared::external_evidence`. No existing contract interfaces or storage keys are modified.

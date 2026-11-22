# Synthetic Monitoring for Critical Workflows (Issue #499)

Module: `shared/src/workflow_synthetic_monitor.rs`

## What it does

Provides continuous, contract-visible synthetic probes for Trellis's core multi-stage user and protocol journeys:
1. **Aid Disbursement Journey**: Config reachability -> Reserve allocation -> Oracle price verification -> Claim disbursement simulation -> Audit receipt logging.
2. **Treasury Rebalance Journey**: Threshold breach trigger -> Rate evaluation -> Slippage preflight -> Swap execution simulation -> Invariant conservation.
3. **Governance Timelock Journey**: Proposal submission -> Quorum validation -> Timelock progression -> Execution gate check -> Target contract state validation.
4. **Escrow Settlement Journey**: Deposit lock -> Milestone condition evaluation -> Multi-signer verification -> Release disbursement -> Receipt archival.

Probes exercise simulated execution paths in read-only / simulation environments, capturing granular stage-by-stage diagnostics without generating accidental financial side effects on-chain.

## Workflow Lifecycle

| Step | Operation | Authorization | Result |
|------|-----------|---------------|--------|
| Configuration | `set_workflow_config` | Admin | Sets enabled status, timeout, and max retry limits |
| Execution | `run_synthetic_probe` | Operator / Admin | Runs all stages, emits event, records diagnostic report |
| Resumption/Retry | `retry_synthetic_probe` | Operator / Admin | Re-evaluates failed workflow idempotently with incremented retry counter |
| Query | `get_latest_probe_report` | Public | Returns current execution health status and stage breakdown |

## Failure, Retry, and Authorization Paths

- **Normal Path**: All stages of the workflow execute sequentially and report `ProbeStageStatus::Passed`. The overall status evaluates to `WorkflowHealthStatus::Healthy`, and results are persisted in contract instance storage.
- **Failure Path**: When a stage fails (e.g., stale oracle quote, reserve shortage, or unmet precondition), that stage is marked `Failed` with an explicit diagnostic error code. All downstream dependent stages are marked `Skipped`, preventing cascading false failures. The report is classified as `Degraded` or `Failing`.
- **Retry Path**: A failed probe can be retried using its correlation ID. The monitor tracks `retry_count`. If `retry_count` reaches `max_retries` (configured up to 10), further retries are rejected with `WorkflowMonitorError::RetryLimitExceeded`.
- **Authorization Path**: Privileged actions (`set_workflow_config`, `run_synthetic_probe`, `retry_synthetic_probe`) require valid authorization from the designated operator address or protocol admin. Unprivileged callers are rejected with `WorkflowMonitorError::Unauthorized`.

## Operational Edge Cases

- **Simulated vs. Live Execution**: Synthetic probes run in simulated sandboxes and do not debit live liquidity pools or transfer donor tokens.
- **Workflow Disabled**: If an operator suspends monitoring via `config.enabled = false`, probe attempts immediately halt with `WorkflowDisabled`.
- **Correlation ID Consistency**: Retrying a synthetic probe requires supplying the matching `correlation_id` from the initial run to prevent state race conditions.

## Recovery and Rollback Behavior

- If a synthetic probe reveals systemic degradation (e.g., Oracle or Reserve failures), automated alert keepers can trigger circuit breakers or degraded mode via `shared/src/dependency_aware_health.rs`.
- Probes write only to instance diagnostic storage; rollback of underlying contracts is not required as probe simulations do not mutate business ledger state.

## Migration Plan

1. Deploy the updated `shared` library.
2. Call `set_workflow_config` for each critical workflow kind (`AidDisbursement`, `TreasuryRebalance`, `GovernanceTimelock`, `EscrowSettlement`).
3. Wire monitoring bots or keepers to run `run_synthetic_probe` on scheduled intervals (e.g., every 500 ledgers).

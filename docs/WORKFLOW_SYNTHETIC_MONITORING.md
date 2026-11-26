# Synthetic Monitoring for Critical Workflows (#578)

## Overview

The Synthetic Monitoring for Critical Workflows module (`shared::workflow_synthetic_monitor`) provides deterministic, contract-visible synthetic health probes for Trellis's core multi-stage user and protocol journeys:

1. **Aid Disbursement Journey**: Config reachability -> Reserve allocation -> Oracle price verification -> Claim disbursement simulation -> Audit receipt logging.
2. **Treasury Rebalance Journey**: Threshold breach trigger -> Rate evaluation -> Slippage preflight -> Swap execution simulation -> Invariant conservation.
3. **Governance Timelock Journey**: Proposal submission -> Quorum validation -> Timelock progression -> Execution gate check -> Target contract state validation.
4. **Escrow Settlement Journey**: Deposit lock -> Milestone condition evaluation -> Multi-signer verification -> Release disbursement -> Receipt archival.

Probes exercise simulated execution paths in read-only / simulation environments, capturing granular stage-by-stage diagnostics without generating accidental financial side effects on-chain.

---

## Architecture & Lifecycle

```text
Synthetic Probe Trigger (Operator / Keeper)
       │
       ▼
[ Authorization & Config Check ] ── (Disabled) ──► WorkflowMonitorError::WorkflowDisabled
       │ (Authorized & Enabled)
       ▼
[ Stage 1: Precondition / Config ] ── (Fail) ──► Mark Stage Failed, Skip Downstream
       │ (Pass)
       ▼
[ Stage 2: Rate / Reserve Check ] ── (Fail) ──► Mark Stage Failed, Skip Downstream
       │ (Pass)
       ▼
[ Stage 3: Execution Simulation ] ── (Fail) ──► Mark Stage Failed, Skip Downstream
       │ (Pass)
       ▼
[ Commit Diagnostic Report ] ──► Healthy / Degraded / Failing
```

### Workflow Operations Matrix

| Step | Operation | Authorization | Result |
|------|-----------|---------------|--------|
| Configuration | `set_workflow_config` | Admin | Sets enabled status, timeout, and max retry limits |
| Execution | `run_synthetic_probe` | Operator / Admin | Runs all stages, emits event, records diagnostic report |
| Resumption/Retry | `retry_synthetic_probe` | Operator / Admin | Re-evaluates failed workflow idempotently with incremented retry counter |
| Query | `get_latest_probe_report` | Public | Returns current execution health status and stage breakdown |

---

## Operational Execution Paths

### 1. Normal Path
- All stages of the workflow execute sequentially and report `ProbeStageStatus::Passed`.
- Overall status evaluates to `WorkflowHealthStatus::Healthy`.
- Results and execution metrics are persisted in contract instance storage and published as an event.

### 2. Failure Path
- When a stage fails (e.g., stale oracle quote, reserve shortage, or unmet precondition):
  - That specific stage is marked `ProbeStageStatus::Failed` with an explicit diagnostic error code.
  - All subsequent downstream stages are marked `ProbeStageStatus::Skipped`, preventing cascading false alarms.
  - Overall health evaluates to `WorkflowHealthStatus::Degraded` or `WorkflowHealthStatus::Failing`.

### 3. Retry Path
- A failed probe can be retried using its unique `correlation_id`.
- The monitor increments `retry_count` monotonically.
- If `retry_count` reaches `max_retries` (default: 3, max: 10), further retries are rejected with `WorkflowMonitorError::RetryLimitExceeded`.
- Retrying an already passed workflow returns the existing passed report without re-executing.

### 4. Authorization Path
- Privileged operations (`set_workflow_config`, `run_synthetic_probe`, `retry_synthetic_probe`) require valid authorization from the designated operator address or protocol admin.
- Unprivileged callers are rejected with `WorkflowMonitorError::Unauthorized`.

---

## Edge Cases, Recovery, and Rollback Behavior

- **Simulated vs. Live Execution**: Synthetic probes run in simulated sandboxes and do not debit live liquidity pools or transfer donor tokens.
- **Workflow Disabled**: If an operator suspends monitoring via `config.enabled = false`, probe attempts immediately halt with `WorkflowDisabled`.
- **Correlation ID Consistency**: Retrying a synthetic probe requires supplying the matching `correlation_id` from the initial run to prevent state race conditions.
- **Rollback Behavior**: Diagnostic reports write exclusively to instance monitoring storage; no business ledger rollback is necessary because probes do not mutate financial balances.

---

## Compatibility & Migration Plan

1. Deploy the updated `shared` library.
2. Call `set_workflow_config` for each critical workflow kind (`AidDisbursement`, `TreasuryRebalance`, `GovernanceTimelock`, `EscrowSettlement`).
3. Wire monitoring bots or keepers to run `run_synthetic_probe` on scheduled intervals (e.g., every 500 ledgers).
4. All existing contract functions and storage remain 100% backward-compatible.

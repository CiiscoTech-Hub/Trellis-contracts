# Governance Proposal Timelock Cancellation and Veto Quorum (#521)

## Overview

The Governance Proposal Timelock Cancellation and Veto Quorum module (`shared::governance_timelock`) establishes critical safeguards during the execution timelock delay of multi-signature governance proposals:

1. **Timelock Delay & Window**:
   - Approved proposals are queued into an execution timelock (`execution_delay_secs`).
   - The proposal can only execute once the ETA has arrived (`now >= eta`) and before the grace period expires (`now <= eta + grace_period_secs`).

2. **Proposer & Super-Admin Cancellation**:
   - If an error, code flaw, or unintended side-effect is identified during the timelock window, the original proposer or the super-admin can unilaterally cancel the queued proposal (`cancel_queued_timelock`).
   - The proposal transitions to `Cancelled` and execution is permanently disabled.

3. **Collective Veto Quorum**:
   - Protects the protocol against malicious proposer attacks or compromised single keys.
   - Any active multi-sig administrator can cast a **Veto** against a queued proposal (`cast_proposal_veto`).
   - Each admin can only veto once (duplicate vetoes are strictly rejected).
   - Once total unique admin vetoes reach or exceed `veto_quorum`, the proposal transitions to `Vetoed`, immediately clearing its execution schedule and locking it from ever being executed.

---

## Architecture & Timelock Lifecycle

```text
Approved Proposal
       │
       ▼
[ Queue Timelock ] ──► Status: Queued (eta = now + delay)
       │
       ├─────────────────────────────────┬─────────────────────────────────┐
       ▼                                 ▼                                 ▼
[ Delay Elapses ]              [ Admin Casts Veto ]             [ Cancel Request ]
now >= eta                     veto_count += 1                  proposer or super_admin
       │                                 │                                 │
       ▼                                 ▼                                 ▼
Validate Window                Check Quorum                     Status: Cancelled
       │                       (veto_count >= quorum)                      │
       ▼                                 │                                 ▼
Status: Executed               ┌─────────┴─────────┐              Execution Blocked
                               ▼                   ▼
                         Quorum Reached      Pending More
                         Status: Vetoed      Status: Queued
                               │
                               ▼
                        Execution Blocked
```

---

## Operational Paths

### 1. Normal Path
- Proposal approved by multi-sig threshold is queued with ETA.
- The timelock delay passes without objection.
- Administrator calls `validate_timelock_execution`, executes action payload, and sets status to `Executed`.

### 2. Failure Path
- **Premature Execution**: Attempting to execute before the ETA fails with `GovernanceTimelockError::TimelockTooEarly`.
- **Grace Period Expiry**: If a proposal is queued but never executed within the grace period, it expires (`GovernanceTimelockError::TimelockExpired`).
- **Execution of Vetoed Proposal**: Any attempt to execute a vetoed proposal fails with `GovernanceTimelockError::ProposalVetoed`.

### 3. Veto Quorum Path
- Admin 1 casts a veto against suspicious proposal: returns `VetoOutcome::Recorded { current_vetoes: 1, required: 2 }`.
- Admin 2 casts a veto: quorum reached! Returns `VetoOutcome::VetoQuorumReached { total_vetoes: 2 }`.
- Status is immediately set to `Vetoed`.

### 4. Authorization Path
- Only registered active administrators can cast vetoes.
- Non-administrators attempting to veto are rejected with `GovernanceTimelockError::Unauthorized`.
- Only the original proposer or super-admin can cancel a queued proposal directly.

---

## Error Taxonomy

| Code | Variant | Description | Remediation |
|---|---|---|---|
| `650` | `Unauthorized` | Caller lacks admin or proposer authorization | Authenticate with authorized governance key |
| `651` | `ProposalNotQueued` | Proposal is not active in timelock queue | Queue proposal before attempting execution or veto |
| `652` | `TimelockTooEarly` | Execution attempted before ETA delay elapsed | Wait until timelock delay window expires |
| `653` | `TimelockExpired` | Grace period elapsed; proposal is stale | Create a fresh proposal if still required |
| `654` | `AlreadyVetoed` | Caller has already cast a veto on this proposal | Each admin may only cast one veto per proposal |
| `655` | `ProposalAlreadyExecuted` | Proposal was already executed | No further action permitted on terminal proposal |
| `656` | `ProposalAlreadyCancelled` | Proposal was cancelled | No further action permitted on terminal proposal |
| `657` | `InvalidVetoQuorum` | Configured veto quorum is zero | Set veto quorum >= 1 |
| `658` | `ProposalVetoed` | Proposal was killed by veto quorum | Execution permanently disabled |

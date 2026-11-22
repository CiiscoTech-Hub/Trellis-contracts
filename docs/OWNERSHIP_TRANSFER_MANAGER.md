# Multi-Role Ownership Transfer Manager with Delay and Expiry (Issue #494)

Module: `shared/src/ownership_transfer_manager.rs`

## What it does

`ownership_transfer_manager` implements an enterprise-grade, two-step ownership handover engine for protocol contracts. It eliminates accidental reassignments, front-running attacks, and unauthorized takeovers by enforcing:

- **Configurable timelock / delay** (`effective_after`): prevents immediate execution upon proposal, providing a safety window to detect compromised keys or erroneous proposals.
- **Deterministic expiration** (`expires_at`): proposals cannot linger indefinitely; if not accepted within the validity window, they lapse automatically.
- **Explicit target acceptance**: ownership does not change until the designated `target_owner` explicitly signs and submits `accept_ownership_transfer`.
- **Target rejection & Owner cancellation**: owners can cancel active proposals; target owners can explicitly decline nominations without waiting for expiry.
- **Permissionless cleanup**: once expired, any caller can invoke `expire_ownership_transfer` to clear the pending slot.
- **Multi-role support**: supports distinct roles (`SuperAdmin`, `TreasuryAdmin`, `GovernanceAdmin`, `EmergencyAdmin`, and `Custom(Symbol)`).

## Public Surface

| Function | Caller | Description |
|---|---|---|
| `initialize_role_owner(env, role, owner)` | Internal / Init | Seeds the initial owner for a role. |
| `set_transfer_config(env, admin, config)` | SuperAdmin | Configures minimum delay, minimum validity, and maximum validity windows. |
| `propose_ownership_transfer(env, caller, role, target_owner, validity_seconds)` | Role Owner | Initiates a transfer proposal with enforced timelock and expiration. |
| `accept_ownership_transfer(env, caller, role, transfer_id)` | Target Owner | Accepts pending transfer after `effective_after` and before `expires_at`. |
| `cancel_ownership_transfer(env, caller, role, transfer_id)` | Role Owner | Cancels an unaccepted pending proposal. |
| `reject_ownership_transfer(env, caller, role, transfer_id)` | Target Owner | Declines a pending nomination. |
| `expire_ownership_transfer(env, role, transfer_id)` | Anyone | Cleans up an expired proposal. |
| `get_role_owner(env, role)` | Read-only | Returns the current owner address for `role`. |
| `get_pending_proposal(env, role)` | Read-only | Returns active proposal details, if any. |
| `is_proposal_expired(env, role)` | Read-only | Returns boolean indicating expiration status. |
| `time_until_expiry(env, role)` | Read-only | Returns seconds remaining until expiry. |

## Normal, Failure, Retry, and Authorization Paths

- **Normal Path**:
  1. Role owner calls `propose_ownership_transfer(caller, role, target, 1000)`. Status becomes `Pending`.
  2. Ledger advances past `effective_after` (default: created + 300s).
  3. Target owner calls `accept_ownership_transfer(target, role, 1)`.
  4. Role owner is atomically reassigned to `target_owner`, proposal status transitions to `Accepted`, and audit events are emitted.
- **Failure Paths**:
  - `TimelockNotElapsed`: Attempting to accept before `now >= effective_after` is rejected.
  - `TransferExpired`: Attempting to accept after `now > expires_at` is rejected, and status marks `Expired`.
  - `NotPendingOwner`: Any caller other than `target_owner` attempting to accept or reject is rejected.
  - `SelfTransfer`: Proposing transfer to the current owner returns `SelfTransfer`.
  - `InvalidDuration`: Requesting validity shorter than `min_validity_seconds` (600s) or longer than `max_validity_seconds` (604,800s) is rejected.
  - `TransferAlreadyPending`: A new proposal cannot be submitted while an unexpired proposal is already pending.
- **Retry and Recovery Path**:
  - If a proposal is cancelled or rejected, a new proposal can immediately be submitted for that role (`transfer_id` increments).
  - If a proposal expires, calling `expire_ownership_transfer` clears the pending slot and allows a fresh proposal.
- **Authorization Path**:
  - Only the current owner of `role` can propose or cancel transfers.
  - Only designated `target_owner` can accept or reject.
  - Only `SuperAdmin` can modify global configuration parameters.

## Operational Edge Cases

1. **Stale proposal blocking**: If an owner nominated the wrong address and it expires, calling `expire_ownership_transfer` clears the block.
2. **Key loss during timelock**: If the owner loses access during the delay window, the proposal will expire safely without auto-executing, preserving current permissions.
3. **Re-proposing over an expired proposal**: Overwriting or cleaning an expired proposal emits `own_mgr:exp` events for audit visibility.

## Migration and Compatibility Plan

This module is additive and standalone in `shared/src/ownership_transfer_manager.rs`. Existing storage layouts, entrypoints, and contracts remain 100% untouched and compatible.

# Security-Event Session Invalidation Engine (Issue #491)

Module: `shared/src/session_invalidation.rs`

## What it does

`session_invalidation` implements atomic, event-driven session invalidation for operators, relayers, keeper bots, and maintainers across Trellis smart contracts.

When an incident occurs (anomalous withdrawals, suspected key leaks, or emergency protocol lockdown), administrators and designated security officers can invalidate sessions across three granularities:
1. **Actor Invalidation**: Atomically invalidates all sessions held by a compromised operator address via blacklisting.
2. **Scope Epoch Invalidation**: Bumps the epoch for a specific capability domain (e.g. `TreasuryOperations`, `DisbursementWorker`), instantly rendering all existing sessions in that scope invalid without affecting other operations.
3. **Global Security Epoch Invalidation**: Bumps the contract's global security epoch, immediately invalidating all active sessions contract-wide.

## Public Surface

| Function | Caller | Description |
|---|---|---|
| `initialize_session_security(env, admin)` | Initializer | Sets initial security admin and seeds global epoch to 1. |
| `register_security_officer(env, admin, officer)` | Admin | Authorizes an automated security monitor or officer address. |
| `create_session(env, caller, actor, scope, duration)` | Officer / Admin | Issues a new scoped execution session bound to the current epoch. |
| `validate_session(env, session_id)` | Anyone / Pre-flight | Checks that session is active, unexpired, and matches current global and scope epochs. |
| `trigger_security_invalidation(env, caller, event_type, actor, scope, reason)` | Officer / Admin | Triggers targeted or global security session invalidation. |
| `reinstate_actor_after_investigation(env, admin, actor)` | Admin | Clears actor blacklist after incident investigation completes. |
| `revoke_session(env, caller, session_id)` | Officer / Admin | Explicitly terminates a single session by ID. |
| `get_global_epoch(env)` | Read-only | Returns the current global security epoch. |
| `is_actor_blacklisted(env, actor)` | Read-only | Returns whether an actor address is blacklisted. |

## Normal, Failure, Retry, and Authorization Paths

- **Normal Path**:
  1. Authorized security officer calls `create_session(officer, actor, scope, 3600)`. Status is `Active` with `epoch_at_creation`.
  2. Transaction handlers call `validate_session(session_id)`. Returns `Ok(session)`.
- **Failure Paths**:
  - `ActorBlacklisted`: If an actor has been blacklisted following an anomaly, all their sessions immediately fail validation.
  - `SessionInvalidated`: If the scope or global epoch was bumped after session creation (`epoch_at_creation < current_epoch`), validation returns `SessionInvalidated`.
  - `SessionExpired`: Sessions evaluated after `now > expires_at` return `SessionExpired`.
  - `SessionNotFound`: Validating a non-existent session ID returns `SessionNotFound`.
  - `InvalidDuration`: Requesting a session with 0 duration or duration $> 7$ days is rejected.
- **Retry and Recovery Path**:
  - Re-triggering security invalidation for an already-blacklisted actor or already-bumped epoch is safe, idempotent, and non-corrupting.
  - After completing an incident investigation, admin calls `reinstate_actor_after_investigation(admin, actor)`. New sessions can then be created for the actor.
- **Authorization Path**:
  - Only authorized admin or security officers can create sessions, revoke sessions, or trigger security invalidations.
  - Only protocol admin can register security officers and reinstate blacklisted actors.
  - Calls by unauthorized actors return `SessionError::Unauthorized`.

## Operational Edge Cases

1. **Gas-Free Bulk Invalidation**: Individual session storage keys do not need to be updated during an incident. Advancing the global epoch (`u32`) in a single $O(1)$ write invalidates thousands of active sessions simultaneously.
2. **Post-Incident Recovery**: When a single compromised operator is blacklisted, other honest operators continue operating uninterrupted.
3. **Audit Trail**: Every invalidation generates a `SecurityInvalidationReceipt` and emits a `sec_sess:invalid` event recording event type, actor, scope, and reason.

## Migration and Compatibility Plan

Fully additive in `shared/src/session_invalidation.rs`. Preserves all existing contract interfaces and storage entries.

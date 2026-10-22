# Rollback Verification for Failed Initialization Steps

`shared::init_rollback` (Issue #337) gives a multi-contract deployment a
tracked, verified rollback path when one of its initialization steps fails
partway through — something none of the existing safety modules cover.

## Why this is a different problem

A single contract's `initialize` entry point is one atomic Soroban
transaction: it can never leave half-initialized on-chain state by itself.
A **deployment** is not atomic — initializing Treasury, Aid, Referral,
Governance, Oracle, Marketplace, and wiring their cross-contract addresses
is a sequence of separate transactions. If one fails partway through, the
system is left with some contracts initialized and others not. Simply
retrying is dangerous unless an operator can first *prove* that whatever
did get initialized was actually undone — not just marked "failed" in a
tracker and hoped-for.

`shared::recovery` already tracks multi-step operations, but only forward
(resume/abandon) — it has no undo or verification concept.
`shared::migration` and `shared::release_readiness` cover schema migrations
and release gating, not a failed cross-contract bootstrap. None of these
modules change.

## Design in one paragraph

`begin_initialization` records an ordered step list for a deployment `id`.
`complete_init_step` / `fail_init_step` advance it deterministically, the
same way `shared::recovery` tracks its own steps. When a step fails, the
tracker moves to `AwaitingRollback` — the operator then undoes whatever the
completed steps actually did, on each affected contract, outside this
module (it cannot reach into other contracts' storage itself). The operator
re-checks the real state and builds one `InitStepProbe` per step that ran,
and `verify_rollback` reports whether every one of them now shows **not**
initialized — the inverse of
`shared::release_readiness::verify_initialized_addresses`, which checks
that addresses *are* set. `complete_rollback` is the hard gate: it refuses
to mark the tracker `RolledBack` unless handed a passing verification for
the same `id`. A tracker can only reach `RolledBack` through that gate —
never by waiting, retrying, or admin override alone. `begin_initialization`
doubles as the retry path: calling it again for an `id` whose tracker is
`RolledBack` (or `Completed`) starts a fresh attempt with `attempt`
incremented.

## Public surface

| Item | Purpose |
|---|---|
| `begin_initialization` | Start (or retry, after a verified rollback) a tracked sequence. |
| `complete_init_step` / `fail_init_step` | Advance the tracker; a failure moves it to `AwaitingRollback`. |
| `verify_rollback` | Read-only check of operator-supplied probes against the steps that ran. |
| `complete_rollback` | Admin-gated; the only path to `RolledBack`, and only with a passing verification. |
| `get_tracker` | Inspection. |

Re-exported from the crate root as `verify_init_rollback` — the unaliased
`verify_rollback` is already taken by `shared::rollout_guard`.

## Who can do what

| Action | Required role / condition |
|---|---|
| Begin, advance, fail, or complete-rollback a tracker | `Role::Admin`, authenticated |
| Verify a rollback (`verify_rollback`), or read a tracker | Anyone (read-only, no auth required) |

## Operational edge cases

| Situation | Behavior |
|---|---|
| Non-admin calls any mutating entry point | `Error::Unauthorized`, before the tracker is touched. |
| `begin_initialization` while a tracker for `id` is `InProgress` or `AwaitingRollback` | `Error::AlreadyInitialized` — finish or roll back the current attempt first. |
| `begin_initialization` with an empty step list, or steps not `0, 1, 2, …` in order | `Error::InvalidArgument`, before anything is stored. |
| `complete_init_step` / `fail_init_step` with the wrong index, or when the tracker isn't `InProgress` | `Error::InvalidTransition`. |
| `verify_rollback` called when the tracker isn't `AwaitingRollback` | `Error::InvalidTransition` — nothing to verify yet. |
| A probe is missing for a step that ran, or reports `still_initialized: true` | `fully_rolled_back: false`, and `first_not_rolled_back` names the step; a missing probe fails closed (treated as still initialized). |
| `complete_rollback` with a verification for a different `id`, or one that isn't fully rolled back | `Error::InvalidTransition` — the tracker stays `AwaitingRollback`. |
| `begin_initialization` again after a verified `RolledBack` | Succeeds; `attempt` increments so the retry is distinguishable in the event log and the tracker itself. |

## Rollback and recovery

This module *is* the rollback-recovery path, so "recovering" it means:

1. **A step failed mid-deployment.** Call `fail_init_step` to record it
   (`AwaitingRollback`). The operator then manually undoes whatever the
   completed steps actually did, on each affected contract.
2. **Prove the undo worked.** Re-read the real state the completed steps
   touched, build one `InitStepProbe` per step, and call `verify_rollback`.
   If `fully_rolled_back` is `false`, more cleanup is needed at
   `first_not_rolled_back` before retrying verification.
3. **Close out the rollback.** `complete_rollback` with the passing
   verification moves the tracker to `RolledBack`.
4. **Retry the deployment.** `begin_initialization` again with the same
   `id` (typically with a corrected step list or fixed root cause).
   `attempt` on the new tracker shows this is a second try, not a first.

## Compatibility

Purely additive: new storage keys, no changes to `shared::recovery`,
`shared::migration`, `shared::release_readiness`, or any contract interface.
A deployment script or admin tool adopts this by calling
`begin_initialization` before running its own per-contract `initialize`
calls, and `complete_init_step` / `fail_init_step` after each one.

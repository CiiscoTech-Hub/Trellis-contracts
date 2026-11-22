# Governance Quadratic Voting Weight Cap & Delegation Snapshot

This document describes the `governance-quadratic-voting` Soroban contract ([`contracts/governance-quadratic-voting/src/lib.rs`](../contracts/governance-quadratic-voting/src/lib.rs)), which implements a focused vertical slice for quadratic voting weight caps, delegation cycle protection, frozen per-proposal delegation snapshots, idempotent retries, and admin recovery/rollback.

## Overview

| Role | Permitted Operations |
|---|---|
| **Admin** | Initialize contract (`init`), rotate roles (`set_snapshotter`, `transfer_admin`), update `VotingConfig` (`set_config`), cancel proposals (`cancel_proposal`), reset un-voted snapshots (`reset_snapshot`), plus all Snapshotter actions. |
| **Snapshotter** | Update account stakes (`set_stake`), create proposals (`create_proposal`), and record frozen voter snapshots (`record_snapshot`). |
| **Voter / Delegator** | Delegate/undelegate own stake (`delegate`, `undelegate`) and cast votes using their frozen snapshot (`cast_vote`). |

## Quadratic Weight Cap & Delegation Snapshot

1. **Delegation**: When `delegator` delegates to `delegatee`, `delegator`'s stake is credited to `DelegatedIn(delegatee)` and `delegator`'s own direct voting stake becomes `0`. Subsequent `set_stake` updates automatically adjust `DelegatedIn(delegatee)`.
2. **Snapshot**: `record_snapshot(proposal_id, voter)` computes:
   - `raw_power = (own_stake if not delegated else 0) + delegated_in`
   - `quadratic_weight = floor(sqrt(raw_power))` via exact integer square root (`isqrt`)
   - `capped_weight = min(quadratic_weight, config.max_weight_cap)`
3. **Immutability**: Once recorded, a voter's snapshot is frozen for that proposal; post-snapshot stake changes or undelegations do not alter `capped_weight`.

## Edge Cases

- **Direct & indirect delegation cycles**: `delegate` rejects `delegator == delegatee` (`Error::SelfDelegation`) and traverses up to `max_delegation_depth` ancestors to block cycles (`Error::DelegationCycle`), failing closed with `Error::DelegationDepthExceeded` if depth is exceeded.
- **Idempotent retries**:
  - `record_snapshot` returns the existing `VoterSnapshot` if already recorded.
  - `cast_vote` returns the existing `VoteReceipt` if retried with the same `idempotency_key`, and rejects with `Error::AlreadyVoted` if a different key is supplied.
- **Voting window & zero power**: `cast_vote` rejects votes outside `[start_ledger, end_ledger]` (`Error::VotingNotOpen`), without a snapshot (`Error::SnapshotNotFound`), or with `capped_weight == 0` (`Error::ZeroVotingPower`).
- **Invalid config**: `max_weight_cap == 0` or `max_delegation_depth` outside `1..=8` is rejected (`Error::InvalidConfig`).

## Recovery & Rollback Behavior

- **Proposal cancellation (`cancel_proposal`)**: Admin can cancel an active proposal to immediately halt further snapshot recording and voting (`Error::ProposalCancelled`).
- **Snapshot correction (`reset_snapshot`)**: Admin can remove an un-voted `VoterSnapshot` so a corrected snapshot can be re-recorded. Once a voter has cast a vote, `reset_snapshot` fails with `Error::AlreadyVoted` to preserve tally integrity.

## Migration Plan & Backwards Compatibility

- **Existing contracts preserved**: `governance-quadratic-voting` is deployed as a standalone Soroban contract crate (`contracts/governance-quadratic-voting`) with isolated storage. `contracts/governance-contract` is untouched.
- **Incremental adoption**:
  1. Deploy and initialize `GovernanceQuadraticVotingContract` with `admin`, `snapshotter`, and `VotingConfig`.
  2. Sync governance token stakes via `Snapshotter`-authorized `set_stake` calls.
  3. Create new proposals and record delegation snapshots per proposal before opening the voting window.

## Verification

```bash
cargo test -p governance-quadratic-voting --lib
```

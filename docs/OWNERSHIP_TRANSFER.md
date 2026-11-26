# Safe Ownership Transfer with Pending Acceptance and Expiry (Issue #286)

## Overview

`shared::auth` implements a two-step administrative ownership transfer with explicit pending acceptance, expiry enforcement, owner cancellation, target rejection, and permissionless expiry cleanup. Ownership (`KEY_ADMIN` and `Role::Admin`) never changes on proposal alone; the designated `target_owner` must explicitly accept before `expiry`.

## Public Surface

| Function | Caller | Behavior |
|---|---|---|
| `propose_ownership_transfer(env, current_owner, target_owner, expiry)` | Current admin | Creates `PendingOwnershipTransfer` if `expiry > now`, `target_owner != current_owner`, and no unexpired transfer is pending. |
| `accept_ownership_transfer(env, caller)` | `target_owner` | Verifies `now <= expiry`, transfers `KEY_ADMIN` and `Role::Admin`, revokes `Role::Admin` from `current_owner`, clears pending record. |
| `cancel_ownership_transfer(env, caller)` | Current admin | Clears pending transfer before acceptance. |
| `reject_ownership_transfer(env, caller)` | `target_owner` | Explicitly declines a pending transfer and clears the pending record so the owner can propose a different target immediately. |
| `expire_ownership_transfer(env)` | Permissionless | Clears a pending transfer once `now > expiry`. |
| `is_ownership_transfer_expired(env)` | Read-only | Returns `Option<bool>` indicating whether a pending transfer has passed `expiry`. |
| `ownership_transfer_time_remaining(env)` | Read-only | Returns `Option<u64>` seconds remaining before `expiry`. |

## Operational Edge Cases

1. **Expired proposal blocking new proposals:** If a transfer expires without acceptance, `propose_ownership_transfer` allows overwriting it (`now > existing.expiry`), or any caller may run `expire_ownership_transfer` to clear it explicitly.
2. **Self-transfer or past expiry:** Rejected immediately with `Error::InvalidArgument`.
3. **Target rejection:** If the wrong address was nominated, the target can call `reject_ownership_transfer` (or the owner can call `cancel_ownership_transfer`) without waiting for `expiry`.
4. **Concurrent proposal:** While `now <= existing.expiry`, a second `propose_ownership_transfer` fails with `Error::TransferAlreadyPending`.

## Recovery and Rollback Behavior

- **Before acceptance:** Ownership remains with `current_owner`. Rollback is `cancel_ownership_transfer` (by owner) or `reject_ownership_transfer` (by target).
- **After expiry:** Call `expire_ownership_transfer` (or directly `propose_ownership_transfer` with a new target/deadline).
- **After acceptance:** Ownership has atomically moved to `target_owner`. Reversing requires the new owner to initiate a new `propose_ownership_transfer` back to the prior owner.

## Contract Preservation

All additions (`reject_ownership_transfer`, `expire_ownership_transfer`, `is_ownership_transfer_expired`, `ownership_transfer_time_remaining`) are purely additive on `shared::auth`. Existing `KEY_ADMIN`, `KEY_PENDING_OWNER`, `PendingOwnershipTransfer`, and `Role::Admin` storage layouts and behaviors are preserved unchanged.

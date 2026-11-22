# Expiring capability tokens

Access control now supports additive, single-action capability tokens. An
admin issues a token to one grantee with an action symbol, bounded lifetime,
and use budget. The grantee must authorize `consume_capability`; consumption
checks the action, grantee, expiry, revocation flag, and remaining uses before
incrementing the counter. The issuer or an admin can revoke a token after a
leak. Existing role checks remain in place, so removing this feature does not
change existing authorization paths.

## Paths, edge cases, and recovery (Issue #479)

`pause_with_capability` is the sensitive action wired to capabilities: a
grantee without a standing admin role pauses one scope with a token whose
action is `pause`.

| Path | Behaviour |
|---|---|
| Normal | The grantee calls `pause_with_capability`; the scope is paused and one use is spent. |
| Failure | Each check fails with its own error and spends nothing: `CapabilityNotFound`, `CapabilityRevoked`, `CapabilityUnauthorized` (caller is not the grantee), `CapabilityActionMismatch`, `CapabilityExpired`, `CapabilityExhausted`. |
| Retry | A call that fails after the use was counted (for example the scope is already paused, `OperationPaused`) rolls back as a whole, so the use is not spent and the same token can be retried. An invalid scope is rejected before the token is read. |
| Authorization | Only the grantee can consume. A token is void once its issuer is no longer an admin: `remove_admin` on the issuer makes every token they issued fail with `CapabilityRevoked`. |

### Edge cases

- **Expiry boundary.** `expires_at` is the issue timestamp plus the lifetime,
  and it is exclusive: a call at `expires_at - 1` succeeds and a call at
  `expires_at` fails with `CapabilityExpired`.
- **Issuer removed and re-added.** The issuer check reads the current admin
  set, so tokens from an issuer who is made admin again become usable again
  until they expire, are exhausted, or are revoked. Call `revoke_capability`
  on a token that must stay dead.

### Recovery

- A leaked token: the issuer or any admin calls `revoke_capability`.
- A token that stopped working because its issuer was removed: a current admin
  issues a new one with `issue_capability`.
- Nothing needs to be rolled back after a failed call: a failed call changes
  no state, including the use counter.

### Migration

The issuer check needs no storage change and reuses the existing
`CapabilityRevoked` error. After an upgrade, tokens issued by admins who have
since been removed stop working; re-issue them from a current admin if they
are still needed.

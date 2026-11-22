# Stale Session and Token Revocation After Security Events (Issue #283)

## Overview

`shared::session_revocation` provides O(1) bulk invalidation of stale sessions and tokens whenever a security event occurs (admin change, role revocation, key compromise, suspicious activity, account lock, or manual revocation), as well as idempotent single-token revocation.

## Design

Each subject `Address` has a persisted `SubjectSecurityState` containing:
- `min_valid_epoch: u64`: incremented on every `trigger_security_revocation` call.
- `last_revoked_at: u64`: timestamp watermark of the latest security event.

Every `SessionToken` issued via `issue_session_token` captures the subject's current `epoch` and `issued_at` timestamp, plus a deterministic `token_id` derived via canonical XDR SHA-256 (`derive_token_id`). `validate_session_token` rejects any token where:
1. `status == TokenStatus::Revoked` (`Error::Unauthorized`)
2. `token.epoch < state.min_valid_epoch` or `token.issued_at < state.last_revoked_at` (`Error::StaleData`)
3. `now > token.expires_at` (`Error::Expired`)

## Operational Edge Cases

1. **Same-ledger reissue after security event:** Because `min_valid_epoch` is strictly incremented by `1`, a token issued in the same ledger timestamp *after* `trigger_security_revocation` receives the new epoch while all pre-event tokens carry the old epoch and remain rejected with `Error::StaleData`.
2. **Idempotent single-token revocation:** Calling `revoke_session_token` on an already-revoked token returns `Ok(false)` rather than failing, making retry loops safe.
3. **Epoch overflow:** `min_valid_epoch.checked_add(1)` fails closed with `Error::Overflow` rather than wrapping to `0`.
4. **Authorization:** Only `require_admin` or the token's `subject` may issue or revoke individual tokens; only `require_admin` may trigger bulk `trigger_security_revocation`.

## Recovery and Rollback Behavior

- **Accidental or emergency lockout:** Security revocations are intentionally non-reversible for old tokens (stale tokens cannot be un-revoked). Recovery is forward-only: once the subject's credentials are rotated or verified, issue fresh tokens via `issue_session_token`, which automatically bind to the new `min_valid_epoch`.
- **Compromised session:** Call `revoke_session_token` for a single leaked token, or `trigger_security_revocation` to invalidate all active sessions for the subject in O(1) storage writes.

## Contract Preservation

`shared::session_revocation` is an additive module using isolated `SessionKey` persistent storage entries. Existing `shared::auth` and `shared::impersonation` interfaces and storage keys are untouched.

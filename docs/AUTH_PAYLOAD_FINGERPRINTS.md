# Replay-Safe Authorization Payload Fingerprints (Issue #325)

Module: `shared/src/auth_fingerprint.rs`

## Fingerprint

```text
fingerprint = sha256(xdr(("auth_fp", FORMAT=1, network_id, contract_address,
                          AuthPayload { signer, action, body_hash, nonce, expires_at_ledger })))
```

Because the network id and the calling contract are inside the hash, a signed
payload cannot be replayed on another network or another contract. Changing
any payload field produces a different fingerprint. `body_hash` is
`sha256(body)`, which binds the full argument body without storing it.

## `consume_authorization` check order

1. revoked → `Revoked`
2. already consumed → `Replayed`
3. `ledger > expires_at_ledger` → `Expired` (expiring exactly at the current ledger is still valid)
4. `expires_at_ledger − ledger > MAX_VALIDITY_LEDGERS` (8 640, about 12 h) → `ExpiryTooFar`
5. `nonce != next_nonce(signer)` → `NonceMismatch`
6. `signer.require_auth_for_args((fingerprint,))`, so the signature covers the fingerprint
7. record `Consumed`, bump the nonce, emit `afp_use`

If a `body` is supplied, it must hash to `body_hash`. Otherwise the call
returns `BodyMismatch`. None of the failure paths advance the nonce.

## Retry semantics

A client whose transaction timed out but actually succeeded gets `Replayed`
when it resubmits. That is different from `NonceMismatch`, so the client knows
the action already ran. It can confirm with `fingerprint_status`, which returns
`Consumed { signer, nonce, consumed_at_ledger }`. Clients should treat
`Replayed` as success and not execute the action a second time.

## Revocation

`revoke_authorization` can be called by the signer (with `require_auth`) or by
the admin. It marks a payload that was signed but not yet used as `Revoked`.
Calling it again on a revoked payload succeeds without changes. Revoking an
already-consumed payload returns `Replayed`. Revocation does **not** advance
the nonce, so the signer can re-issue with the same nonce as long as some field
(usually the body) differs. Any other caller gets `Unauthorized`.

## Storage and expiry

`Consumed` and `Revoked` markers are stored in temporary storage with a TTL of
`TEMPORARY_BUMP_AMOUNT` (17 280 ledgers), which is more than
`MAX_VALIDITY_LEDGERS`. A marker can only expire after its payload has already
expired, so the payload is rejected as `Expired` from then on. The strictly
increasing nonce in persistent storage still protects against replay after
that. Storage stays bounded: one nonce per signer plus markers that expire on
their own.

## Operational edge cases

- **Lost nonce sync**: clients read `next_nonce(signer)` before they sign.
  Payloads for nonces ahead of it are rejected, not queued.
- **Parallel signing**: only one payload per nonce can succeed. Sign the
  next payload after the previous one is consumed, or revoke the pending one.
- **Changing `MAX_VALIDITY_LEDGERS`** must keep it below `TEMPORARY_BUMP_AMOUNT`.
  Otherwise a marker could expire while its payload is still valid.
- **Bumping the format**: increment `AUTH_FINGERPRINT_FORMAT` when the payload
  shape changes. Old signatures stop verifying, which is intended.

## Migration plan

This change only adds a new module. Existing `shared::auth`, `idempotency` and
`replay` APIs are unchanged. Entrypoints that accept off-chain authorized
actions call `consume_authorization` before their side effects. There is no
state to migrate. Nonces start at 0 for every signer.

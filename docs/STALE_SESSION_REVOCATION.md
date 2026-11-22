# Stale Session and Token Revocation Handling (Issue #430)

## Overview & Goal

Across the Trellis smart contract suite, privileged operators and end-users authenticate actions using session tokens and delegated permissions. Security events such as administrative ownership changes, credential compromises, anomalous transaction patterns, or account quarantines require immediate, comprehensive invalidation of all existing tokens without incurring unbounded storage scans or gas costs.

The [`shared::session_revocation`](../shared/src/session_revocation.rs) module provides an **$O(1)$ bulk invalidation mechanism** alongside granular single-token revocation and time-to-live (TTL) expiration.

---

## Architecture & Data Model

### 1. Watermark-Based Invalidation ($O(1)$)

Rather than maintaining and iterating through unbounded token lists, each subject possesses an on-chain `SubjectSecurityState`:

```rust
pub struct SubjectSecurityState {
    pub min_valid_epoch: u64,
    pub last_revoked_at: u64,
    pub last_event: SecurityEventKind,
    pub revocation_count: u32,
}
```

- **`min_valid_epoch`**: Monotonically increasing epoch counter. Any token carrying an epoch $< \text{min\_valid\_epoch}$ is rejected immediately.
- **`last_revoked_at`**: Ledger timestamp of the most recent bulk revocation. Any token issued with $\text{issued\_at} < \text{last\_revoked\_at}$ is rejected.
- **`last_event`**: Category of the triggering security event (`AdminChanged`, `RoleRevoked`, `KeyCompromised`, `SuspiciousActivity`, `AccountLocked`, `ManualRevocation`).

### 2. Session Token Structure & Deterministic Derivation

Each token carries its issuance metadata and security epoch:

```rust
pub struct SessionToken {
    pub token_id: BytesN<32>,
    pub subject: Address,
    pub epoch: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub status: TokenStatus, // Active or Revoked
}
```

The `token_id` is derived deterministically via SHA-256 over canonical XDR:
$$\text{token\_id} = \text{SHA-256}(\text{"sess\_tok"}, \text{contract\_address}, \text{subject}, \text{nonce}, \text{issued\_at})$$

---

## Validation Lifecycle & Edge Cases

When `validate_session_token(env, token_id)` is invoked, it enforces a 4-point verification pipeline:

1. **Existence**: Token record must exist in storage; otherwise returns `Error::NotFound`.
2. **Explicit Revocation**: If `status == TokenStatus::Revoked`, returns `Error::Unauthorized`.
3. **Watermark / Stale Data**:
   $$\text{epoch} < \text{min\_valid\_epoch} \quad \lor \quad \text{issued\_at} < \text{last\_revoked\_at} \implies \text{Error::StaleData}$$
4. **Expiration**: If $\text{current\_timestamp} > \text{expires\_at}$, returns `Error::Expired`.

### Retries & Idempotency

- `revoke_session_token`: Repeated revocation calls for an already revoked token return `Ok(false)` idempotently without erroring or duplicating events.
- Re-issuance post-revocation: A subject can immediately be re-issued tokens under the new epoch without state corruption.

---

## Operator Runbook & Rollback

### Triggering Emergency Revocation
Administrators trigger bulk revocation via:
```rust
trigger_security_revocation(&env, &admin_addr, &subject_addr, SecurityEventKind::KeyCompromised)?;
```

### Recovery from False Positives
Because watermark invalidation is monotonic, pre-event tokens cannot be re-activated. To restore a mistakenly revoked subject, the operator simply issues a fresh session token under the subject's newly incremented valid epoch. Existing contract interfaces and storage schemas are fully preserved with zero breaking changes.

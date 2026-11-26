# Referral Multi-Tier Commission Cap & Self-Referral Guard

This document describes the `referral-commission-guard` Soroban contract ([`contracts/referral-commission-guard/src/lib.rs`](../contracts/referral-commission-guard/src/lib.rs)), which implements a focused vertical slice for multi-tier referral commission caps, direct and indirect self-referral prevention, idempotent accrual retries, and admin rollback/recovery.

## Overview

| Role | Permitted Operations |
|---|---|
| **Admin** | Initialize contract (`init`), rotate roles (`set_operator`, `transfer_admin`), update cap/tier configuration (`set_config`), revoke abusive referral links (`revoke_referral`), roll back completed accruals (`rollback_accrual`), plus all Operator actions. |
| **Operator** | Register referrals on behalf of users (`register_referral`) and accrue multi-tier commissions (`accrue_commission`). |
| **Referee / Referrer** | Referees can self-register (`register_referral`); referrers can claim their own accrued balances (`claim_commission`). |

## Commission Caps

Every `accrue_commission` invocation enforces four independent cap layers:

1. **Aggregate BPS cap (`max_total_bps`)**: Validated at config time so `sum(tier_bps) <= max_total_bps <= 10_000`.
2. **Per-tier absolute cap (`per_tier_cap`)**: Clamps any single tier's payout for an accrual event.
3. **Per-transaction aggregate cap (`per_tx_commission_cap`)**: Bounds the total commission distributed across all tiers in one accrual event; stops tier traversal once exhausted.
4. **Per-referrer lifetime cap (`lifetime_cap`)**: Bounds cumulative lifetime commission per referrer; once reached, subsequent accruals distribute `0` to that referrer.

## Self-Referral & Cycle Guard

- **Direct self-referral**: `register_referral` rejects `referee == referrer` with `Error::SelfReferral`.
- **Indirect (multi-hop) self-referral**: `register_referral` traverses `referrer -> parent -> ...` up to `cycle_check_depth`. If `referee` appears in the ancestor chain, it rejects with `Error::ReferralCycle`.
- **Fail-closed depth limit**: If the ancestor chain exceeds `cycle_check_depth` without reaching a root, registration fails closed with `Error::CycleDepthExceeded`.
- **Accrual-time defense-in-depth**: `accrue_commission` tracks paid addresses per event and halts if `ancestor == referee` or an address was already paid in the same event.

## Edge Cases

- **Idempotent retries**: Re-submitting `accrue_commission` with a previously completed `event_id` returns the stored `AccrualReceipt` without double-crediting balances.
- **Replaying rolled-back events**: Re-submitting an `event_id` whose status is `AccrualStatus::RolledBack` is rejected with `Error::EventRolledBack`.
- **Duplicate registration**: Attempting to overwrite an existing referral link returns `Error::AlreadyRegistered`.
- **Zero / negative amounts**: `accrue_commission` and `claim_commission` reject `amount <= 0` with `Error::InvalidAmount`.

## Recovery & Rollback Behavior

- **Accrual rollback (`rollback_accrual`)**: Admin can reverse a `Completed` accrual event by `event_id`. All tier payouts are subtracted from both `Accrued` and `LifetimeAccrued` balances, and the receipt status becomes `RolledBack`. If a referrer has already claimed funds such that `accrued < payout.amount`, the rollback fails atomically with `Error::InsufficientBalance` to prevent negative accounting.
- **Referral revocation (`revoke_referral`)**: Admin can remove an abusive or mistaken referral link so the referee can be re-registered cleanly.

## Migration Plan & Backwards Compatibility

- **Existing contracts preserved**: `referral-commission-guard` is deployed as a standalone Soroban contract crate (`contracts/referral-commission-guard`) with isolated storage. `contracts/referral-contract` is untouched.
- **Incremental adoption**:
  1. Deploy and initialize `ReferralCommissionGuardContract` with `admin`, `operator`, and validated `CommissionConfig`.
  2. Route new referral registrations and commission accruals through `ReferralCommissionGuardContract`.
  3. Optionally backfill existing referral links via `Operator`-authorized `register_referral` calls in topological (root-first) order.

## Verification

```bash
cargo test -p referral-commission-guard --lib
```

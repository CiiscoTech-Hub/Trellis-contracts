# Tranche-locked aid voucher redemption

Milestone aid programs are the on-chain voucher record. Each milestone is a
tranche with an amount, verification flag, and redeemed flag. The donor funds
the complete program once; the recipient can redeem each tranche only after an
authorized inspector verifies it.

## Flow

1. The donor creates a program with `create_milestone_aid`.
2. An admin or inspector verifies a tranche with `verify_milestone`.
3. The intended recipient redeems it with `redeem_aid_voucher`.
4. If the program expires, the donor or admin calls
   `clawback_expired_aid_voucher`. Only unredeemed tranches return to the
   donor; redeemed tranches are never clawed back.

`claim_aid_milestone` and `refund_milestone_aid` remain supported as the
original API names. The voucher names are compatibility-preserving aliases and
do not introduce a storage migration.

## Edge cases and recovery

- Redemption on or before `expiry_ledger` is allowed; redemption after it is
  rejected with `AidError::Expired`.
- Unverified, out-of-range, already redeemed, wrong-recipient, and stranger
  clawback attempts fail without changing the voucher or token balances.
- A failed redemption can be retried after the tranche is verified. A failed
  clawback can be retried after the expiry ledger passes.
- A second redemption is rejected with `MilestoneAlreadyClaimed`; a second
  clawback is rejected with `AlreadyRefunded`. These terminal checks make
  retries safe and prevent duplicate transfers.
- A partially redeemed program is marked `PartiallyClaimed` before expiry and
  `Refunded` after clawback. A fully redeemed program is `Settled` and cannot
  be clawed back.
- If the tranche totals do not equal the recorded escrow amount, the
  transition fails with `InvariantViolation` before any payout or clawback is
  committed.

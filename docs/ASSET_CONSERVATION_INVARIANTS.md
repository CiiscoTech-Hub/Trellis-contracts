# Contract-Level Asset Conservation Invariant Proofs & Formal Verification

/* Authorized Protocol Quality Assurance & Formal Verification Test Suite */

## 1. Executive Summary & Purpose

The **Trellis Contracts** suite manages financial value, humanitarian aid disbursements, escrow commitments, and protocol reserves on the Stellar/Soroban ledger. To provide mathematical assurance against unauthorized asset creation, loss, or misallocation, this framework implements **contract-level invariant proofs** that verify state conservation before and after every supported transition.

This document describes:
- The formal mathematical conservation model.
- The state transition matrix across financial contracts (`payments-contract`, `aid-contract`, `treasury-contract`).
- Invariant assertions on success, failure, and reversion paths.
- Negative testing via fixture mutations that prove tests fail when impossible balances occur.
- Assumptions, operational bounds, and known exclusions.

---

## 2. Formal Mathematical Conservation Model

### 2.1 The Closed Token System

For any token asset contract $\mathcal{T}$, let:
- $\mathcal{U} = \{ u_1, u_2, \dots, u_n \}$ be the set of all external participants (donors, beneficiaries, managers, fee recipients).
- $\mathcal{C}$ be the Trellis smart contract address.
- $B(x, t)$ denote the on-chain token balance of address $x$ at discrete ledger state $t$.
- $L(\mathcal{C}, t)$ denote the sum of all internal liability obligations recorded in contract storage at state $t$.

### 2.2 Global Conservation Invariant (Axiom I)

Across any state transition $\tau: t \to t+1$:
$$\sum_{u \in \mathcal{U}} B(u, t+1) + B(\mathcal{C}, t+1) = \sum_{u \in \mathcal{U}} B(u, t) + B(\mathcal{C}, t)$$

Equivalently, the net change in total system assets is strictly zero:
$$\Delta S = \Delta B_{\text{external}} + \Delta B_{\text{contract}} = 0$$

No tokens are spontaneously generated from thin air, destroyed, or lost to inaccessible storage keys.

### 2.3 Solvency & Backing Equivalence Invariant (Axiom II)

The contract's physical token balance held in the Stellar Asset Contract (SAC) must strictly match or exceed all internal accounting commitments:
$$B(\mathcal{C}, t) \ge L(\mathcal{C}, t)$$

Under strict conservation (where no untracked surplus is retained):
$$B(\mathcal{C}, t) = L(\mathcal{C}, t)$$

Where $L(\mathcal{C}, t)$ is defined per contract:
- **`payments-contract`**: $L = \text{total\_deposits} + \sum_{e \in \text{ActiveEscrows}} \text{amount}(e)$.
- **`aid-contract`**: $L = \sum_{a \in \text{PendingAids}} \text{amount}(a)$.
- **`treasury-contract`**: $L = \sum_{c \in \text{Categories}} \text{category\_balance}(c)$.

### 2.4 Reversion Invariance (Axiom III)

For any transition $\tau$ that encounters an invalid argument, unauthorized caller, expired deadline, or insufficient funds:
$$B(x, t+1) = B(x, t) \quad \forall x \in \mathcal{U} \cup \{ \mathcal{C} \}$$
$$L(\mathcal{C}, t+1) = L(\mathcal{C}, t)$$

Rejected transactions guarantee zero side effects and zero balance drift.

---

## 3. State Transition Matrix

| Contract | Entry Point | Path Type | External Delta ($\Delta B_{\text{ext}}$) | Contract Delta ($\Delta B_{\mathcal{C}}$) | Internal Liability Delta ($\Delta L_{\mathcal{C}}$) | Invariant Status |
|:---|:---|:---|:---:|:---:|:---:|:---:|
| **Payments** | `deposit` | Deposit | $-A$ (depositor) | $+A$ | $+A$ (`total_deposits`) | $\Delta S = 0$ |
| **Payments** | `withdraw` | Withdrawal | $+N$ (caller), $+F$ (fee recipient) | $-A$ ($A = N + F$) | $-A$ (`total_deposits`) | $\Delta S = 0$ |
| **Payments** | `withdraw_amount` | Partial WD | $+N$ (caller), $+F$ (fee recipient) | $-A$ ($A = N + F$) | $-A$ (`total_deposits`) | $\Delta S = 0$ |
| **Payments** | `create_escrow_entry` | Escrow | $-A$ (depositor) | $+A$ | $+A$ (`active_escrows`) | $\Delta S = 0$ |
| **Payments** | `release_escrow_entry` | Settlement | $+A$ (beneficiary) | $-A$ | $-A$ (`active_escrows`) | $\Delta S = 0$ |
| **Payments** | `refund_escrow_entry` | Cancellation | $+A$ (depositor) | $-A$ | $-A$ (`active_escrows`) | $\Delta S = 0$ |
| **Payments** | `batch_payout` | Batch Payout | $+\sum A_i$ (recipients) | $-\sum A_i$ | $-\sum A_i$ | $\Delta S = 0$ |
| **Aid** | `create_aid` | Disbursement | $-A$ (donor) | $+A$ | $+A$ (`pending_aids`) | $\Delta S = 0$ |
| **Aid** | `claim_aid` | Settlement | $+A$ (recipient) | $-A$ | $-A$ (`pending_aids`) | $\Delta S = 0$ |
| **Aid** | `refund_aid` | Cancellation | $+A$ (donor) | $-A$ | $-A$ (`pending_aids`) | $\Delta S = 0$ |
| **Treasury** | `deposit` | Category Funding | $-A$ (manager) | $+A$ | $+A$ (`category_balance`) | $\Delta S = 0$ |
| **Treasury** | `withdraw` | Withdrawal | $+A$ (recipient) | $-A$ | $-A$ (`category_balance`) | $\Delta S = 0$ |
| **Treasury** | `execute_scheduled_withdraw` | Scheduled WD | $+A$ (recipient) | $-A$ | $-A$ (`category_balance`) | $\Delta S = 0$ |
| **Treasury** | `distribute_reward` | Commission | $+A$ (recipient) | $-A$ | $-A$ (`rewards_balance`) | $\Delta S = 0$ |
| **Treasury** | `emergency_withdraw` | Emergency | $+A$ (to) | $-A$ | $-A$ (`reserve_balance`) | $\Delta S = 0$ |
| **All** | *Rejected Calls* | Failure | $0$ | $0$ | $0$ | $\Delta S = 0$ |

---

## 4. Fixture Mutation & Invariant Sensitivity Testing

To guarantee that the invariant test engine is sensitive and does not produce false negatives, explicit **mutation tests** inject corrupted state:

1. **Unbacked Reserve Inflation**: Simulates impossible asset creation where contract reserve increases without an external debit.
   - **Expected Error**: `InvariantViolation::AssetConservationViolated { net_delta > 0 }`.
2. **Unauthorized Reserve Drainage**: Simulates asset leakage where contract balance decreases without a legitimate withdrawal.
   - **Expected Error**: `InvariantViolation::AssetConservationViolated { net_delta < 0 }`.
3. **Internal Liability Desynchronization**: Simulates internal ledger corruption where liabilities exceed physical reserves.
   - **Expected Error**: `InvariantViolation::SolvencyBackingMismatched`.
4. **Negative Balance Corruption**: Simulates integer underflow or invalid balance states.
   - **Expected Error**: `InvariantViolation::ImpossibleBalanceDetected`.

---

## 5. Assumptions & Known Exclusions

### 5.1 Protocol Assumptions
- **Standard SAC Semantics**: The underlying token contracts implement standard Stellar Asset Contract semantics where transfer amounts are deterministic and 1:1.
- **Atomic Execution**: Soroban host environment guarantees atomic execution; cross-contract invocation failures revert all associated state changes.
- **Time/Sequence Monotonicity**: Expiry windows rely on monotonic ledger sequence numbers and timestamps (`env.ledger().sequence()`, `env.ledger().timestamp()`).

### 5.2 Known Exclusions
- **Rebasing & Fee-on-Transfer Tokens**: Tokens that algorithmically alter balances in holder accounts outside standard `transfer` calls (e.g., elastic supply rebasing tokens) violate the constant-sum assumption and are **not supported**.
- **Admin Minting / Burning Outside Contracts**: Token administrators minting directly to contract addresses or burning tokens via SAC administrator keys outside the contract's methods will alter reserves and require balance resynchronization.

---

## 6. Test Suite & Validation Commands

All invariant tests are automated and execute via `cargo test`:

```bash
# Run Payments invariant test suite
cargo test -p payments-contract invariants_test

# Run Aid invariant test suite
cargo test -p aid-contract invariants_test

# Run Treasury invariant test suite
cargo test -p treasury-contract invariants_test

# Run all invariant tests across the workspace
cargo test invariants_test
```

---

## 7. Executable Domain Consistency Invariants

The Soroban contract test modules below exercise domain state through their
public clients and ledger environment. Each test checks a valid transition,
rejects an invalid mutation, or both; the mutation tests also prove the
conservation verifier detects deliberately corrupted snapshots.

| Invariant | Why it matters | Contract path and executable test |
|---|---|---|
| An aid creation debits the donor and records an equally backed pending liability. | Prevents phantom aid obligations and unbacked escrow. | [`create_aid`](../contracts/aid-contract/src/lib.rs), [`test_invariant_create_aid_conserves_assets`](../contracts/aid-contract/src/invariants_test.rs) |
| Aid settlement transfers the escrow once and clears the pending liability. | Prevents double payment and stuck liabilities. | [`claim_aid`](../contracts/aid-contract/src/lib.rs), [`test_invariant_claim_aid_settlement_conserves_assets`](../contracts/aid-contract/src/invariants_test.rs), [`test_threat_double_claim_rejected_and_conserves_assets`](../contracts/aid-contract/src/invariants_test.rs) |
| A refunded aid cannot later be claimed, and a settled aid cannot be refunded. | Keeps terminal lifecycle states mutually exclusive. | [`refund_aid`](../contracts/aid-contract/src/lib.rs), [`test_threat_claim_after_refund_rejected`](../contracts/aid-contract/src/invariants_test.rs), [`test_threat_refund_after_claim_rejected`](../contracts/aid-contract/src/invariants_test.rs) |
| Only the donor may reclaim expired aid. | Stops unrelated callers from redirecting escrow on cancellation. | [`refund_aid`](../contracts/aid-contract/src/lib.rs), [`test_threat_unauthorized_refund_by_non_donor_rejected`](../contracts/aid-contract/src/invariants_test.rs) |
| Milestone tranches sum to the escrowed amount and status reflects remaining entitlement. | Prevents one aid record from consuming another record's assets. | [`settle_milestones`](../contracts/aid-contract/src/transitions.rs), [`milestone_claims_track_entitlement_until_settled`](../contracts/aid-contract/src/transitions.rs) |
| Milestone verification, claims, and refunds require their designated actors. | Prevents unauthorized movement of individual entitlements. | [`only_owners_can_move_entitlements`](../contracts/aid-contract/src/transitions.rs) |
| Deposits and fee-bearing withdrawals conserve the complete token amount. | Ensures fees plus net proceeds equal the amount removed from contract accounting. | [`deposit`](../contracts/payments-contract/src/lib.rs), [`withdraw_amount`](../contracts/payments-contract/src/lib.rs), [`test_invariant_partial_withdrawal_conserves_assets`](../contracts/payments-contract/src/invariants_test.rs) |
| Escrow release and cancellation pay only the beneficiary or depositor and clear escrow once. | Prevents incorrect ownership and repeated settlement. | [`release_escrow_entry`](../contracts/payments-contract/src/lib.rs), [`refund_escrow_entry`](../contracts/payments-contract/src/lib.rs), [`test_invariant_escrow_settlement_lifecycle_conserves_assets`](../contracts/payments-contract/src/invariants_test.rs), [`test_invariant_escrow_cancellation_refund_conserves_assets`](../contracts/payments-contract/src/invariants_test.rs) |
| Batch payouts cannot create or destroy assets. | Keeps aggregate recipient credits equal to the contract debit. | [`batch_payout`](../contracts/payments-contract/src/lib.rs), [`test_invariant_batch_payout_conserves_assets`](../contracts/payments-contract/src/invariants_test.rs) |
| Treasury category balances remain segregated and cannot be overdrawn. | Stops one category or reward pool from spending another category's allocation. | [`category_balance`](../contracts/treasury-contract/src/lib.rs), [`test_invariant_multi_category_segregation_conserves_assets`](../contracts/treasury-contract/src/invariants_test.rs), [`test_threat_referral_overdraft_cannot_underflow_rewards_category`](../contracts/treasury-contract/src/invariants_test.rs) |
| Scheduled withdrawals follow their lifecycle and rejected calls leave state unchanged. | Prevents early/replayed withdrawals and partial state updates on failure. | [`execute_scheduled_withdraw`](../contracts/treasury-contract/src/lib.rs), [`test_invariant_scheduled_withdrawal_lifecycle_conserves_state`](../contracts/treasury-contract/src/invariants_test.rs), [`test_invariant_treasury_failure_paths_preserve_exact_state`](../contracts/treasury-contract/src/invariants_test.rs) |
| Invalid balances and unbacked liabilities are detected by the invariant verifier. | Demonstrates that impossible states fail assertions rather than silently passing. | [`verify_conservation`](../shared/src/invariants.rs), [`test_mutation_impossible_balances_fail_invariant_verification`](../contracts/payments-contract/src/invariants_test.rs) |

These modules are included by their contract crates under `cfg(test)`. Run
the targeted suites locally with:

```bash
cargo test -p aid-contract invariants_test
cargo test -p payments-contract invariants_test
cargo test -p treasury-contract invariants_test
cargo test -p aid-contract transitions
```

---

## 8. Runtime Transition Checks in the Aid Contract (Issue #266)

The suites above check invariants from outside, after a call. The aid
contract now also enforces them inside every balance, ownership, and
entitlement transition
([`contracts/aid-contract/src/transitions.rs`](../contracts/aid-contract/src/transitions.rs)),
so a violating call is rejected and rolled back instead of only being
detected later.

| Invariant | Check | Paths |
|---|---|---|
| Balance (Axiom II) | `escrow_in`: the contract's token balance must rise by exactly the recorded amount, otherwise `InvariantViolation` (118) | `create_aid`, `batch_create_aid`, `create_milestone_aid` |
| Ownership | `commit`: donor, recipient, token, amount, and tranche count are immutable | every status change |
| Lifecycle | `commit`: `Settled` and `Refunded` are terminal; status only moves forward | every status change |
| Entitlement | `settle_milestones`: tranches must sum to the escrowed amount; status is derived from what is still unclaimed | `claim_aid_milestone`, `refund_milestone_aid` |

### Defects closed

| Before | After |
|---|---|
| `claim_aid` on a milestone program paid out the whole escrow without inspector verification, after which the tranches could be claimed again, draining other records' escrow | `InvalidArgument`; tranches are claimed only through `claim_aid_milestone` |
| `refund_aid` on a milestone program refunded the full amount, including tranches already paid | `InvalidArgument`; use `refund_milestone_aid` |
| `claim_aid_milestone` never changed the record's status | `PartiallyClaimed` while tranches remain, `Settled` when none remain |
| `refund_milestone_aid` left verified-but-unclaimed tranches in the contract forever (claims close at expiry) | Every unclaimed tranche is refunded; a fully claimed program returns `AlreadyClaimed` |
| `delete_aid` could delete a partially claimed record that still held escrow | `CannotDeletePending` |
| A fee-on-transfer token under-backed new liabilities (§5.2) | Rejected at escrow time with `InvariantViolation` |

**Migration.** No storage migration is needed. Milestone records created
before this change still read `Pending`; their status is recomputed from the
stored tranches on the next claim or refund.

**Recovery.** A rejected transition writes nothing, so the caller retries
once the precondition holds; for example, an unverified tranche can be
claimed after an inspector verifies it. If `InvariantViolation` comes from
`settle_milestones`, stored tranches disagree with the record: pause the
contract and reconcile the record against token balances before resuming.

```bash
cargo test -p aid-contract transitions
```

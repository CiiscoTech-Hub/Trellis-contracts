# External Dependency Degradation Matrix & User-Safe Fallback Behavior (Issue #231)

Across Soroban contracts — **Treasury**, **Aid**, **Referral**, **Governance**, **Oracle**, and **Marketplace** — interactions with critical external dependencies (such as external price feeds, payment gateways/escrows, cross-contract tokens, and indexing/relay services) can suffer latency spikes, total outages, rate-limits, or corrupted data.

The Degradation Matrix provides:
1. Formal failure mode classification for all critical external dependencies.
2. Tiered degradation levels (`Nominal`, `DegradedMinor`, `DegradedMajor`, `CriticalFailure`).
3. User-safe fallback strategies ensuring funds, accounts, and cryptographic state invariants remain sound.
4. Automated verification checks and deterministic decision policies (`FallbackDecision`).
5. Controlled recovery workflows with receipts and rollback steps.

Implementation resides in [`shared::degradation`](../shared/src/degradation.rs).

---

## 1. Critical Dependency Matrix

| Module | Critical Dependency | Primary Failure Mode | Safe Fallback Strategy | Max Staleness | Failure Threshold |
|---|---|---|---|:---:|:---:|
| **Treasury** | Stellar Asset Contract (`token_sac`) | Total Outage / Unreachable | `FailSafeRejection` (prevent balance desync) | 50 ledgers | 2 failures |
| **Aid** | Payment Gateway (`pay_gate`) | High Latency / Network Timeout | `EscrowHoldWithRefundGuarantee` | 100 ledgers | 3 failures |
| **Aid** | Stellar Asset Contract (`token_sac`) | Total Outage / Revert | `EscrowHoldWithRefundGuarantee` | 50 ledgers | 2 failures |
| **Referral** | Indexer / Relayer (`indexer`) | Rate Limit / Quota Exhaustion | `LinearBaseCalculation` (base tier payout) | 200 ledgers | 3 failures |
| **Governance** | Indexer / Relayer (`indexer`) | Quorum Deficit / Stale Data | `ReadOnlyInspection` (block active votes) | 120 ledgers | 2 failures |
| **Oracle** | External Oracle Feed (`ora_feed`) | Corrupted / Extreme Price Skew | `CachedLastKnownGood` (within volatility limit) | 60 ledgers | 2 failures |
| **Marketplace** | Stellar Asset Contract (`token_sac`) | Total Outage / Transfer Error | `EscrowHoldWithRefundGuarantee` | 50 ledgers | 2 failures |

---

## 2. Documented Failure Modes

### 2.1 High Latency or Timeout (`HighLatencyOrTimeout`)
- **Symptoms**: Remote API calls or ledger submissions exceed typical window; transactions pend beyond expected timeout.
- **Affected**: Off-chain payment bridges, indexers.
- **Impact**: User transactions could be double-submitted if not protected by idempotency nonces.
- **Mitigation**: Escrow holds with clear refund expirations and non-blocking background queueing.

### 2.2 Total Outage (`TotalOutage`)
- **Symptoms**: Remote contract invocation panics, reverts, or returns network unreachable (5xx/RPC down).
- **Affected**: External token contracts, off-chain payment rails.
- **Impact**: Fund transfers cannot complete.
- **Mitigation**: Fail-safe rejection before state modification, ensuring no partial or asymmetric ledger state.

### 2.3 Corrupted or Invalid Data (`CorruptedOrInvalidData`)
- **Symptoms**: Divergent prices, negative values, malformed attestation signatures.
- **Affected**: Oracle price feeds.
- **Impact**: Inaccurate liquidations, incorrect auction settlements, or aid conversion discrepancies.
- **Mitigation**: Cached last-known-good price bounded by volatility envelope and freshness limits.

### 2.4 Quorum Loss or Stale Sequence (`QuorumLossOrStaleData`)
- **Symptoms**: Submitter quorum drops below required threshold or sequence timestamp has lagged.
- **Affected**: Oracle aggregators, Governance snapshot voting indexers.
- **Impact**: Stale prices or unverified votes deciding treasury allocations.
- **Mitigation**: Switch to read-only inspection mode; suspend proposal executions until quorum returns.

### 2.5 Rate Limit or Capacity Exhaustion (`RateLimitOrCapacityExhaustion`)
- **Symptoms**: 429 Too Many Requests, worker queue backlog, CPU/memory limits approached.
- **Affected**: Referral calculation engines, indexer feeds.
- **Impact**: Dynamic multi-tier bonus calculations fail.
- **Mitigation**: Fall back to simple deterministic linear base calculations.

---

## 3. Degradation Levels & Fallback UX/API Behavior

```
     [ Nominal ]
          │ (1st error / minor delay)
          ▼
   [ DegradedMinor ] ──► Standard path attempted; alerts emitted
          │ (consecutive failures >= threshold or staleness exceeded)
          ▼
   [ DegradedMajor ] ──► Mandatory Safe Fallback engaged (`ProceedFallback`)
          │ (failures >= 2x threshold or status == Down)
          ▼
  [ CriticalFailure ] ──► Strict Fallback or User-Safe Rejection (`RejectOperation`)
```

### 3.1 Fallback Decision Matrix

| Level | Decision | User / API Behavior |
|---|---|---|
| `Nominal` | `ProceedPrimary` | Standard execution path without alteration. |
| `DegradedMinor` | `ProceedPrimary` | Primary execution path proceeds; telemetry warning logged. |
| `DegradedMajor` | `ProceedFallback(strategy)` | Automatic user-safe fallback behavior executed; event published. |
| `CriticalFailure` | `ProceedFallback` or `RejectOperation` | If fallback cannot guarantee solvency, operation fails safely with `Error::DependencyDegraded` (code 41). |

---

## 4. Operational Edge Cases & Rollback / Recovery Steps

### 4.1 Edge Cases Handled
1. **Flapping Dependencies**:
   - Dependencies with intermittent drops require a streak of consecutive healthy checks (`recovery_success_threshold`, default 3) before recovering to `Nominal`.
2. **Stale Records**:
   - If a dependency has not been evaluated within `max_staleness_ledgers`, it automatically degrades to `DegradedMajor` regardless of the last recorded status.
3. **Escrow Guarantee**:
   - Any funds held during degraded payment/marketplace operations are locked in audited contract escrows with immutable refund capabilities.

### 4.2 Recovery & Rollback Runbook
When external dependencies have stabilized:
1. **Automated Verification**:
   - Background checks record successful outcomes via `record_dependency_check(..., true, 0)`.
   - Once consecutive successful checks reach `recovery_success_threshold`, status resets to `Nominal`.
2. **Administrative Override & Receipt**:
   - Authorized administrators can invoke `recover_dependency(env, admin, module, dependency, rollback_applied)`.
   - Emits canonical audit event `(recovery, recovered)`.
   - Stores an immutable `RecoveryReceipt` documenting the resolution ledger and whether state rollback was performed.
3. **Emergency Circuit Breaker**:
   - If a dependency fails critically during flight, `execute_with_fallback` catches the error, records telemetry, and executes the fallback path immediately without transaction abort.

---

## 5. User-Safe Degraded Mode at the Entry Point (Issue #265)

`RejectOperation` above blocks every call, including a user taking out their
own funds. [`shared::degraded_mode::guard_operation`](../shared/src/degraded_mode.rs)
classifies each entry point instead. A contract calls it first, before any
write:

```rust
use shared::degraded_mode::{guard_operation, OperationClass, DegradedAccess};

let access = guard_operation(&env, DegradationModule::Treasury,
    ExternalDependencyKind::StellarAssetContract, OperationClass::Entry)?;
```

| `OperationClass` | Nominal | Safe fallback strategy | `ReadOnlyInspection`, `FailSafeRejection`, or `RejectOperation` |
|---|---|---|---|
| `Entry` (deposit, create, purchase) | `Primary` | `Fallback(strategy)` | `Err(Error::DependencyDegraded)` before any write |
| `Exit` (claim, refund, withdraw) | `Primary` | `Primary` | `Primary`; exits are never blocked |
| `Read` | `Primary` | `Fallback(strategy)` | `Fallback(ReadOnlyInspection)` |

Exits stay open because Soroban runs a transaction atomically. If the
dependency really is down, the exit's transfer fails, the whole invocation
reverts, and the user retries later. Funds are never stuck behind the gate,
and a compromised health reporter can at most pause new entries.

### Edge cases

- **Health must be reported from a committed transaction.** A failure
  recorded inside an invocation that then returns `Err` is rolled back with
  everything else in that invocation. Feed degradation through
  `shared::health_guard::report_health_check` in its own transaction from a
  registered reporter.
- **No health record yet.** The dependency is treated as nominal, as
  `evaluate_dependency_decision` already does.
- **The reporter goes silent.** Once the record is older than
  `max_staleness_ledgers`, entries switch to their fallback or are refused.
  Windows are counted in ledgers, so their wall-clock length varies with the
  network's ledger close time.
- **Retrying a refused entry.** Nothing was written, so the user just retries
  after recovery.

### Recovery

1. Healthy reports reach `recovery_success_threshold` (default 3) and the
   entry returns to `Nominal`.
2. Or an admin calls `recover_dependency`.
3. If a reporter is compromised: `revoke_reporter`, then step 2. Exits were
   never blocked, so there are no user funds to recover.

```bash
cargo test -p shared degraded_mode
```

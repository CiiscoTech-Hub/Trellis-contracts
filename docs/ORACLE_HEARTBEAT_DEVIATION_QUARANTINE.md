# Oracle Price Feed Heartbeat and L2 Deviation Quarantine (#518)

## Overview

The Oracle Price Feed Heartbeat and L2 Deviation Quarantine module (`shared::oracle_quarantine`) provides critical resilience and market-integrity guardrails for oracle price feeds across Stellar and L2 networks:

1. **Heartbeat Verification**:
   - Every price feed has an expected update interval (`heartbeat_secs`) plus a network skew tolerance (`tolerance_secs`).
   - If the interval between the current ledger timestamp and the feed's last recorded timestamp exceeds this window, the feed update or consumption is rejected with `HeartbeatMissed` (code 524).
   - Prevents downstream contracts from consuming stale or frozen prices following sequencer outages, relayer partitions, or network downtime.

2. **L2 Deviation Quarantine**:
   - Detects abnormal price spikes or flash drops where the candidate price deviates from the established reference price by more than `max_deviation_bps` (e.g. 1,000 bps = 10%).
   - When tripped, the candidate price is **not** propagated to live settlement. Instead, the feed is placed into a protective **Quarantine State** (`PriceDeviationQuarantined` / `QuarantineActive`).
   - While in quarantine, attempts to read or execute settlements against the quarantined feed fail fast with `QuarantineActive` (code 526).

3. **Auto-Recovery and Governance Override**:
   - **Auto-Recovery**: Once the cooldown window (`quarantine_duration_secs`) elapses, the feed auto-recovers after receiving `required_recovery_ticks` consecutive submissions within standard deviation bounds.
   - **Governance Override**: Authorized administrators can manually release a quarantined feed (`release_quarantine_override`) or force-quarantine a suspicious feed during an incident drill (`force_quarantine_feed`).

---

## Architecture & Data Flow

```text
Price Submission (candidate_price)
         │
         ▼
[ Heartbeat Check ] ── (now > last_update + heartbeat) ──► Fail: HeartbeatMissed (524)
         │ Pass
         ▼
[ Compute Deviation ] ── (|candidate - ref| / ref * 10,000)
         │
    ┌────┴──────────────────────────┐
    ▼                               ▼
Within Bound (<= max_bps)    Exceeds Bound (> max_bps)
    │                               │
    ├─ If Quarantined:              └─► Trip Quarantine (525)
    │    Check cooldown &               Set quarantine_until = now + duration
    │    tick counter                   Set is_quarantined = true
    │    Auto-recover if met
    ▼
Accept Clean Price
Update reference_price
```

---

## Operational Paths

### 1. Normal Path
- Submitter pushes a price within the heartbeat window whose deviation is within `max_deviation_bps`.
- Evaluator returns `QuarantineEvaluation::Accepted`, updates `reference_price`, and records the timestamp.
- Downstream contracts consume the validated price.

### 2. Failure Path
- **Heartbeat Expiry**: If no submitter has posted an update within `heartbeat_secs + tolerance_secs`, queries return `OracleQuarantineError::HeartbeatMissed`.
- **Deviation Spike**: An errant feed or flash manipulation swings the price by 25% (exceeding 10% max). Evaluator trips quarantine, stores `quarantined_price`, and returns `QuarantineEvaluation::Quarantined`.
- **Quarantine Interception**: While quarantined, calls fail with `OracleQuarantineError::QuarantineActive`.

### 3. Retry Path
- **Transient Network Delays**: Once connectivity is restored, submitters resume updates. If within tolerance, updates succeed.
- **Auto-Recovery**: After the quarantine cooldown duration elapses, submitters send prices that remain within tolerance. After `required_recovery_ticks` consecutive healthy observations, the feed auto-recovers to active state.

### 4. Authorization Path
- Setting quarantine parameters, force-quarantining, or manually overriding/releasing a quarantined feed requires administrator authorization.
- Unauthorized callers attempting override calls are rejected with `OracleQuarantineError::Unauthorized`.

---

## Error Taxonomy

| Code | Variant | Description | Remediation |
|---|---|---|---|
| `524` | `HeartbeatMissed` | Feed update exceeded heartbeat window | Wait for a fresh price submission from authorized oracles |
| `525` | `PriceDeviationQuarantined` | Candidate price deviated beyond maximum allowable basis points | Wait for cooldown or inspect submitter feeds for manipulation |
| `526` | `QuarantineActive` | Feed is currently in quarantine; settlements blocked | Wait for auto-recovery observations or request admin release |
| `527` | `InvalidQuarantineConfig` | Parameter out of bounds (bps > 10,000 or 0 duration) | Correct configuration parameters |
| `528` | `Unauthorized` | Caller lacks governance role | Require admin authentication |

---

## Edge Cases and Rollback Behavior

- **Zero / Negative Reference Price**: On the initial observation or when initializing a feed, deviation from reference price defaults to 0 bps to allow bootstrap.
- **Arithmetic Overflow Protection**: All basis-point multiplications use checked arithmetic; overflow falls back cleanly to `MathOverflow`.
- **Zero Heartbeat (Disabled)**: Setting `heartbeat_secs = 0` cleanly disables heartbeat enforcement for testing or low-frequency static feeds.
- **Atomic Rollback**: If an update evaluation fails or enters quarantine, no invalid state is committed to canonical feed pricing.

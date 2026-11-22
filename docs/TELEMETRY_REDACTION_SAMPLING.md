# High-Cardinality Telemetry Redaction and Sampling (Issue #428)

## Overview & Goal

Smart contract observability relies on emitting structured event telemetry so off-chain indexers and operational dashboards can monitor protocol health, throughput, and latencies. However, emitting high-cardinality values (such as raw wallet addresses or token IDs) causes cardinality explosion in time-series backends, while logging secret material or account balances creates compliance and security risks.

The [`shared::telemetry_protection`](../shared/src/telemetry_protection.rs) and [`shared::sanitize`](../shared/src/sanitize.rs) modules provide automated label sanitization, sensitive data masking, and deterministic event sampling.

---

## Redaction Strategy

### Sensitive Label Redaction
Labels containing high-cardinality or confidential prefixes are masked with the stable `<redacted>` placeholder:
- `user:G...` $\to$ `user:<redacted>`
- `wallet:G...` $\to$ `wallet:<redacted>`
- `amount:...` $\to$ `amount:<redacted>`
- `secret:S...` $\to$ `secret:<redacted>`
- `token:...` $\to$ `token:<redacted>`

Bounded operational labels (e.g., `op:transfer`, `actor:user`, `status:ok`) pass through unchanged up to `MAX_LABEL_LEN` (64 characters).

---

## Deterministic Sampling Policy

High-volume operations are protected by a configurable `SamplingConfig`:

```rust
pub struct SamplingConfig {
    pub burst_threshold: u32,
    pub sample_rate_denominator: u32,
}
```

### Sampling Invariants

1. **Burst Preservation**: While event volume $\le \text{burst\_threshold}$, 100% of events are emitted.
2. **Error & Priority Bypass**: Error events (index `0`) are **never dropped**, guaranteeing complete visibility into protocol anomalies regardless of transaction volume.
3. **Deterministic Decimation**: For volume $> \text{burst\_threshold}$, events are emitted if:
   $$\text{event\_index} \pmod{\text{sample\_rate\_denominator}} == 0$$

---

## Authorization & Administrative Controls

The sampling configuration can be updated dynamically by administrators via `update_sampling_policy`:
- Caller must satisfy `require_admin`.
- Rejects invalid parameters (e.g. `sample_rate_denominator == 0`).
- Emits `(telemetry, cfg_upd)` audit events for operational traceability.

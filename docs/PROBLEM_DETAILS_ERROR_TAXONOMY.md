# Stable API Problem-Details Error Taxonomy

## Executive Summary
This document defines the RFC 7807 and RFC 9457 compliant error presentation taxonomy for Trellis Soroban contracts (`shared::problem_details_taxonomy`, Issue #497).

Contracts return stable numeric error codes across execution entry points. Off-chain API gateways, indexers, client SDKs, and operator dashboards require human- and machine-readable error details that are consistent, safe from information leakage, and actionable.

---

## Architectural Principles

1. **Stable Machine Codes**:
   - Every known contract error discriminant maps to a fixed, permanent machine symbol (e.g., `AUTH_UNAU`, `VAL_AMT`, `STATE_EXPRD`, `SYS_ERR`).
   - Codes are never renumbered or repurposed across releases.
2. **HTTP Transport Harmonization**:
   - Each error category aligns with standard HTTP status semantics:
     - `401 / 403`: Authorization & permission escalation failures.
     - `400 / 422`: Structural validation and arithmetic overflow failures.
     - `404`: Missing resources or state records.
     - `409`: State conflicts, expirations, and claim collisions.
     - `503`: Transient backpressure, contract pause, and dependency degradation.
     - `500`: Unmapped or unexpected internal invariant failures.
3. **Information Leakage Defense**:
   - All client-facing summaries (`title`) and remediation hints (`remediation`) are generic, static descriptors.
   - Internal stack traces, raw memory addresses, cryptographic secrets, and host panic strings are strictly prevented from reaching users.
4. **Retryability Semantics**:
   - Errors are categorized as either permanent (`is_retryable: false`) or transient (`is_retryable: true`).
   - Transient errors include explicit `retry_after_ms` backoff hints (e.g. 5,000ms for paused contracts, 3,000ms for degraded dependencies).

---

## Operational Execution Paths

### Normal Path
- Standard contract errors (e.g., `Unauthorized`, `InvalidAmount`, `NotFound`) map to distinct, structured `ProblemDetailsRecord` structs containing stable machine codes, appropriate HTTP status codes, and user-safe remediation guidance.

### Failure Path
- Unknown, out-of-range, or unanticipated error codes safely resolve to the fallback record:
  - Code: `SYS_ERR`
  - Category: `internal`
  - HTTP Status: `500`
  - Remediation: `ContactOp`
- Fails closed without panicking or triggering host traps.

### Retry Path
- Callers receiving transient errors (`is_retryable == true`) execute backoff and retry.
- Permanent errors (`is_retryable == false`) require payload correction or credential renewal before retrying.

### Authorization Path
- Administrative inspection (`inspect_problem_details`) allows maintainers and telemetry collectors to introspect error metadata.
- Unauthorized callers attempting administrative inspection are rejected with `Error::Unauthorized`.

---

## Migration & Compatibility
- Purely additive: existing contract error enums and Soroban event layouts are unchanged.
- Backward-compatible with all existing frontend clients and indexing pipelines.

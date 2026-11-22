# Fuzz Testing for Malformed Payloads and Boundary Inputs

## Executive Summary
This document establishes formal guidelines, implementation architecture, and verification standards for property-based and randomized fuzz testing across the Trellis smart contract suite (`shared::fuzz_boundary_inputs`, Issue #498).

By systematically generating boundary numeric distributions, malformed byte payloads, and collection cardinality edge cases within a deterministic, `no_std`-compliant test framework, contracts prevent unhandled arithmetic overflows, host execution panics, out-of-gas loops, and authorization bypasses.

---

## Threat Model & Failure Modes

1. **Arithmetic Boundary Traps**:
   - Operations on extreme integer limits (`0`, `1`, `u32::MAX`, `u64::MAX - 1`, `u64::MAX`, `i128::MIN`, `i128::MAX`) can trigger unexpected runtime traps or panics if arithmetic operations are not strictly checked.
   - Basis point fee calculations (`apply_bps`) must enforce strict fund conservation ($fee + remainder = amount$) and reject overflow percentages ($> 10,000$ bps).
2. **Malformed Payload Injection**:
   - Zero-length buffers, oversized strings, embedded null bytes, and non-ASCII or control characters submitted in contract arguments can corrupt indexer deserialization or exhaust contract storage quotas.
   - Truncated cryptographic hashes (e.g., 31 bytes instead of 32 bytes) must be rejected prior to signature verification.
3. **Cardinality Exhaustion**:
   - Collections with $0$ elements or exceeding bounds ($> 200$ elements) can induce unexpected behavior or gas exhaustion in vector processing loops.
   - Adjacent or duplicate IDs must be validated to prevent double-spending or duplicate state registrations.
4. **Adversarial Auth Evasion**:
   - Attackers submitting malformed payloads must not bypass authorization checks. The contract must evaluate permissions before argument processing or fail closed without leaking state.

---

## Architectural Design

### 1. Deterministic `no_std` PRNG (`FuzzRng`)
A deterministic, 64-bit XorShift* pseudo-random number generator (`FuzzRng`) ensures reproducible fuzz testing without external standard library dependencies (`rand`):
- Accepts a non-zero 64-bit `seed`.
- Produces uniform pseudo-random distributions across 64-bit, 32-bit, bounded ranges, and curated boundary numeric sets.

### 2. Boundary Validation Primitives
- `validate_boundary_amount(amount, config)`: Enforces $min\_amount \le amount \le max\_amount$, returning `Error::InvalidAmount`.
- `validate_and_apply_bps(amount, bps)`: Computes fee using 128-bit intermediate math, guaranteeing fund conservation ($fee + remainder == amount$) and rejecting $bps > 10,000$ with `Error::InvalidArgument`.
- `validate_fuzz_payload(payload, max_len)`: Bounded check rejecting empty payloads or $len > max\_len$ with `Error::InvalidArgument`.
- `validate_fuzz_collection(items, max_items)`: Enforces $1 \le len \le max\_items$ and rejects duplicate elements.

---

## Operational Execution Paths

### Normal Path
- Valid pseudo-random inputs generated within schema limits parse, validate, and execute cleanly.
- Fee and remainder calculations preserve balance invariants.

### Failure Path
- Boundary violations ($0$ amount, $u64::MAX$ overflow, $bps > 10000$, empty payload, oversize buffer, duplicate collection entries) deterministically return structured contract errors (`Error::InvalidAmount`, `Error::InvalidArgument`, `Error::Overflow`).
- Execution terminates cleanly without host traps or contract panics.

### Retry Path
- After an intentional failure on a malformed payload, state remains completely unmutated.
- Submitting corrected, sanitized arguments immediately succeeds on retry without residual dirty state.

### Authorization Path
- Privileged operations (`execute_admin_fuzz_action`) strictly enforce `require_admin`.
- Unauthorized callers submitting adversarial payloads are rejected with `Error::Unauthorized` at the authorization gate, preventing payload-based exploits.

---

## Rollback & State Preservation
- Fuzz testing functions are pure validation checks with zero persistent storage mutation.
- Existing storage schemas and public contract interfaces are 100% preserved.

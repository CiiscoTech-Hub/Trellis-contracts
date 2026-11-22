# Release Readiness Checks for Migrations and Rollback (Issue #422)

## Overview & Goal

Upgrades across Trellis core contracts (Treasury, Aid, Referral, Governance, Oracle, Marketplace) involve state transformations and cross-contract dependency updates. Issue #422 establishes strict, machine-enforced release readiness checks for schema migrations and automated rollback rehearsals.

The implementation is anchored in [`shared::release_readiness`](../shared/src/release_readiness.rs) and validated in CI via [`scripts/release-readiness-gate.cjs`](../scripts/release-readiness-gate.cjs).

---

## The Four-Pillar Gate Architecture

A release manifest is certified as production-ready (`is_ready = true`) if and only if all registered modules pass all four gates:

1. **Migration Gate (`GateKind::Migration`)**:
   - Storage version evolution and compatibility verified.
   - Non-destructive migration steps validated.
   - Changelog entries contain migration guidance when breaking.
2. **Security Gate (`GateKind::Security`)**:
   - Security audit allowlist freshness verified.
   - Formal invariants (token conservation, acyclicity, non-revocability) hold.
3. **Smoke Test Gate (`GateKind::SmokeTest`)**:
   - Zero-value simulations verify cross-contract wiring and getter liveness.
4. **Rollback Rehearsal Gate (`GateKind::RollbackRehearsal`)**:
   - Pre-upgrade state snapshot captured.
   - Simulated failure and recovery under [`RollbackStrategy`] (Revert, ForwardFix, Manual) executed.
   - Issuance of an immutable, auditable [`RollbackRehearsalReceipt`].

---

## On-Chain Manifest Evaluation & Error Handling

```rust
pub struct ReleaseManifest {
    pub release_version: Symbol,
    pub modules: Vec<ReleaseModule>,
    pub checks: Vec<GateCheck>,
    pub signoff_admin: Address,
    pub exception_marker: Option<Symbol>,
}
```

Evaluating a manifest fails closed:
- Missing any gate returns `ReleaseGateError::MissingMigrationVerification`, `MissingRollbackRehearsal`, etc.
- Any check with status `Failed` or `Pending` blocks release promotion (`ReleaseBlocked`).
- Emergency bypass markers require administrative authorization and are recorded in the immutable audit log.

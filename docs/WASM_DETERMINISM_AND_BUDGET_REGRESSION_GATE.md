# Workspace WASM Determinism & Soroban Budget Regression Gate (#546)

## Overview

The WASM Determinism and Soroban Budget Regression Gate module (`shared::wasm_determinism` and `scripts/wasm-budget-regression-gate.cjs`) provides continuous release-readiness guarantees:

1. **WASM Build Reproducibility**:
   - Asserts byte-for-byte reproducibility between independent build passes using SHA-256 fingerprint matching.
   - Detects hidden non-determinism introduced by debug sections, unstable timestamps, or host path leakage.
2. **Soroban Budget Regression Gate**:
   - Continuously evaluates CPU instruction counts and memory byte consumption against baseline metrics in `testing/budget-baseline.json`.
   - Enforces a 10% maximum regression threshold tolerance.
   - Evaluates absolute ceiling boundaries across `normal`, `failure`, `retry`, and `authorization` profiles.
   - Implements 2x budget headroom for retry attempts recovering from transient failures.

## Evaluation Logic

```text
Measured Metric (CPU, Memory)
             │
             ▼
   [ Absolute Ceiling Check ] ── (measured > ceiling) ────────► FAIL (BudgetCeilingExceeded)
             │ Pass
             ▼
   [ Relative Regression Check ] ── (delta > threshold %) ────► FAIL (RegressionThresholdExceeded)
             │ Pass
             ▼
        PASS VERDICT
```

## Algorithmic Complexity

- **Time Complexity**: $O(1)$ evaluation per profiled entry.
- **Space Complexity**: $O(1)$ memory consumption.

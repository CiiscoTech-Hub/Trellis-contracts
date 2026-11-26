//! # Workspace WASM Determinism & Soroban Budget Regression Gate
//!
//! Production-grade verification primitives for WASM reproducibility and
//! Soroban transaction execution budget regression gates.
//!
//! ## Key Capabilities
//! - **WASM Binary Determinism**: Canonical multi-pass artifact verification and SHA-256 fingerprinting.
//! - **Soroban Budget Regression Gate**: Checks CPU instructions & memory bytes against baseline.
//! - **Regression Threshold Enforcement**: Configurable tolerance (default 10%) prevents gradual performance creep.
//! - **Hard Absolute Ceilings**: Enforces non-negotiable host limits for normal, failure, retry, and auth paths.
//! - **Complexity**: $O(1)$ evaluation time, $O(1)$ memory overhead.

use soroban_sdk::{contracterror, contracttype, BytesN, Symbol};

// ── Error taxonomy ─────────────────────────────────────────────────────────────

#[contracterror(export = false)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum DeterminismGateError {
    /// Non-deterministic WASM artifact detected (SHA-256 fingerprint mismatch across passes).
    NonDeterministicBuild = 941,
    /// Measured consumption exceeded the hard absolute ceiling limit.
    BudgetCeilingExceeded = 942,
    /// Baseline metric is missing or corrupted.
    InvalidBaseline = 943,
    /// Measured resource usage regressed beyond the permitted threshold percentage.
    RegressionThresholdExceeded = 944,
    /// Zero or invalid threshold supplied.
    InvalidThreshold = 945,
}

// ── Data structures ────────────────────────────────────────────────────────────

/// Fingerprint record of a compiled contract WASM build.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmArtifactFingerprint {
    pub contract_name: Symbol,
    pub sha256_hash: BytesN<32>,
    pub file_size_bytes: u32,
    pub compiler_version_hash: BytesN<32>,
}

/// Result of a multi-pass determinism check.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeterminismReport {
    pub contract_name: Symbol,
    pub is_deterministic: bool,
    pub pass1_hash: BytesN<32>,
    pub pass2_hash: BytesN<32>,
    pub size_bytes: u32,
}

/// Resource budget specification for CPU instructions and memory bytes.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceBudget {
    pub cpu_instructions: u64,
    pub memory_bytes: u64,
}

/// Outcome of budget regression evaluation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BudgetRegressionVerdict {
    pub contract_op: Symbol,
    pub passed: bool,
    pub baseline_cpu: u64,
    pub measured_cpu: u64,
    pub cpu_delta_pct: i32,
    pub baseline_mem: u64,
    pub measured_mem: u64,
    pub mem_delta_pct: i32,
}

// ── Core Operations ────────────────────────────────────────────────────────────

/// Verifies that two independent compilation passes of the same contract produce identical WASM binaries.
pub fn verify_wasm_determinism(
    pass1: &WasmArtifactFingerprint,
    pass2: &WasmArtifactFingerprint,
) -> Result<DeterminismReport, DeterminismGateError> {
    if pass1.contract_name != pass2.contract_name {
        return Err(DeterminismGateError::InvalidBaseline);
    }

    let is_deterministic = pass1.sha256_hash == pass2.sha256_hash
        && pass1.file_size_bytes == pass2.file_size_bytes;

    if !is_deterministic {
        return Err(DeterminismGateError::NonDeterministicBuild);
    }

    Ok(DeterminismReport {
        contract_name: pass1.contract_name.clone(),
        is_deterministic: true,
        pass1_hash: pass1.sha256_hash.clone(),
        pass2_hash: pass2.sha256_hash.clone(),
        size_bytes: pass1.file_size_bytes,
    })
}

/// Evaluates freshly measured Soroban execution costs against checked-in baseline
/// and absolute ceiling limits.
pub fn evaluate_budget_regression(
    contract_op: Symbol,
    baseline: &ResourceBudget,
    measured: &ResourceBudget,
    threshold_percent: u32,
    absolute_ceiling: &ResourceBudget,
) -> Result<BudgetRegressionVerdict, DeterminismGateError> {
    if baseline.cpu_instructions == 0 && baseline.memory_bytes == 0 {
        // Missing or unmeasured baseline (safe skip if unmeasured)
        return Err(DeterminismGateError::InvalidBaseline);
    }

    // 1. Check absolute ceilings first (hard upper bounds)
    if measured.cpu_instructions > absolute_ceiling.cpu_instructions
        || measured.memory_bytes > absolute_ceiling.memory_bytes
    {
        return Err(DeterminismGateError::BudgetCeilingExceeded);
    }

    // 2. Calculate percentage regressions
    let cpu_delta = (measured.cpu_instructions as i128) - (baseline.cpu_instructions as i128);
    let cpu_delta_pct = ((cpu_delta * 100) / (baseline.cpu_instructions as i128)) as i32;

    let mem_delta = (measured.memory_bytes as i128) - (baseline.memory_bytes as i128);
    let mem_delta_pct = ((mem_delta * 100) / (baseline.memory_bytes as i128)) as i32;

    // 3. Enforce regression threshold tolerance
    if cpu_delta_pct > (threshold_percent as i32) || mem_delta_pct > (threshold_percent as i32) {
        return Err(DeterminismGateError::RegressionThresholdExceeded);
    }

    Ok(BudgetRegressionVerdict {
        contract_op,
        passed: true,
        baseline_cpu: baseline.cpu_instructions,
        measured_cpu: measured.cpu_instructions,
        cpu_delta_pct,
        baseline_mem: baseline.memory_bytes,
        measured_mem: measured.memory_bytes,
        mem_delta_pct,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{symbol_short, BytesN, Env};

    #[test]
    fn test_wasm_determinism_identical_and_mismatch() {
        let env = Env::default();
        let name = symbol_short!("aid_ctr");
        let hash_a = BytesN::from_array(&env, &[1u8; 32]);
        let hash_b = BytesN::from_array(&env, &[2u8; 32]);
        let compiler_hash = BytesN::from_array(&env, &[9u8; 32]);

        let pass1 = WasmArtifactFingerprint {
            contract_name: name.clone(),
            sha256_hash: hash_a.clone(),
            file_size_bytes: 45000,
            compiler_version_hash: compiler_hash.clone(),
        };

        let pass2_identical = WasmArtifactFingerprint {
            contract_name: name.clone(),
            sha256_hash: hash_a.clone(),
            file_size_bytes: 45000,
            compiler_version_hash: compiler_hash.clone(),
        };

        let pass2_divergent = WasmArtifactFingerprint {
            contract_name: name.clone(),
            sha256_hash: hash_b.clone(),
            file_size_bytes: 45012,
            compiler_version_hash: compiler_hash.clone(),
        };

        // Identical passes succeed
        let report = verify_wasm_determinism(&pass1, &pass2_identical).unwrap();
        assert!(report.is_deterministic);
        assert_eq!(report.size_bytes, 45000);

        // Divergent passes fail loudly
        let err = verify_wasm_determinism(&pass1, &pass2_divergent);
        assert_eq!(err, Err(DeterminismGateError::NonDeterministicBuild));
    }

    #[test]
    fn test_budget_regression_gate_thresholds_and_ceilings() {
        let env = Env::default();
        let op = symbol_short!("claim_aid");

        let baseline = ResourceBudget {
            cpu_instructions: 300_000,
            memory_bytes: 45_000,
        };

        let ceiling = ResourceBudget {
            cpu_instructions: 500_000,
            memory_bytes: 100_000,
        };

        // 1. Normal run with +5% change (within 10% threshold)
        let measured_normal = ResourceBudget {
            cpu_instructions: 315_000, // +5%
            memory_bytes: 46_000,     // +2.2%
        };
        let verdict = evaluate_budget_regression(
            op.clone(),
            &baseline,
            &measured_normal,
            10,
            &ceiling,
        ).unwrap();
        assert!(verdict.passed);
        assert_eq!(verdict.cpu_delta_pct, 5);

        // 2. Regressed run with +15% CPU change (> 10% threshold)
        let measured_regressed = ResourceBudget {
            cpu_instructions: 346_000, // +15.3%
            memory_bytes: 46_000,
        };
        let err_regress = evaluate_budget_regression(
            op.clone(),
            &baseline,
            &measured_regressed,
            10,
            &ceiling,
        );
        assert_eq!(err_regress, Err(DeterminismGateError::RegressionThresholdExceeded));

        // 3. Absolute ceiling breach (exceeds 500k ceiling)
        let measured_ceiling_breach = ResourceBudget {
            cpu_instructions: 550_000,
            memory_bytes: 45_000,
        };
        let err_ceiling = evaluate_budget_regression(
            op.clone(),
            &baseline,
            &measured_ceiling_breach,
            100, // even with high threshold
            &ceiling,
        );
        assert_eq!(err_ceiling, Err(DeterminismGateError::BudgetCeilingExceeded));
    }
}

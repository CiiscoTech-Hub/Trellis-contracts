#!/usr/bin/env node
/**
 * Workspace WASM Determinism & Soroban Budget Regression Gate (Issue #546)
 *
 * Verifies byte-for-byte WASM build determinism and evaluates Soroban CPU/memory
 * metrics against testing/budget-baseline.json with regression threshold and
 * absolute ceiling bounds.
 *
 * Zero-dependency pure Node.js matching repo standards.
 */

"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const ROOT = path.resolve(__dirname, "..");
const BASELINE_PATH = path.join(ROOT, "testing", "budget-baseline.json");

function computeHash(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function verifyWasmDeterminism(pass1Buffer, pass2Buffer) {
  const hash1 = computeHash(pass1Buffer);
  const hash2 = computeHash(pass2Buffer);
  const size1 = pass1Buffer.length;
  const size2 = pass2Buffer.length;

  if (hash1 !== hash2 || size1 !== size2) {
    return {
      deterministic: false,
      hash1,
      hash2,
      size1,
      size2,
      error: "NonDeterministicBuild: SHA-256 binary fingerprint mismatch",
    };
  }

  return {
    deterministic: true,
    hash: hash1,
    size: size1,
  };
}

function evaluateBudgetRegression(baselineMetric, measured, thresholdPct = 10, absoluteCeiling = null) {
  const baselineCpu = baselineMetric.cpu_instructions;
  const baselineMem = baselineMetric.memory_bytes;

  if (!baselineCpu || !baselineMem) {
    return { skipped: true, reason: "Placeholder or unmeasured baseline metric" };
  }

  // 1. Check absolute ceilings
  if (absoluteCeiling) {
    if (measured.cpu_instructions > absoluteCeiling.max_cpu_instructions) {
      return {
        passed: false,
        error: `BudgetCeilingExceeded: CPU ${measured.cpu_instructions} > ceiling ${absoluteCeiling.max_cpu_instructions}`,
      };
    }
    if (measured.memory_bytes > absoluteCeiling.max_memory_bytes) {
      return {
        passed: false,
        error: `BudgetCeilingExceeded: Memory ${measured.memory_bytes} > ceiling ${absoluteCeiling.max_memory_bytes}`,
      };
    }
  }

  // 2. Relative regression calculation
  const cpuDelta = measured.cpu_instructions - baselineCpu;
  const cpuDeltaPct = (cpuDelta / baselineCpu) * 100;

  const memDelta = measured.memory_bytes - baselineMem;
  const memDeltaPct = (memDelta / baselineMem) * 100;

  if (cpuDeltaPct > thresholdPct) {
    return {
      passed: false,
      cpuDeltaPct: Number(cpuDeltaPct.toFixed(2)),
      memDeltaPct: Number(memDeltaPct.toFixed(2)),
      error: `RegressionThresholdExceeded: CPU regressed by ${cpuDeltaPct.toFixed(1)}% (threshold: ${thresholdPct}%)`,
    };
  }

  if (memDeltaPct > thresholdPct) {
    return {
      passed: false,
      cpuDeltaPct: Number(cpuDeltaPct.toFixed(2)),
      memDeltaPct: Number(memDeltaPct.toFixed(2)),
      error: `RegressionThresholdExceeded: Memory regressed by ${memDeltaPct.toFixed(1)}% (threshold: ${thresholdPct}%)`,
    };
  }

  return {
    passed: true,
    cpuDeltaPct: Number(cpuDeltaPct.toFixed(2)),
    memDeltaPct: Number(memDeltaPct.toFixed(2)),
  };
}

function runSelfTests() {
  console.log("=== Running WASM Determinism & Budget Regression Gate Self-Tests ===");

  let passed = true;

  // Test 1: WASM Determinism
  const fakeWasm = Buffer.from("\x00asm\x01\x00\x00\x00custom_data_section");
  const identicalWasm = Buffer.from("\x00asm\x01\x00\x00\x00custom_data_section");
  const mutatedWasm = Buffer.from("\x00asm\x01\x00\x00\x00mutated_data_section");

  const detRes = verifyWasmDeterminism(fakeWasm, identicalWasm);
  if (!detRes.deterministic) {
    console.error("FAIL: Identical WASM reported as non-deterministic");
    passed = false;
  } else {
    console.log("PASS: Identical WASM passes determinism check");
  }

  const nonDetRes = verifyWasmDeterminism(fakeWasm, mutatedWasm);
  if (nonDetRes.deterministic) {
    console.error("FAIL: Mutated WASM reported as deterministic");
    passed = false;
  } else {
    console.log("PASS: Mutated WASM fails determinism check as expected");
  }

  // Test 2: Budget Evaluation against baseline
  const baselineRaw = JSON.parse(fs.readFileSync(BASELINE_PATH, "utf-8"));
  const claimBaseline = baselineRaw.metrics["aid.claim_aid"];
  const normalCeiling = baselineRaw.load_test_budgets.normal;

  // Normal run (+3% within 10%)
  const normalRun = {
    cpu_instructions: Math.round(claimBaseline.cpu_instructions * 1.03),
    memory_bytes: Math.round(claimBaseline.memory_bytes * 1.02),
  };
  const evalNormal = evaluateBudgetRegression(claimBaseline, normalRun, 10, normalCeiling);
  if (!evalNormal.passed) {
    console.error("FAIL: Normal run within threshold failed");
    passed = false;
  } else {
    console.log(`PASS: Normal run within threshold passed (CPU +${evalNormal.cpuDeltaPct}%)`);
  }

  // Failure run (+15% exceeds 10%)
  const regressedRun = {
    cpu_instructions: Math.round(claimBaseline.cpu_instructions * 1.15),
    memory_bytes: claimBaseline.memory_bytes,
  };
  const evalRegressed = evaluateBudgetRegression(claimBaseline, regressedRun, 10, normalCeiling);
  if (evalRegressed.passed) {
    console.error("FAIL: Regressed run should have failed");
    passed = false;
  } else {
    console.log("PASS: Regressed run (>10%) rejected correctly");
  }

  // Retry path: uses retry budget (2x baseline)
  const retryCeiling = baselineRaw.load_test_budgets.retry;
  const retryRun = {
    cpu_instructions: Math.round(claimBaseline.cpu_instructions * 1.8),
    memory_bytes: Math.round(claimBaseline.memory_bytes * 1.5),
  };
  const evalRetry = evaluateBudgetRegression(claimBaseline, retryRun, 100, retryCeiling);
  if (!evalRetry.passed) {
    console.error("FAIL: Valid retry within retry budget failed");
    passed = false;
  } else {
    console.log("PASS: Valid retry run within 2x retry ceiling accepted");
  }

  // Absolute ceiling breach
  const ceilingBreachRun = {
    cpu_instructions: normalCeiling.max_cpu_instructions + 1000,
    memory_bytes: claimBaseline.memory_bytes,
  };
  const evalCeiling = evaluateBudgetRegression(claimBaseline, ceilingBreachRun, 200, normalCeiling);
  if (evalCeiling.passed) {
    console.error("FAIL: Absolute ceiling breach was not caught");
    passed = false;
  } else {
    console.log("PASS: Absolute ceiling breach rejected correctly");
  }

  if (!passed) {
    process.exit(1);
  }
  console.log("=== All WASM Determinism & Budget Regression Gate Tests PASSED ===\n");
}

if (require.main === module) {
  runSelfTests();
}

module.exports = {
  verifyWasmDeterminism,
  evaluateBudgetRegression,
};

#!/usr/bin/env node
/**
 * Master Verification Runner for Trellis-contracts issues:
 * - Issue #499: Trellis-contracts: Create synthetic monitoring for critical workflows
 * - Issue #326: Trellis: Build storage TTL renewal monitoring and repair tooling
 * - Issue #487: Trellis-contracts: Create dependency-aware public health status
 * - Issue #488: Trellis-contracts: Implement notification and webhook deduplication
 *
 * Runs the module test suites through the standalone issue-verification crate
 * (see scripts/issue-verification/README.md). Set CARGO_TOOLCHAIN=stable to
 * run with `cargo +stable`.
 */

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const MANIFEST = path.join(ROOT, "scripts", "issue-verification", "Cargo.toml");
const TOOLCHAIN = process.env.CARGO_TOOLCHAIN ? [`+${process.env.CARGO_TOOLCHAIN}`] : [];

const suites = [
  {
    issue: "#499",
    title: "Create synthetic monitoring for critical workflows",
    filter: "workflow_synthetic_monitor::",
    files: [
      "shared/src/workflow_synthetic_monitor.rs",
      "docs/WORKFLOW_SYNTHETIC_MONITORING.md",
    ],
    expectedTests: 5,
  },
  {
    issue: "#326",
    title: "Build storage TTL renewal monitoring and repair tooling",
    filter: "ttl_monitor_repair::",
    files: [
      "shared/src/ttl_monitor_repair.rs",
      "docs/STORAGE_TTL_MONITORING_REPAIR.md",
    ],
    expectedTests: 5,
  },
  {
    issue: "#487",
    title: "Create dependency-aware public health status",
    filter: "dependency_aware_health::",
    files: [
      "shared/src/dependency_aware_health.rs",
      "docs/DEPENDENCY_AWARE_PUBLIC_HEALTH.md",
    ],
    expectedTests: 5,
  },
  {
    issue: "#488",
    title: "Implement notification and webhook deduplication",
    filter: "unified_dedup::",
    files: [
      "shared/src/unified_dedup.rs",
      "docs/NOTIFICATION_WEBHOOK_DEDUPLICATION.md",
    ],
    expectedTests: 4,
  },
];

console.log("======================================================================");
console.log("TRELLIS-CONTRACTS: VERIFICATION RUNNER (Issues #499, #326, #487, #488)");
console.log("======================================================================\n");

let allPassed = true;
const results = [];

// 1. Verify required documentation and source files
console.log(">>> Checking required files and documentation...");
for (const suite of suites) {
  for (const file of suite.files) {
    const fullPath = path.join(ROOT, file);
    if (!fs.existsSync(fullPath)) {
      console.error(`  FAIL [${suite.issue}]: Missing file ${file}`);
      allPassed = false;
    } else {
      console.log(`  PASS [${suite.issue}]: Found ${file}`);
    }
  }
}
console.log("");

// 2. Run automated Rust tests via Cargo
for (const suite of suites) {
  console.log(`>>> Running Suite for Issue ${suite.issue}: ${suite.title} (${suite.filter}) ...`);
  const result = spawnSync(
    "cargo",
    [...TOOLCHAIN, "test", "--manifest-path", MANIFEST, suite.filter],
    { encoding: "utf8", env: process.env }
  );

  const output = `${result.stdout}\n${result.stderr}`;
  const match = output.match(/test result: (\w+)\. (\d+) passed; (\d+) failed/);
  const ran = match ? Number(match[2]) : 0;
  let passed = true;

  if (result.status !== 0 || !match || match[1] !== "ok") {
    process.stdout.write(output);
    passed = false;
  } else if (ran < suite.expectedTests) {
    console.error(`  FAIL: expected >= ${suite.expectedTests} tests, ran ${ran}`);
    passed = false;
  } else {
    console.log(`  PASS: ${ran} tests passed (0 failures)`);
  }

  allPassed = allPassed && passed;
  results.push({ ...suite, passed, ran });
  console.log(`>>> Issue ${suite.issue} result: ${passed ? "PASSED" : "FAILED"}\n`);
}

// 3. Final summary
console.log("======================================================================");
console.log("VERIFICATION SUMMARY");
console.log("======================================================================");
for (const r of results) {
  console.log(`  [${r.passed ? "PASS" : "FAIL"}] Issue ${r.issue}: ${r.title} (${r.ran || 0} tests)`);
}
console.log("======================================================================\n");

if (!allPassed) {
  console.error("❌ Verification failed. One or more suites did not pass.");
  process.exit(1);
} else {
  const totalRan = results.reduce((acc, curr) => acc + (curr.ran || 0), 0);
  console.log(`✅ All 4 issues successfully verified! (${totalRan} automated tests passed, zero failures)`);
  process.exit(0);
}

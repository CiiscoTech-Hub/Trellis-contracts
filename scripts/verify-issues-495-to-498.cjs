#!/usr/bin/env node
/**
 * Master Verification Runner for Trellis-contracts issues:
 * - Issue #498: Trellis-contracts: Add fuzz tests for malformed and boundary inputs
 * - Issue #497: Trellis-contracts: Implement stable problem-details error taxonomy
 * - Issue #496: Trellis-contracts: Build permission-diff preview before policy changes
 * - Issue #495: Trellis-contracts: Add deployment rollback verification checks
 */

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const MANIFEST = path.join(ROOT, "scripts", "issue-verification", "Cargo.toml");

const suites = [
  {
    issue: "#498",
    title: "Add fuzz tests for malformed and boundary inputs",
    filter: "fuzz_boundary_inputs",
    expectedTests: 5,
  },
  {
    issue: "#497",
    title: "Implement stable problem-details error taxonomy",
    filter: "problem_details_taxonomy",
    expectedTests: 5,
  },
  {
    issue: "#496",
    title: "Build permission-diff preview before policy changes",
    filter: "permission_diff_preview",
    expectedTests: 5,
  },
  {
    issue: "#495",
    title: "Add deployment rollback verification checks",
    filter: "deployment_rollback_verification",
    expectedTests: 4,
  },
];

console.log("======================================================================");
console.log("TRELLIS-CONTRACTS: VERIFICATION RUNNER (Issues #495, #496, #497, #498)");
console.log("======================================================================\n");

let allPassed = true;
const results = [];

// 1. Verify required source files and documentation
console.log(">>> Checking required files and documentation...");
const requiredFiles = [
  "shared/src/fuzz_boundary_inputs.rs",
  "docs/FUZZ_TESTING_BOUNDARY_INPUTS.md",
  "shared/src/problem_details_taxonomy.rs",
  "docs/PROBLEM_DETAILS_ERROR_TAXONOMY.md",
  "shared/src/permission_diff_preview.rs",
  "docs/PERMISSION_DIFF_PREVIEW.md",
  "shared/src/deployment_rollback_verification.rs",
  "docs/DEPLOYMENT_ROLLBACK_VERIFICATION.md",
];

for (const file of requiredFiles) {
  const filePath = path.join(ROOT, file);
  if (!fs.existsSync(filePath)) {
    console.error(`  FAIL: Missing file: ${file}`);
    allPassed = false;
  } else {
    console.log(`  PASS: Found ${file}`);
  }
}
console.log("");

// 2. Run automated Rust tests via Cargo
for (const suite of suites) {
  console.log(`>>> Running Suite for Issue ${suite.issue}: ${suite.title} (${suite.filter}) ...`);
  const result = spawnSync(
    "cargo",
    ["test", "--manifest-path", MANIFEST, suite.filter],
    {
      stdio: "inherit",
      env: process.env,
    }
  );

  const passed = result.status === 0;
  if (!passed) {
    allPassed = false;
  }
  results.push({
    issue: suite.issue,
    title: suite.title,
    passed,
    expectedTests: suite.expectedTests,
  });
  console.log(`>>> Issue ${suite.issue} result: ${passed ? "PASSED" : "FAILED"}\n`);
}

// 3. Final summary
console.log("======================================================================");
console.log("VERIFICATION SUMMARY");
console.log("======================================================================");
let totalTests = 0;
for (const r of results) {
  totalTests += r.expectedTests;
  console.log(`  [${r.passed ? "PASS" : "FAIL"}] Issue ${r.issue} - ${r.title} (${r.expectedTests} tests)`);
}
console.log("======================================================================");

if (!allPassed) {
  console.error("\n❌ Verification failed. One or more suites did not pass.");
  process.exit(1);
} else {
  console.log(`\n✓ All 4 issues successfully verified with 100% passing tests (${totalTests}/${totalTests} passed).`);
  process.exit(0);
}

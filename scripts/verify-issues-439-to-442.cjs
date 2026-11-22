#!/usr/bin/env node
/**
 * Master Verification Runner for Trellis-contracts issues:
 * - Issue #439: Add stale-cache detection with repair recommendations
 * - Issue #440: Create end-to-end failure injection for critical workflows
 * - Issue #441: Implement user-facing status for degraded dependencies
 * - Issue #442: Add property tests for boundary numeric and timestamp values
 */

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const MANIFEST = path.join(ROOT, "scripts", "issue-verification", "Cargo.toml");

const suites = [
  {
    issue: "#439",
    title: "Add stale-cache detection with repair recommendations",
    filter: "bounded_cache",
    expectedTests: 15,
  },
  {
    issue: "#440",
    title: "Create end-to-end failure injection for critical workflows",
    filter: "workflow_failure_injection",
    expectedTests: 5,
  },
  {
    issue: "#441",
    title: "Implement user-facing status for degraded dependencies",
    filter: "user_facing_degraded_status",
    expectedTests: 5,
  },
  {
    issue: "#442",
    title: "Add property tests for boundary numeric and timestamp values",
    filter: "test_boundary_properties",
    expectedTests: 5,
  },
];

console.log("======================================================================");
console.log("TRELLIS-CONTRACTS: VERIFICATION RUNNER (Issues #439, #440, #441, #442)");
console.log("======================================================================\n");

let allPassed = true;
const results = [];

// 1. Verify required documentation and implementation files
console.log(">>> Checking required files and artifacts...");
const requiredFiles = [
  "implementation.md",
  "shared/src/bounded_cache.rs",
  "shared/src/workflow_failure_injection.rs",
  "shared/src/user_facing_degraded_status.rs",
  "shared/src/test_boundary_properties.rs",
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
    ["test", "--manifest-path", MANIFEST, suite.filter, "--offline"],
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
  });
  console.log(`>>> Issue ${suite.issue} result: ${passed ? "PASSED" : "FAILED"}\n`);
}

console.log("======================================================================");
console.log("VERIFICATION SUMMARY");
console.log("======================================================================");
for (const r of results) {
  const status = r.passed ? "PASS" : "FAIL";
  console.log(`  [${status}] Issue ${r.issue}: ${r.title}`);
}
console.log("======================================================================\n");

if (allPassed) {
  console.log("All 4 issues verified and passing successfully!");
  process.exit(0);
} else {
  console.error("Verification failed. One or more suites did not pass.");
  process.exit(1);
}


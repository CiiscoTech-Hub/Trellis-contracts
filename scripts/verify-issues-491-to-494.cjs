#!/usr/bin/env node
/**
 * Master Verification Runner for Trellis-contracts issues:
 * - Issue #494: Implement ownership transfer acceptance and expiry
 * - Issue #493: Create rare-failure fixture generator
 * - Issue #492: Add deterministic sorting for status and event lists
 * - Issue #491: Implement security-event session invalidation
 */

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const MANIFEST = path.join(ROOT, "scripts", "issue-verification", "Cargo.toml");
const TOOLCHAIN = process.env.CARGO_TOOLCHAIN ? [`+${process.env.CARGO_TOOLCHAIN}`] : [`+1.85.0-x86_64-pc-windows-gnu`];

const suites = [
  {
    issue: "#494",
    title: "Implement ownership transfer acceptance and expiry",
    filter: "ownership_transfer_manager",
    files: [
      "shared/src/ownership_transfer_manager.rs",
      "docs/OWNERSHIP_TRANSFER_MANAGER.md",
    ],
    expectedTests: 5,
  },
  {
    issue: "#493",
    title: "Create rare-failure fixture generator",
    filter: "rare_failure_fixtures",
    files: [
      "shared/src/rare_failure_fixtures.rs",
      "docs/RARE_FAILURE_FIXTURE_GENERATOR.md",
    ],
    expectedTests: 4,
  },
  {
    issue: "#492",
    title: "Add deterministic sorting for status and event lists",
    filter: "deterministic_sort",
    files: [
      "shared/src/deterministic_sort.rs",
      "docs/DETERMINISTIC_SORTING.md",
    ],
    expectedTests: 7,
  },
  {
    issue: "#491",
    title: "Implement security-event session invalidation",
    filter: "session_invalidation",
    files: [
      "shared/src/session_invalidation.rs",
      "docs/SECURITY_EVENT_SESSION_INVALIDATION.md",
    ],
    expectedTests: 6,
  },
];

console.log("======================================================================");
console.log("TRELLIS-CONTRACTS: VERIFICATION RUNNER (Issues #491, #492, #493, #494)");
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

  if (result.status !== 0 || ran < suite.expectedTests) {
    console.error(`  FAIL: ${suite.filter} failed or ran fewer than expected tests (expected ${suite.expectedTests}, got ${ran})`);
    console.error(output);
    passed = false;
    allPassed = false;
  } else {
    console.log(`  PASS: ${ran} tests passed for ${suite.filter}`);
  }

  results.push({
    issue: suite.issue,
    title: suite.title,
    filter: suite.filter,
    passed,
    ran,
  });
  console.log(`>>> Issue ${suite.issue} result: ${passed ? "PASSED" : "FAILED"}\n`);
}

console.log("======================================================================");
console.log("VERIFICATION SUMMARY");
console.log("======================================================================");
for (const r of results) {
  const status = r.passed ? "PASS" : "FAIL";
  console.log(`[${status}] Issue ${r.issue} - ${r.title} (${r.ran} tests)`);
}
console.log("======================================================================");

if (!allPassed) {
  console.error("\n❌ Verification failed. Fix reported issues above.");
  process.exit(1);
} else {
  console.log("\n✓ All 4 issues successfully verified with 100% passing tests.");
  process.exit(0);
}

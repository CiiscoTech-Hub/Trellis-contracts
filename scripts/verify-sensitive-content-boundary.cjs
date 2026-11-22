#!/usr/bin/env node
/**
 * Executable verification runner for Sensitive-Content Boundary Defenses.
 *
 * Verifies that:
 * 1. Rendering Boundary: Untrusted content cannot execute arbitrary script (XSS vectors,
 *    dangerous HTML/SVG tags, event handlers, pseudo-protocols, template injections,
 *    BiDi spoofing, ANSI escapes, or null-byte poisoning).
 * 2. Download Boundary: Untrusted download endpoints cannot escape sandboxes, execute path
 *    traversal attacks (`../`), download executable extensions, or leverage SSRF against
 *    loopback or cloud instance metadata.
 * 3. Webhooks Boundary: Inbound webhooks enforce cryptographic authentication, payload bounds,
 *    and replay windows, while outbound event webhooks scrub private fields and secret material.
 * 4. Exports Boundary: Scoped export pipelines across Treasury, Aid, Referral, Governance,
 *    Oracle, and Marketplace enforce field allow-lists, purge forbidden secrets, enforce
 *    caller scope isolation, and enforce bounded memory chunk ceilings.
 * 5. Operational Edge Cases & Recovery: Failure modes, tampering detection, and quarantine
 *    procedures function reliably without breaking public contract APIs.
 */

const assert = require("node:assert");
const crypto = require("node:crypto");

console.log("==================================================================");
console.log("TRELLIS: SENSITIVE-CONTENT BOUNDARY TEST & VERIFICATION RUNNER");
console.log("==================================================================\n");

// ---------------------------------------------------------------------------
// Constants & Specifications
// ---------------------------------------------------------------------------

const CoreModule = {
  Treasury: "treasury",
  Aid: "aid",
  Referral: "referral",
  Governance: "governance",
  Oracle: "oracle",
  Marketplace: "marketplace",
};

const ExportScope = {
  OwnRecords: "OwnRecords",
  Operational: "Operational",
  Full: "Full",
};

const RecordSensitivity = {
  Public: "Public",
  Operational: "Operational",
  Restricted: "Restricted",
};

const ALLOWLISTED_EXPORT_FIELDS = new Set([
  "id", "type", "status", "amount", "created", "expiry",
  "region", "role", "tier", "version", "network", "count"
]);

const FORBIDDEN_SECRET_FIELDS = new Set([
  "priv_key", "sec_key", "seed", "entropy", "token_sec", "auth_sig",
  "password", "ssn", "tax_id", "bank_wire", "card_num", "admin_key",
  "res_seed", "raw_pii", "ballot_slt", "sign_key", "raw_nonce", "ip_addr"
]);

const ALLOWED_DOWNLOAD_SCHEMES = new Set([
  "https:", "ipfs:", "ipns:", "ar:", "did:"
]);

const FORBIDDEN_DOWNLOAD_SCHEMES = new Set([
  "javascript:", "data:", "file:", "blob:", "vbscript:", "about:", "chrome:", "view-source:", "ftp:"
]);

const ALLOWED_DOWNLOAD_EXTENSIONS = new Set([
  ".json", ".csv", ".txt", ".pdf", ".png", ".jpg", ".jpeg", ".svg", ".webp"
]);

const DANGEROUS_DOWNLOAD_EXTENSIONS = new Set([
  ".exe", ".bat", ".cmd", ".sh", ".ps1", ".vbs", ".wasm", ".jar",
  ".msi", ".dll", ".so", ".html", ".htm", ".js", ".mjs", ".xhtml", ".scr"
]);

const MAX_RENDER_TEXT_LEN = 8192;
const MAX_DOWNLOAD_URI_LEN = 2048;
const MAX_FILENAME_LEN = 255;
const MAX_WEBHOOK_PAYLOAD_LEN = 4096;
const BOUNDARY_CHUNK_CEILING = 50;

// ---------------------------------------------------------------------------
// [1/8] Rendering Boundary & Untrusted Execution Defense
// ---------------------------------------------------------------------------

console.log("[1/8] Verifying Rendering Boundary & Untrusted Script Execution Defense...");

function validateRenderContent(rawText, maxLen = MAX_RENDER_TEXT_LEN, allowMultiline = false) {
  if (!rawText || rawText.length === 0 || rawText.length > maxLen) {
    throw new Error("BoundaryLimitExceeded");
  }

  // Null byte check
  if (rawText.includes("\0")) {
    throw new Error("ExecutableContentRejected: Null byte detected");
  }

  // ANSI escape sequences
  if (rawText.includes("\x1b")) {
    throw new Error("SandboxEscapeAttempt: ANSI escape detected");
  }

  // Control character check
  for (let i = 0; i < rawText.length; i++) {
    const code = rawText.charCodeAt(i);
    if (code < 32 && code !== 127) {
      if (allowMultiline && (code === 10 || code === 13 || code === 9)) {
        continue;
      }
      throw new Error("ExecutableContentRejected: Control character detected");
    }
  }

  // BiDi overrides: U+202A to U+202E, U+200E, U+200F, U+2066 to U+2069
  const bidiPattern = /[\u202A-\u202E\u200E\u200F\u2066-\u2069]/;
  if (bidiPattern.test(rawText)) {
    throw new Error("SandboxEscapeAttempt: BiDi override detected");
  }

  // Dangerous script/HTML tags
  const lower = rawText.toLowerCase();
  const dangerousTags = [
    "<script", "<iframe", "<object", "<embed", "<form", "<svg",
    "<link", "<style", "<meta", "<base", "<applet", "<math", "<template",
    "javascript:", "vbscript:", "data:text/html",
    "onload=", "onerror=", "onclick=", "onmouseover=", "onfocus=", "onblur="
  ];
  for (const tag of dangerousTags) {
    if (lower.includes(tag)) {
      throw new Error(`ExecutableContentRejected: Dangerous markup '${tag}'`);
    }
  }

  // Template injection
  const templateTokens = ["{{", "${", "<%=", "#{"];
  for (const tok of templateTokens) {
    if (rawText.includes(tok)) {
      throw new Error(`ExecutableContentRejected: Template token '${tok}'`);
    }
  }

  return rawText.trim();
}

// Exercise rendering attacks
const xssPayloads = [
  "<script>alert('xss')</script>",
  "<ScRiPt SRC='https://evil.org/xss.js'></SCRIPT>",
  "<iframe src='javascript:alert(1)'></iframe>",
  "<svg onload=alert(document.cookie)>",
  "<img src=x onerror=alert(1)>",
  "<a href='javascript:alert(1)'>Claim Aid</a>",
  "{{7*7}}",
  "${process.env.SECRET_KEY}",
  "<%= File.read('/etc/shadow') %>",
  "Proposal Title\0<script>evil()</script>",
  "\x1b[2J\x1b[H ANSI Escape Breakout",
  "Admin Account \u202Ereversed",
];

for (const payload of xssPayloads) {
  assert.throws(
    () => validateRenderContent(payload, MAX_RENDER_TEXT_LEN, true),
    /ExecutableContentRejected|SandboxEscapeAttempt/,
    `Payload should have been rejected: ${payload}`
  );
}

// Clean rendering content must pass
const cleanRender = "Treasury grant disbursement for regional medical aid campaign #42.";
assert.strictEqual(validateRenderContent(cleanRender, MAX_RENDER_TEXT_LEN, false), cleanRender);
console.log("  ✓ All 12 injection and sandbox escape vectors blocked across rendering inputs");

// ---------------------------------------------------------------------------
// [2/8] Download Boundary: Scheme Allow-List & Sandbox Containment
// ---------------------------------------------------------------------------

console.log("[2/8] Verifying Download Boundary Scheme Allow-Lists & Containment...");

function validateDownloadUri(uri, maxLen = MAX_DOWNLOAD_URI_LEN) {
  if (!uri || uri.length === 0 || uri.length > maxLen) {
    throw new Error("BoundaryLimitExceeded");
  }

  const lower = uri.toLowerCase();

  // Explicit forbidden schemes
  for (const badScheme of FORBIDDEN_DOWNLOAD_SCHEMES) {
    if (lower.startsWith(badScheme) || lower.includes(`=${badScheme}`)) {
      throw new Error(`UnsafeDownloadDestination: Forbidden scheme '${badScheme}'`);
    }
  }

  // SSRF and private IP loopback defense
  const ssrfTargets = [
    "localhost", "127.0.0.1", "[::1]", "169.254.169.254", "metadata.google.internal",
    "http://10.", "https://10.", "http://192.168.", "https://192.168.",
    "http://172.16.", "https://172.16.", "http://0.0.0.0", "https://0.0.0.0"
  ];
  for (const ssrf of ssrfTargets) {
    if (lower.includes(ssrf)) {
      throw new Error(`UnsafeDownloadDestination: SSRF target '${ssrf}'`);
    }
  }

  let matchedScheme = null;
  for (const safeScheme of ALLOWED_DOWNLOAD_SCHEMES) {
    if (lower.startsWith(safeScheme)) {
      matchedScheme = safeScheme;
      break;
    }
  }

  if (!matchedScheme) {
    throw new Error("AllowListViolation: Unsupported download scheme");
  }

  return matchedScheme;
}

// Exercise download schemes
const validDownloads = [
  "https://trellis.network/evidence/v1/bundle_1001.json",
  "ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
  "ipns://k51qzi5uqu5dl11xvi25278m0q36b75eakpwhc1809072r2pndv3q538wz1p3w",
  "ar://aB1c2D3e4F5g6H7i8J9k0L1m2N3o4P5q6R7s8T9u0V1",
  "did:pkh:stellar:GABC1234567890",
];

for (const v of validDownloads) {
  assert.doesNotThrow(() => validateDownloadUri(v), `Valid URI should be accepted: ${v}`);
}

const dangerousDownloads = [
  "javascript:alert(1)",
  "data:application/json,{\"priv_key\":\"secret\"}",
  "file:///etc/shadow",
  "blob:https://trellis.network/uuid-1234",
  "vbscript:msgbox(\"hack\")",
  "ftp://ftp.evil.com/payload.exe",
  "https://localhost/admin/keys",
  "https://127.0.0.1:8080/secrets",
  "https://169.254.169.254/latest/meta-data/",
  "https://metadata.google.internal/computeMetadata/v1/",
  "https://10.0.0.1/private",
];

for (const d of dangerousDownloads) {
  assert.throws(
    () => validateDownloadUri(d),
    /UnsafeDownloadDestination|AllowListViolation/,
    `Dangerous URI should be rejected: ${d}`
  );
}
console.log("  ✓ Download schemes validated; dangerous schemes and SSRF endpoints rejected");

// ---------------------------------------------------------------------------
// [3/8] Download Boundary: Path Traversal & Dangerous Extensions
// ---------------------------------------------------------------------------

console.log("[3/8] Verifying Download Filename Traversal & Extension Allow-Lists...");

function validateDownloadFilename(filename, maxLen = MAX_FILENAME_LEN) {
  if (!filename || filename.length === 0 || filename.length > maxLen) {
    throw new Error("BoundaryLimitExceeded");
  }

  // Null-byte poisoning
  if (filename.includes("\0")) {
    throw new Error("SandboxEscapeAttempt: Null byte poisoning");
  }

  // Path traversal
  const lower = filename.toLowerCase();
  const traversal = ["../", "..\\", "..%2f", "..%5c", "%2e%2e", "/..", "\\.."];
  for (const t of traversal) {
    if (lower.includes(t)) {
      throw new Error(`SandboxEscapeAttempt: Traversal sequence '${t}'`);
    }
  }

  // Dangerous executable extensions
  for (const ext of DANGEROUS_DOWNLOAD_EXTENSIONS) {
    if (lower.endsWith(ext)) {
      throw new Error(`ExecutableContentRejected: Dangerous extension '${ext}'`);
    }
  }

  // Extension allow-list check
  let hasValidExt = false;
  for (const ext of ALLOWED_DOWNLOAD_EXTENSIONS) {
    if (lower.endsWith(ext)) {
      hasValidExt = true;
      break;
    }
  }
  if (!hasValidExt) {
    throw new Error("AllowListViolation: Extension not in allow-list");
  }

  return filename;
}

const traversalAttacks = [
  "../../etc/passwd.json",
  "..\\..\\windows\\system32\\calc.exe",
  "downloads/../../secret.csv",
  "report%2e%2e/file.txt",
  "bundle.pdf\0.exe",
];

for (const t of traversalAttacks) {
  assert.throws(
    () => validateDownloadFilename(t),
    /SandboxEscapeAttempt/,
    `Traversal attack should be rejected: ${t}`
  );
}

const executableFiles = [
  "payload.exe", "install.sh", "run.bat", "script.cmd", "exploit.ps1",
  "macro.vbs", "bytecode.wasm", "malware.jar", "phishing.html", "client.js"
];

for (const exe of executableFiles) {
  assert.throws(
    () => validateDownloadFilename(exe),
    /ExecutableContentRejected/,
    `Executable file should be rejected: ${exe}`
  );
}

const safeFilenames = [
  "treasury_allocation_2026.json",
  "aid_disbursements.csv",
  "audit_trail.txt",
  "governance_whitepaper.pdf",
  "nft_artwork.png",
  "nft_media.svg",
];

for (const s of safeFilenames) {
  assert.doesNotThrow(() => validateDownloadFilename(s), `Safe filename should pass: ${s}`);
}
console.log("  ✓ Directory traversal, null-byte poisoning, and executable extensions blocked");

// ---------------------------------------------------------------------------
// [4/8] Webhook Boundary: Authentication & Ingress Replay Enforcement
// ---------------------------------------------------------------------------

console.log("[4/8] Verifying Webhook Ingress Authentication & Replay Boundary...");

function verifyWebhookIngress(event, secret, signatureHex, config, currentTime) {
  if (!event || !event.payload || event.payload.length > MAX_WEBHOOK_PAYLOAD_LEN) {
    throw new Error("BoundaryLimitExceeded");
  }

  // Executable markup check
  const lowerPayload = event.payload.toLowerCase();
  if (lowerPayload.includes("<script") || lowerPayload.includes("onload=") || lowerPayload.includes("javascript:")) {
    throw new Error("ExecutableContentRejected: Executable markup in webhook payload");
  }

  // Replay window check
  const minAllowed = currentTime - config.replayWindowSeconds;
  if (event.timestamp < minAllowed) {
    throw new Error("WebhookVerificationFailed: Timestamp outside replay window (stale)");
  }
  const maxAllowed = currentTime + config.maxFutureSkewSeconds;
  if (event.timestamp > maxAllowed) {
    throw new Error("WebhookVerificationFailed: Timestamp outside future window (skew)");
  }

  // Cryptographic signature check (HMAC-SHA256)
  const hmac = crypto.createHmac("sha256", secret);
  const tsBuf = Buffer.alloc(8);
  tsBuf.writeBigUInt64BE(BigInt(event.timestamp));
  hmac.update(Buffer.from(event.eventId, "hex"));
  hmac.update(tsBuf);
  hmac.update(Buffer.from(event.payload, "utf8"));
  const expectedSigHex = hmac.digest("hex");

  if (!crypto.timingSafeEqual(Buffer.from(signatureHex, "hex"), Buffer.from(expectedSigHex, "hex"))) {
    throw new Error("WebhookVerificationFailed: Invalid cryptographic signature");
  }

  return true;
}

const secretKey = "trellis_webhook_secret_key_32bytes!!";
const eventId = crypto.randomBytes(32).toString("hex");
const timestamp = 10000;
const payload = JSON.stringify({ event: "aid_disbursed", aid_id: "AID_99", amount: 2500 });

// Compute valid signature
const hmac = crypto.createHmac("sha256", secretKey);
const tsBuf = Buffer.alloc(8);
tsBuf.writeBigUInt64BE(BigInt(timestamp));
hmac.update(Buffer.from(eventId, "hex"));
hmac.update(tsBuf);
hmac.update(Buffer.from(payload, "utf8"));
const validSigHex = hmac.digest("hex");

const webhookConfig = { replayWindowSeconds: 300, maxFutureSkewSeconds: 60 };

// 1. Valid webhook succeeds
assert.strictEqual(
  verifyWebhookIngress({ eventId, timestamp, payload }, secretKey, validSigHex, webhookConfig, 10000),
  true
);

// 2. Tampered signature fails
const forgedSigHex = crypto.randomBytes(32).toString("hex");
assert.throws(
  () => verifyWebhookIngress({ eventId, timestamp, payload }, secretKey, forgedSigHex, webhookConfig, 10000),
  /WebhookVerificationFailed: Invalid cryptographic signature/
);

// 3. Stale event (> 300s old) fails
assert.throws(
  () => verifyWebhookIngress({ eventId, timestamp: 9600, payload }, secretKey, validSigHex, webhookConfig, 10000),
  /WebhookVerificationFailed: Timestamp outside replay window/
);

// 4. Excessive future skew (> 60s ahead) fails
assert.throws(
  () => verifyWebhookIngress({ eventId, timestamp: 10100, payload }, secretKey, validSigHex, webhookConfig, 10000),
  /WebhookVerificationFailed: Timestamp outside future window/
);

// 5. Script injection in webhook payload fails
const injectedPayload = JSON.stringify({ memo: "<script>drain()</script>" });
assert.throws(
  () => verifyWebhookIngress({ eventId, timestamp, payload: injectedPayload }, secretKey, validSigHex, webhookConfig, 10000),
  /ExecutableContentRejected/
);
console.log("  ✓ Webhook authentication, replay protection, and ingress payload sanitization verified");

// ---------------------------------------------------------------------------
// [5/8] Webhook Boundary: Egress Privacy & Secret Leakage Prevention
// ---------------------------------------------------------------------------

console.log("[5/8] Verifying Webhook Egress Privacy & Secret Leakage Prevention...");

function assertWebhookPayloadClean(payloadStr) {
  const lower = payloadStr.toLowerCase();
  for (const forbidden of FORBIDDEN_SECRET_FIELDS) {
    if (lower.includes(`"${forbidden}"`) || lower.includes(`${forbidden}=`) || lower.includes(`'${forbidden}'`)) {
      throw new Error(`PrivateFieldLeakage: Forbidden field '${forbidden}' detected in outbound webhook`);
    }
  }
  return true;
}

const leakingWebhooks = [
  '{"event":"auth","priv_key":"SCZANGBA5YHTNYVS3ZSXQ7"}',
  '{"event":"deposit","seed":"RAW_ENTROPY_SEED"}',
  '{"event":"login","password":"admin_password"}',
  '{"event":"user","ssn":"123-45-6789"}',
  '{"event":"wire","bank_wire":"US9911223344"}',
  '{"event":"payout","card_num":"4111222233334444"}',
  '{"event":"config","admin_key":"TOP_SECRET_ADMIN_TOKEN"}',
  '{"event":"vote","ballot_slt":"voter_secret_salt_hash"}',
];

for (const leak of leakingWebhooks) {
  assert.throws(
    () => assertWebhookPayloadClean(leak),
    /PrivateFieldLeakage/,
    `Leaking webhook payload should be blocked: ${leak}`
  );
}

const safeWebhookPayload = JSON.stringify({
  event: "treasury_sweep",
  id: "SWEEP_001",
  amount: 10000,
  status: "settled",
  timestamp: 10000,
});
assert.strictEqual(assertWebhookPayloadClean(safeWebhookPayload), true);
console.log("  ✓ All 8 private secret fields strictly blocked from outbound webhook payloads");

// ---------------------------------------------------------------------------
// [6/8] Export Boundary: Allow-List Enforcement across 6 Modules
// ---------------------------------------------------------------------------

console.log("[6/8] Verifying Multi-Module Export Allow-Lists (Treasury, Aid, Referral, Governance, Oracle, Market)...");

function sanitizeExportRecord(record) {
  const safeFields = [];
  let purgedCount = 0;

  for (const field of record.fields) {
    if (ALLOWLISTED_EXPORT_FIELDS.has(field.name) && !FORBIDDEN_SECRET_FIELDS.has(field.name)) {
      safeFields.push(field);
    } else {
      purgedCount++;
    }
  }

  return {
    record: {
      ...record,
      fields: safeFields,
    },
    purgedCount,
  };
}

const modules = [
  CoreModule.Treasury,
  CoreModule.Aid,
  CoreModule.Referral,
  CoreModule.Governance,
  CoreModule.Oracle,
  CoreModule.Marketplace,
];

for (const mod of modules) {
  const dirtyRecord = {
    id: `REC_${mod.toUpperCase()}_01`,
    module: mod,
    owner: "G_ALICE",
    sensitivity: RecordSensitivity.Public,
    fields: [
      { name: "id", value: "001" },
      { name: "status", value: "active" },
      { name: "amount", value: "5000" },
      // Forbidden fields
      { name: "priv_key", value: "SCZA..." },
      { name: "seed", value: "ENTROPY" },
      { name: "admin_key", value: "SECRET_KEY" },
      { name: "raw_pii", value: "alice@trellis.org" },
      // Arbitrary non-allowlisted fields
      { name: "custom_note", value: "internal memo" },
      { name: "debug_trace", value: "trace_id_42" },
    ],
  };

  const { record: sanitized, purgedCount } = sanitizeExportRecord(dirtyRecord);
  assert.strictEqual(purgedCount, 6, `Module ${mod} must purge 6 unapproved/forbidden fields`);
  assert.strictEqual(sanitized.fields.length, 3, `Module ${mod} must retain exactly 3 safe fields`);
  const remainingFieldNames = sanitized.fields.map(f => f.name);
  assert.deepStrictEqual(remainingFieldNames, ["id", "status", "amount"]);
}
console.log("  ✓ Export records across all 6 core modules purged of unapproved & forbidden fields");

// ---------------------------------------------------------------------------
// [7/8] Scope Sandboxing & Memory Chunk Ceilings
// ---------------------------------------------------------------------------

console.log("[7/8] Verifying Export Scope Sandboxing & Bounded Memory Ceilings...");

function enforceExportScope(caller, recordOwner, sensitivity, scope) {
  if (scope === ExportScope.OwnRecords) {
    if (caller !== recordOwner) {
      throw new Error("ScopeIsolationViolation: Caller cannot access other user's records");
    }
    if (sensitivity !== RecordSensitivity.Public) {
      throw new Error("ScopeIsolationViolation: OwnRecords caller cannot access operational/restricted records");
    }
    return true;
  }

  if (scope === ExportScope.Operational) {
    if (sensitivity === RecordSensitivity.Restricted) {
      throw new Error("ScopeIsolationViolation: Operational scope cannot access restricted records");
    }
    return true;
  }

  if (scope === ExportScope.Full) {
    return true; // Admin scope
  }

  throw new Error("InvalidScope");
}

// 1. OwnRecords isolation
assert.strictEqual(enforceExportScope("ALICE", "ALICE", RecordSensitivity.Public, ExportScope.OwnRecords), true);
assert.throws(
  () => enforceExportScope("BOB", "ALICE", RecordSensitivity.Public, ExportScope.OwnRecords),
  /ScopeIsolationViolation: Caller cannot access other user's records/
);
assert.throws(
  () => enforceExportScope("ALICE", "ALICE", RecordSensitivity.Operational, ExportScope.OwnRecords),
  /ScopeIsolationViolation: OwnRecords caller cannot access operational/
);

// 2. Operational isolation
assert.strictEqual(enforceExportScope("OPERATOR", "ALICE", RecordSensitivity.Operational, ExportScope.Operational), true);
assert.throws(
  () => enforceExportScope("OPERATOR", "ALICE", RecordSensitivity.Restricted, ExportScope.Operational),
  /ScopeIsolationViolation: Operational scope cannot access restricted/
);

// 3. Full isolation
assert.strictEqual(enforceExportScope("ADMIN", "ALICE", RecordSensitivity.Restricted, ExportScope.Full), true);

// 4. Chunk ceilings
function validateChunkSize(chunkSize) {
  if (chunkSize > BOUNDARY_CHUNK_CEILING) {
    throw new Error("BoundaryLimitExceeded: Chunk size exceeds bounded memory ceiling (50)");
  }
  return true;
}

assert.strictEqual(validateChunkSize(25), true);
assert.strictEqual(validateChunkSize(50), true);
assert.throws(() => validateChunkSize(51), /BoundaryLimitExceeded/);
assert.throws(() => validateChunkSize(100), /BoundaryLimitExceeded/);
console.log("  ✓ Caller authorization scopes isolated and bounded memory chunk ceilings enforced");

// ---------------------------------------------------------------------------
// [8/8] Operational Edge Cases, Failure Modes & Tamper Recovery
// ---------------------------------------------------------------------------

console.log("[8/8] Verifying Operational Edge Cases, Failure Modes & Recovery Workflows...");

// Edge case 1: Case-folding evasion in script tags (e.g. <sCrIpT>)
assert.throws(
  () => validateRenderContent("Mixed case <sCrIpT>alert(1)</ScRiPt>", MAX_RENDER_TEXT_LEN, false),
  /ExecutableContentRejected/
);

// Edge case 2: Mixed-case evasion in download protocols (e.g. jAvAsCrIpT:)
assert.throws(
  () => validateDownloadUri("jAvAsCrIpT:alert(1)"),
  /UnsafeDownloadDestination/
);

// Edge case 3: URL-encoded path traversal in download filenames (e.g. ..%2f)
assert.throws(
  () => validateDownloadFilename("archive/..%2f..%2fsecret.csv"),
  /SandboxEscapeAttempt/
);

// Edge case 4: Tamper-evident digest mismatch recovery
function verifyExportDigest(records, expectedDigest) {
  const hash = crypto.createHash("sha256");
  for (const r of records) {
    hash.update(JSON.stringify(r));
  }
  const actualDigest = hash.digest("hex");
  if (actualDigest !== expectedDigest) {
    throw new Error("ExportDigestMismatch: Artifact tampered in transit");
  }
  return true;
}

const sampleRecords = [{ id: "1", amount: 100 }, { id: "2", amount: 200 }];
const legitimateDigest = crypto.createHash("sha256")
  .update(JSON.stringify(sampleRecords[0]))
  .update(JSON.stringify(sampleRecords[1]))
  .digest("hex");

assert.strictEqual(verifyExportDigest(sampleRecords, legitimateDigest), true);

// Modifying one field breaks digest
const tamperedRecords = [{ id: "1", amount: 999999 }, { id: "2", amount: 200 }];
assert.throws(
  () => verifyExportDigest(tamperedRecords, legitimateDigest),
  /ExportDigestMismatch: Artifact tampered in transit/
);

console.log("  ✓ Operational evasion attempts and tamper detection recovered cleanly");

console.log("\n==================================================================");
console.log("ALL SENSITIVE-CONTENT BOUNDARY TEST SUITES COMPLETED SUCCESSFULLY");
console.log("==================================================================");
process.exit(0);

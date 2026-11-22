# Sensitive-Content Boundary Specification & Verification Runbook

## 1. Overview & Architectural Context

Trellis Contracts operates across multiple high-stakes financial, governance, and operational domains:
- **Treasury Contract**: Manages asset reserves, multi-party approvals, budget allocations, and fund sweeps.
- **Aid Contract**: Governs humanitarian relief campaigns, donor deposits, and recipient aid disbursements.
- **Referral Contract**: Tracks affiliate trees, referral attributions, tier transitions, and reward claims.
- **Governance Contract**: Manages multi-sig voting ballots, proposals, parameter changes, and execution timelocks.
- **Oracle Contract**: Aggregates multi-provider price feeds, staleness thresholds, and price update submissions.
- **NFT Marketplace Contract**: Governs collection registration, listing escrows, auction settlement, and IPFS/Arweave metadata URIs.

Untrusted external data crosses contract and client boundaries at four critical interfaces:
1. **Rendering Boundary**: User-supplied titles, descriptions, memos, and metadata presented in dashboards, block explorers, and client frontends.
2. **Downloads Boundary**: External URLs, IPFS content identifiers, attachments, and downloadable export artifacts.
3. **Webhooks Boundary**: Inbound event triggers (automated sweeps, oracle updates) and outbound notification delivery to integration partners.
4. **Exports Boundary**: Multi-module audit, compliance, and operational exports consumed by external users and automated indexing workers.

This document and its companion automated tests form the **executable security boundary specification**, proving that untrusted input cannot execute code, escape sandboxing, leak private fields, or bypass allow-lists.

---

## 2. Threat Model & Boundary Defenses

```
                        UNTRUSTED INGRESS BOUNDARY
                                    │
    ┌───────────────────────────────┴──────────────────────────────┐
    ▼                               ▼                              ▼
[Rendering Boundary]        [Downloads Boundary]          [Webhooks Boundary]
 • XSS / Tag Injection       • Scheme Allow-Lists          • Ingress Auth (HMAC)
 • BiDi Text Spoofing        • Path Traversal Defense      • Replay Window (300s)
 • Template Injections       • Executable Extensions       • Egress PII Scrubber
 • ANSI / Null Poisoning     • SSRF / Metadata Block       • HTTPS Enforced
    │                               │                              │
    └───────────────────────────────┬──────────────────────────────┘
                                    │
                                    ▼
                         [Exports Boundary]
                          • Safe Field Allow-List
                          • Forbidden Secret Purging
                          • Caller Scope Sandboxing
                          • Bounded Memory (≤ 50/chunk)
```

### 2.1 Rendering Boundary
Untrusted strings entered into transactions (e.g. governance proposal summaries, marketplace collection descriptions, aid campaign reasons, treasury withdrawal memos) must never execute code or break presentation sandboxes.

- **Non-Execution Invariant**: All strings are validated against a strict denylist of executable markup and event triggers:
  - Script & Executable tags: `<script>`, `<iframe`, `<object>`, `<embed>`, `<form>`, `<svg>`, `<link>`, `<style>`, `<meta>`, `<base>`, `<applet>`, `<math>`, `<template>`.
  - Pseudo-protocols: `javascript:`, `vbscript:`, `data:text/html`.
  - DOM Event Handlers: `onload=`, `onerror=`, `onclick=`, `onmouseover=`, `onfocus=`, `onblur=`, `onchange=`, `onsubmit=`, `onunload=`, `onkeydown=`.
- **Sandbox Containment**:
  - Rejection of Unicode Bidirectional (BiDi) override and isolate code points (`U+202A`–`U+202E`, `U+200E`, `U+200F`, `U+2066`–`U+2069`) which flip visual order to disguise malicious URLs or masquerade addresses.
  - Rejection of ANSI escape code sequences (`\x1b[`) preventing terminal or CLI breakout.
  - Rejection of null bytes (`\0`) preventing C-string termination attacks.
  - Rejection of server-side / client-side template injection tokens (`{{`, `${`, `<%=`, `#{`).
- **Length Ceilings**: Strict ceiling enforced at `MAX_RENDER_TEXT_LEN` (8,192 bytes).

### 2.2 Downloads Boundary
Contracts often store and emit references to external documents, metadata JSON, and media assets.

- **Scheme Allow-Listing**:
  - Authorized safe schemes: `https://`, `ipfs://`, `ipns://`, `ar://`, `did:`.
  - Explicitly forbidden schemes: `javascript:`, `data:`, `file:`, `blob:`, `vbscript:`, `about:`, `chrome:`, `view-source:`, `ftp:`.
- **Sandbox Escaping & Path Traversal Prevention**:
  - Filename verification prevents directory traversal sequences: `../`, `..\`, `..%2f`, `..%5c`, `%2e%2e`.
  - Null-byte extension spoofing (`bundle.pdf\0.exe`) rejected.
  - Executable file extensions rejected: `.exe`, `.bat`, `.cmd`, `.sh`, `.ps1`, `.vbs`, `.wasm`, `.jar`, `.msi`, `.dll`, `.so`, `.html`, `.htm`, `.js`, `.mjs`, `.xhtml`, `.scr`.
  - Authorized download extension allow-list: `.json`, `.csv`, `.txt`, `.pdf`, `.png`, `.jpg`, `.jpeg`, `.svg`, `.webp`.
- **SSRF & Network Boundary Protection**:
  - External download URLs must not target loopback (`127.0.0.1`, `localhost`, `[::1]`), cloud metadata services (`169.254.169.254`, `metadata.google.internal`), or RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).

### 2.3 Webhooks Boundary
Webhooks provide real-time notification bridging on-chain events with off-chain infrastructure.

- **Ingress Authentication & Anti-Replay**:
  - Cryptographic verification using HMAC-SHA256 over `event_id || timestamp || payload`.
  - Replay protection enforces acceptance only within `replay_window_seconds` (default 300s) and future clock skew ceiling (default 60s).
  - Processed `event_id` keys are stored on-chain or in persistent storage, preventing duplicate processing (`Error::AlreadyClaimed`).
  - Executable markup in ingress payloads rejected immediately.
- **Egress Private Field Leakage Protection**:
  - Outbound webhook payloads are scrubbed through a secret-detection filter.
  - Payloads containing private keys (`priv_key`), seeds (`seed`, `res_seed`), authentication signatures (`auth_sig`), tokens (`token_sec`), passwords, SSNs, bank wire instructions, credit card numbers, or voting salts (`ballot_slt`) are rejected before transmission.
- **Destination Allow-Listing**:
  - Webhook callback endpoints must strictly use `https://` and cannot target loopback or private network SSRF endpoints.

### 2.4 Exports Boundary
The multi-module export pipeline serves Treasury, Aid, Referral, Governance, Oracle, and Marketplace data.

- **Field Allow-List**:
  Only 12 approved public fields may appear in exported records:
  `id`, `type`, `status`, `amount`, `created`, `expiry`, `region`, `role`, `tier`, `version`, `network`, `count`.
  Any other field is treated as untrusted/sensitive and purged.
- **Forbidden Secret Purging**:
  17 high-risk fields are strictly forbidden from appearing in any export record:
  `priv_key`, `sec_key`, `seed`, `entropy`, `token_sec`, `auth_sig`, `password`, `ssn`, `tax_id`, `bank_wire`, `card_num`, `admin_key`, `res_seed`, `raw_pii`, `ballot_slt`, `sign_key`, `raw_nonce`, `ip_addr`.
- **Scope Sandboxing**:
  - `OwnRecords`: Callers can only view records where `owner == caller`. Restricted or operational records are omitted.
  - `Operational`: Authorized operational roles can inspect operational records, but restricted secrets remain blocked.
  - `Full`: Restricted to authenticated admins.
- **Bounded Memory & Gas Limits**:
  - Streaming exports enforce a hard ceiling of `BOUNDARY_CHUNK_CEILING` (50 records per chunk, default 25), preventing gas exhaustion and host memory overflow.

---

## 3. Multi-Module Vertical Slice Matrix

| Module | Rendering Boundary | Download Boundary | Webhook Boundary | Export Boundary |
|---|---|---|---|---|
| **Treasury** | Proposal memos, budget categories | Audit bundles, payout vouchers | Automated sweep triggers, deposit receipts | Balance reports, sweep histories, allocation scopes |
| **Aid** | Campaign titles, distribution reasons | Proof of disbursement, audit documents | Milestone completion notifications | Campaign progress, beneficiary rosters, disbursement records |
| **Referral** | Campaign codes, tier badges | Affiliate commission reports | Referral attribution webhooks | Commission summaries, affiliate tree metrics |
| **Governance** | Ballot proposals, discussion specs | Technical specs, manifest attachments | Timelock queue alerts, execution notices | Ballot tallies, voter turnout logs, execution histories |
| **Oracle** | Feed descriptions, provider names | Historical price archive snapshots | Heartbeat callbacks, price ingestion feeds | Feed submission histories, provider SLA reports |
| **Marketplace**| Item descriptions, collection names | NFT metadata JSON, media assets | Order matched events, auction finalized hooks| Collection registries, sale transaction logs |

---

## 4. Operational Edge Cases & Failure Modes

### 4.1 Failure Modes Table

| Code | Failure Mode | Severity | Detection Point | Automatic Containment | Operator Action |
|---|---|---|---|---|---|
| `960` | `ExecutableContentRejected` | High | Ingress text validation | Request rejected; event dropped | Investigate caller account; block abusive actor |
| `961` | `SandboxEscapeAttempt` | Critical | Filename / URI parser | Immediate transaction abort | Quarantine origin; audit affected download endpoints |
| `962` | `PrivateFieldLeakage` | Critical | Egress scrubber / export sanitizer | Offending fields purged or webhook blocked | Revoke leaked credentials; trigger secret rotation runbook |
| `963` | `AllowListViolation` | Medium | Scheme / field allow-list checker | Non-allowlisted field or scheme dropped | Verify client schema version; update allow-list if authorized |
| `964` | `UnsafeDownloadDestination` | High | URI scheme / SSRF validator | Network request refused | Inspect destination host; ensure no internal IP exposure |
| `965` | `WebhookVerificationFailed` | High | HMAC / replay validator | Callback rejected with 401/403 | Verify integration secret key and system clock NTP sync |
| `966` | `ScopeIsolationViolation` | High | Scope authorization guard | Unauthorized record omitted from response | Audit caller role assignments |
| `967` | `BoundaryLimitExceeded` | Medium | Payload / chunk size validator | Request rejected before memory allocation | Split payload into smaller chunks (≤ 25 items) |

### 4.2 Operational Edge Cases

1. **Mixed-Case Protocol Evasion**:
   Attackers attempt bypasses using mixed-case schemes (`jAvAsCrIpT:`, `dAtA:`, `<sCrIpT>`). All boundary checks perform zero-allocation ASCII lowercasing prior to needle matching.
2. **URL-Encoded Path Traversal**:
   Attacks using `%2e%2e%2f` or `..%5c` are normalized and rejected by the traversal detector before resolving filenames.
3. **Clock Drift on Webhooks**:
   NTP clock skew can cause false-positive webhook rejections. The system tolerates up to 60s future skew and 300s historical latency. Larger drifts require server NTP resynchronization.
4. **Homoglyph & BiDi Spoofing**:
   Bidirectional controls alter the reading order of URLs and addresses. The rendering boundary inspects UTF-8 byte patterns and rejects any input containing code points in the BiDi range (`U+202A`–`U+202E`, `U+2066`–`U+2069`).

---

## 5. Rollback, Recovery & Incident Response

### 5.1 Incident Response Playbook

1. **Secret Leakage Detected (`PrivateFieldLeakage`)**:
   - Step 1: Immediately identify the leaked field (`priv_key`, `seed`, `admin_key`, `token_sec`).
   - Step 2: Invalidate the compromised key material on-chain and in off-chain secret managers (e.g. HashiCorp Vault, AWS Secrets Manager).
   - Step 3: Trigger key rotation and reissue credentials to authorized service accounts.
   - Step 4: Purge cached export bundles or webhook delivery logs containing the unredacted payload.
2. **Malicious Attachment / SSRF Attempt (`UnsafeDownloadDestination` / `SandboxEscapeAttempt`)**:
   - Step 1: Freeze affected module using the emergency circuit breaker (`shared::pause`).
   - Step 2: Verify that no internal service endpoints responded to the request.
   - Step 3: Add offending IP address or domain to the edge firewall blocklist.
   - Step 4: Resume module operations after validating ingress parameters.
3. **Export Integrity Mismatch (`ExportDigestMismatch`)**:
   - Step 1: Discard the corrupted or tampered export artifact.
   - Step 2: Regenerate the export bundle from authoritative on-chain storage with fresh cursor.
   - Step 3: Validate the newly computed SHA-256 digest against published checkpoint receipts.

---

## 6. Compatibility & API Guarantees

- **100% Backwards Compatible**:
  - No existing public contract interfaces, schemas, or storage keys were modified or broken.
  - The sensitive boundary defenses in `shared::sensitive_boundary` integrate seamlessly as zero-allocation validation layers.
  - Safe fields in existing exports continue to be exported with identical keys and values.
  - Valid existing webhooks and clean text continue to pass without friction.

---

## 7. Automated Verification Instructions

### 7.1 Running the Executable Verification Runner
The repository provides a fast, standalone Node.js verification script:

```bash
node scripts/verify-sensitive-content-boundary.cjs
```

Output:
```
==================================================================
TRELLIS: SENSITIVE-CONTENT BOUNDARY TEST & VERIFICATION RUNNER
==================================================================

[1/8] Verifying Rendering Boundary & Untrusted Script Execution Defense...
  ✓ All 12 injection and sandbox escape vectors blocked across rendering inputs
[2/8] Verifying Download Boundary Scheme Allow-Lists & Containment...
  ✓ Download schemes validated; dangerous schemes and SSRF endpoints rejected
[3/8] Verifying Download Filename Traversal & Extension Allow-Lists...
  ✓ Directory traversal, null-byte poisoning, and executable extensions blocked
[4/8] Verifying Webhook Ingress Authentication & Replay Boundary...
  ✓ Webhook authentication, replay protection, and ingress payload sanitization verified
[5/8] Verifying Webhook Egress Privacy & Secret Leakage Prevention...
  ✓ All 8 private secret fields strictly blocked from outbound webhook payloads
[6/8] Verifying Multi-Module Export Allow-Lists (Treasury, Aid, Referral, Governance, Oracle, Market)...
  ✓ Export records across all 6 core modules purged of unapproved & forbidden fields
[7/8] Verifying Export Scope Sandboxing & Bounded Memory Ceilings...
  ✓ Caller authorization scopes isolated and bounded memory chunk ceilings enforced
[8/8] Verifying Operational Edge Cases, Failure Modes & Recovery Workflows...
  ✓ Operational evasion attempts and tamper detection recovered cleanly

==================================================================
ALL SENSITIVE-CONTENT BOUNDARY TEST SUITES COMPLETED SUCCESSFULLY
==================================================================
```

### 7.2 Running Rust Unit Tests
In environments with the Rust/Cargo toolchain:

```bash
cargo test --package shared -- test_sensitive_boundary
```

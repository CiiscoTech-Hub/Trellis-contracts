//! Sensitive-content boundary validation, sandboxing, and leakage protection.
//!
//! Provides defense-in-depth boundary controls across Soroban contracts, treasury,
//! aid, referral, governance, oracle, and marketplace modules for:
//! 1. **Rendering Boundary**: Prevents untrusted content from executing arbitrary script,
//!    escaping presentation sandboxes, or leveraging injection vectors (XSS, SVG script,
//!    template injection, BiDi text spoofing, ANSI escapes, null-byte poisoning).
//! 2. **Downloads Boundary**: Validates download endpoints and file descriptors against safe
//!    scheme allow-lists (`https://`, `ipfs://`, `ipns://`, `ar://`, `did:`), rejects path
//!    traversal (`../`), blocks executable file extensions, and blocks SSRF targets
//!    (loopback, private subnets, cloud metadata).
//! 3. **Webhooks Boundary**: Validates inbound webhook integrity and replay windows, and
//!    enforces egress redaction so private keys, secret material, authentication signatures,
//!    and PII never leak into external callback events.
//! 4. **Exports Boundary**: Multi-module permissioned export boundaries across Treasury, Aid,
//!    Referral, Governance, Oracle, and Marketplace, enforcing field allow-lists,
//!    strict purging of forbidden secrets, and caller scope isolation.

#![no_std]

use soroban_sdk::{
    contracterror, contracttype, symbol_short, Address, Bytes, BytesN, Env, String, Symbol, Vec,
};

use crate::export::{ExportField, ExportRecord, ExportScope, RecordSensitivity};
use crate::webhook::{WebhookConfig, WebhookEvent};

// ---------------------------------------------------------------------------
// Error Taxonomy
// ---------------------------------------------------------------------------

/// Error codes for sensitive content boundary enforcement (Range 960–969).
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SensitiveBoundaryError {
    /// Untrusted content contains forbidden executable script, tags, or injection markup.
    ExecutableContentRejected = 960,
    /// Untrusted content attempted to escape sandboxing (e.g. path traversal, DOM breakout).
    SandboxEscapeAttempt = 961,
    /// Private or forbidden secret field detected in payload, export, or notification.
    PrivateFieldLeakage = 962,
    /// Field, scheme, or extension is not present on the authorized allow-list.
    AllowListViolation = 963,
    /// Download destination is unsafe, malformed, or targets a forbidden network (SSRF).
    UnsafeDownloadDestination = 964,
    /// Webhook authentication failed, signature mismatch, or replay window expired.
    WebhookVerificationFailed = 965,
    /// Caller authorization scope does not permit access to record or module data.
    ScopeIsolationViolation = 966,
    /// Content exceeds maximum allowed byte length or memory chunk size limit.
    BoundaryLimitExceeded = 967,
}

// ---------------------------------------------------------------------------
// Domain Enums
// ---------------------------------------------------------------------------

/// Core contract module subject to sensitive-content boundary enforcement.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BoundaryModule {
    Treasury,
    Aid,
    Referral,
    Governance,
    Oracle,
    Marketplace,
}

/// Boundary domain classification.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BoundaryDomain {
    Rendering,
    Download,
    Webhook,
    Export,
}

/// Authorized URI scheme for content downloads and attachments.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DownloadScheme {
    Https,
    Ipfs,
    Ipns,
    Arweave,
    Did,
}

// ---------------------------------------------------------------------------
// Limits & Ceilings
// ---------------------------------------------------------------------------

/// Maximum allowed byte length for untrusted text rendering fields.
pub const MAX_RENDER_TEXT_LEN: u32 = 8192;

/// Maximum allowed byte length for download and attachment URIs.
pub const MAX_DOWNLOAD_URI_LEN: u32 = 2048;

/// Maximum allowed byte length for downloaded asset filenames.
pub const MAX_FILENAME_LEN: u32 = 255;

/// Maximum allowed webhook payload size (bytes).
pub const MAX_WEBHOOK_PAYLOAD_LEN: u32 = 4096;

/// Default export chunk size ceiling to guarantee bounded memory.
pub const BOUNDARY_CHUNK_CEILING: u32 = 50;

// ---------------------------------------------------------------------------
// Low-Level Byte Helpers
// ---------------------------------------------------------------------------

#[inline]
pub fn is_ascii_whitespace(b: u8) -> bool {
    b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' || b == 0x0c || b == 0x0b
}

#[inline]
pub fn to_ascii_lower(b: u8) -> u8 {
    if (b'A'..=b'Z').contains(&b) {
        b + (b'a' - b'A')
    } else {
        b
    }
}

/// Case-insensitive subslice search across a `soroban_sdk::Bytes` object.
pub fn contains_subslice_ci(bytes: &Bytes, needle: &[u8]) -> bool {
    if bytes.len() < needle.len() as u32 {
        return false;
    }
    let max_start = bytes.len() - needle.len() as u32;
    let mut start = 0u32;
    while start <= max_start {
        let mut matched = true;
        let mut i = 0usize;
        while i < needle.len() {
            let b = bytes.get(start + i as u32).unwrap_or(0);
            if to_ascii_lower(b) != needle[i] {
                matched = false;
                break;
            }
            i += 1;
        }
        if matched {
            return true;
        }
        start += 1;
    }
    false
}

/// Case-insensitive prefix check.
pub fn starts_with_ci(bytes: &Bytes, prefix: &[u8]) -> bool {
    if bytes.len() < prefix.len() as u32 {
        return false;
    }
    let mut i = 0usize;
    while i < prefix.len() {
        let b = bytes.get(i as u32).unwrap_or(0);
        if to_ascii_lower(b) != prefix[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Case-insensitive suffix check.
pub fn ends_with_ci(bytes: &Bytes, suffix: &[u8]) -> bool {
    if bytes.len() < suffix.len() as u32 {
        return false;
    }
    let offset = bytes.len() - suffix.len() as u32;
    let mut i = 0usize;
    while i < suffix.len() {
        let b = bytes.get(offset + i as u32).unwrap_or(0);
        if to_ascii_lower(b) != suffix[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Trims leading and trailing ASCII whitespace from a `Bytes` sequence.
pub fn trim_whitespace_bytes(env: &Env, raw: &Bytes) -> Bytes {
    let len = raw.len();
    if len == 0 {
        return Bytes::new(env);
    }
    let mut start = 0u32;
    while start < len {
        if !is_ascii_whitespace(raw.get(start).unwrap_or(0)) {
            break;
        }
        start += 1;
    }
    if start == len {
        return Bytes::new(env);
    }
    let mut end = len;
    while end > start {
        if !is_ascii_whitespace(raw.get(end - 1).unwrap_or(0)) {
            break;
        }
        end -= 1;
    }
    let mut out = Bytes::new(env);
    let mut curr = start;
    while curr < end {
        out.push_back(raw.get(curr).unwrap_or(0));
        curr += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// 1. Rendering Boundary
// ---------------------------------------------------------------------------

/// Detects dangerous script tags, event handlers, and injection tokens.
pub fn contains_executable_markup(raw: &Bytes) -> bool {
    let tags: &[&[u8]] = &[
        b"<script",
        b"<iframe",
        b"<object",
        b"<embed",
        b"<form",
        b"<svg",
        b"<link",
        b"<style",
        b"<meta",
        b"<base",
        b"<applet",
        b"<math",
        b"<template",
        b"javascript:",
        b"vbscript:",
        b"data:text/html",
        b"onload=",
        b"onerror=",
        b"onclick=",
        b"onmouseover=",
        b"onfocus=",
        b"onblur=",
        b"onchange=",
        b"onsubmit=",
        b"onunload=",
        b"onkeydown=",
    ];
    for &tag in tags {
        if contains_subslice_ci(raw, tag) {
            return true;
        }
    }
    false
}

/// Detects template injection and expression language evaluation tokens.
pub fn contains_template_injection(raw: &Bytes) -> bool {
    let patterns: &[&[u8]] = &[
        b"{{",
        b"${",
        b"<%=",
        b"#{"",
    ];
    for &p in patterns {
        if contains_subslice_ci(raw, p) {
            return true;
        }
    }
    false
}

/// Detects Unicode bidirectional (BiDi) override and embedding controls.
///
/// UTF-8 representations checked:
/// - U+202A (LRE): [0xE2, 0x80, 0xAA]
/// - U+202B (RLE): [0xE2, 0x80, 0xAB]
/// - U+202C (PDF): [0xE2, 0x80, 0xAC]
/// - U+202D (LRO): [0xE2, 0x80, 0xAD]
/// - U+202E (RLO): [0xE2, 0x80, 0xAE]
/// - U+200E (LRM): [0xE2, 0x80, 0x8E]
/// - U+200F (RLM): [0xE2, 0x80, 0x8F]
/// - U+2066 (LRI): [0xE2, 0x81, 0xA6]
/// - U+2067 (RLI): [0xE2, 0x81, 0xA7]
/// - U+2068 (FSI): [0xE2, 0x81, 0xA8]
/// - U+2069 (PDI): [0xE2, 0x81, 0xA9]
pub fn contains_bidi_controls(raw: &Bytes) -> bool {
    if raw.len() < 3 {
        return false;
    }
    let max = raw.len() - 3;
    let mut i = 0u32;
    while i <= max {
        let b0 = raw.get(i).unwrap_or(0);
        if b0 == 0xE2 {
            let b1 = raw.get(i + 1).unwrap_or(0);
            let b2 = raw.get(i + 2).unwrap_or(0);
            if b1 == 0x80 && (b2 == 0x8E || b2 == 0x8F || (b2 >= 0xAA && b2 <= 0xAE)) {
                return true;
            }
            if b1 == 0x81 && (b2 >= 0xA6 && b2 <= 0xA9) {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Validates untrusted text content before presentation/rendering.
///
/// Ensures:
/// 1. Length within `[1, max_len]`.
/// 2. No null bytes (`\0`).
/// 3. No unapproved ASCII control characters (< 32, except `\n`, `\r`, `\t` if multiline).
/// 4. No ANSI terminal escape characters (`\x1b`).
/// 5. No BiDi override characters.
/// 6. No executable script/HTML markup.
/// 7. No template injection tokens.
pub fn validate_render_content(
    raw: &Bytes,
    max_len: u32,
    allow_multiline: bool,
) -> Result<(), SensitiveBoundaryError> {
    let len = raw.len();
    if len == 0 || len > max_len {
        return Err(SensitiveBoundaryError::BoundaryLimitExceeded);
    }

    let mut i = 0u32;
    while i < len {
        let b = raw.get(i).unwrap_or(0);
        if b == 0 {
            // Null-byte strictly rejected (terminator injection)
            return Err(SensitiveBoundaryError::ExecutableContentRejected);
        }
        if b == 0x1B {
            // ANSI escape sequence strictly rejected (terminal breakout)
            return Err(SensitiveBoundaryError::SandboxEscapeAttempt);
        }
        if b < 32 && b != 127 {
            if allow_multiline && (b == b'\n' || b == b'\r' || b == b'\t') {
                // Allowed whitespace
            } else {
                return Err(SensitiveBoundaryError::ExecutableContentRejected);
            }
        }
        i += 1;
    }

    if contains_bidi_controls(raw) {
        return Err(SensitiveBoundaryError::SandboxEscapeAttempt);
    }
    if contains_executable_markup(raw) {
        return Err(SensitiveBoundaryError::ExecutableContentRejected);
    }
    if contains_template_injection(raw) {
        return Err(SensitiveBoundaryError::ExecutableContentRejected);
    }

    Ok(())
}

/// Sanitizes content for safe rendering: trims surrounding whitespace and verifies safety.
pub fn sanitize_render_content(
    env: &Env,
    raw: &Bytes,
    max_len: u32,
    allow_multiline: bool,
) -> Result<Bytes, SensitiveBoundaryError> {
    let trimmed = trim_whitespace_bytes(env, raw);
    validate_render_content(&trimmed, max_len, allow_multiline)?;
    Ok(trimmed)
}

// ---------------------------------------------------------------------------
// 2. Downloads Boundary
// ---------------------------------------------------------------------------

/// Detects directory traversal markers in filenames or relative paths.
pub fn contains_path_traversal(raw: &Bytes) -> bool {
    let traversal_patterns: &[&[u8]] = &[
        b"../",
        b"..\\",
        b"..%2f",
        b"..%2F",
        b"..%5c",
        b"..%5C",
        b"%2e%2e",
        b"/..",
        b"\\..",
    ];
    for &pattern in traversal_patterns {
        if contains_subslice_ci(raw, pattern) {
            return true;
        }
    }
    false
}

/// Detects dangerous executable or script file extensions.
pub fn has_dangerous_download_extension(filename: &Bytes) -> bool {
    let dangerous: &[&[u8]] = &[
        b".exe",
        b".bat",
        b".cmd",
        b".sh",
        b".ps1",
        b".vbs",
        b".wasm",
        b".jar",
        b".msi",
        b".dll",
        b".so",
        b".html",
        b".htm",
        b".js",
        b".mjs",
        b".xhtml",
        b".scr",
        b".pif",
        b".com",
    ];
    for &ext in dangerous {
        if ends_with_ci(filename, ext) {
            return true;
        }
    }
    false
}

/// Returns `true` if `filename` ends with an allowed download extension.
pub fn has_allowlisted_download_extension(filename: &Bytes) -> bool {
    let allowed: &[&[u8]] = &[
        b".json",
        b".csv",
        b".txt",
        b".pdf",
        b".png",
        b".jpg",
        b".jpeg",
        b".svg",
        b".webp",
    ];
    for &ext in allowed {
        if ends_with_ci(filename, ext) {
            return true;
        }
    }
    false
}

/// Detects private IP, loopback, or cloud instance metadata targets (SSRF defense).
pub fn is_forbidden_ssrf_destination(url: &Bytes) -> bool {
    let ssrf_needles: &[&[u8]] = &[
        b"localhost",
        b"127.0.0.1",
        b"[::1]",
        b"169.254.169.254",
        b"metadata.google.internal",
        b"http://10.",
        b"https://10.",
        b"http://192.168.",
        b"https://192.168.",
        b"http://172.16.",
        b"https://172.16.",
        b"http://172.31.",
        b"https://172.31.",
        b"http://0.0.0.0",
        b"https://0.0.0.0",
        b"fd00::",
    ];
    for &needle in ssrf_needles {
        if contains_subslice_ci(url, needle) {
            return true;
        }
    }
    false
}

/// Validates download URIs against safe scheme allow-lists and SSRF boundaries.
pub fn validate_download_uri(
    uri: &Bytes,
    max_len: u32,
) -> Result<DownloadScheme, SensitiveBoundaryError> {
    let len = uri.len();
    if len == 0 || len > max_len {
        return Err(SensitiveBoundaryError::BoundaryLimitExceeded);
    }

    // Prohibit null bytes and ASCII control characters
    let mut i = 0u32;
    while i < len {
        let b = uri.get(i).unwrap_or(0);
        if b < 32 || b == 127 || is_ascii_whitespace(b) {
            return Err(SensitiveBoundaryError::UnsafeDownloadDestination);
        }
        i += 1;
    }

    // Prohibit dangerous schemes explicitly
    let dangerous_schemes: &[&[u8]] = &[
        b"javascript:",
        b"data:",
        b"file:",
        b"vbscript:",
        b"blob:",
        b"about:",
        b"chrome:",
        b"view-source:",
    ];
    for &bad in dangerous_schemes {
        if contains_subslice_ci(uri, bad) {
            return Err(SensitiveBoundaryError::UnsafeDownloadDestination);
        }
    }

    // Prohibit loopback / private IP / cloud metadata SSRF
    if is_forbidden_ssrf_destination(uri) {
        return Err(SensitiveBoundaryError::UnsafeDownloadDestination);
    }

    // Match authorized scheme allow-list
    if starts_with_ci(uri, b"https://") {
        if len <= 8 {
            return Err(SensitiveBoundaryError::UnsafeDownloadDestination);
        }
        let next = uri.get(8).unwrap_or(0);
        if next == b'/' || next == b'?' || next == b'#' {
            return Err(SensitiveBoundaryError::UnsafeDownloadDestination);
        }
        Ok(DownloadScheme::Https)
    } else if starts_with_ci(uri, b"ipfs://") {
        if len <= 7 {
            return Err(SensitiveBoundaryError::UnsafeDownloadDestination);
        }
        Ok(DownloadScheme::Ipfs)
    } else if starts_with_ci(uri, b"ipns://") {
        if len <= 7 {
            return Err(SensitiveBoundaryError::UnsafeDownloadDestination);
        }
        Ok(DownloadScheme::Ipns)
    } else if starts_with_ci(uri, b"ar://") {
        if len <= 5 {
            return Err(SensitiveBoundaryError::UnsafeDownloadDestination);
        }
        Ok(DownloadScheme::Arweave)
    } else if starts_with_ci(uri, b"did:") {
        if len <= 4 {
            return Err(SensitiveBoundaryError::UnsafeDownloadDestination);
        }
        Ok(DownloadScheme::Did)
    } else {
        Err(SensitiveBoundaryError::AllowListViolation)
    }
}

/// Validates download filenames to prevent sandbox escapes, path traversal,
/// and executable artifact masquerading.
pub fn validate_download_filename(filename: &Bytes) -> Result<(), SensitiveBoundaryError> {
    let len = filename.len();
    if len == 0 || len > MAX_FILENAME_LEN {
        return Err(SensitiveBoundaryError::BoundaryLimitExceeded);
    }

    // Check for null byte poisoning (e.g. "report.pdf\0.exe")
    let mut i = 0u32;
    while i < len {
        let b = filename.get(i).unwrap_or(0);
        if b == 0 || b < 32 || b == 127 {
            return Err(SensitiveBoundaryError::SandboxEscapeAttempt);
        }
        i += 1;
    }

    // Check for path traversal sequences
    if contains_path_traversal(filename) {
        return Err(SensitiveBoundaryError::SandboxEscapeAttempt);
    }

    // Prohibit dangerous executable extensions
    if has_dangerous_download_extension(filename) {
        return Err(SensitiveBoundaryError::ExecutableContentRejected);
    }

    // Ensure extension passes allow-list
    if !has_allowlisted_download_extension(filename) {
        return Err(SensitiveBoundaryError::AllowListViolation);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 3. Webhooks Boundary
// ---------------------------------------------------------------------------

/// Forbidden secret keys that must NEVER appear in outbound webhook events.
pub fn is_sensitive_webhook_key(key: &Bytes) -> bool {
    let sensitive: &[&[u8]] = &[
        b"priv_key",
        b"sec_key",
        b"seed",
        b"entropy",
        b"token_sec",
        b"auth_sig",
        b"password",
        b"ssn",
        b"tax_id",
        b"bank_wire",
        b"card_num",
        b"admin_key",
        b"res_seed",
        b"ballot_slt",
        b"sign_key",
        b"raw_nonce",
    ];
    for &k in sensitive {
        if contains_subslice_ci(key, k) {
            return true;
        }
    }
    false
}

/// Validates outbound webhook notification destinations.
pub fn validate_webhook_destination(url: &Bytes) -> Result<(), SensitiveBoundaryError> {
    let len = url.len();
    if len == 0 || len > MAX_DOWNLOAD_URI_LEN {
        return Err(SensitiveBoundaryError::BoundaryLimitExceeded);
    }

    if !starts_with_ci(url, b"https://") {
        return Err(SensitiveBoundaryError::UnsafeDownloadDestination);
    }

    if is_forbidden_ssrf_destination(url) {
        return Err(SensitiveBoundaryError::UnsafeDownloadDestination);
    }

    Ok(())
}

/// Scrubs webhook payload bytes to ensure sensitive credentials are not leaked.
/// Rejects payload if unmasked secret keys are detected.
pub fn assert_webhook_payload_clean(payload: &Bytes) -> Result<(), SensitiveBoundaryError> {
    if payload.len() > MAX_WEBHOOK_PAYLOAD_LEN {
        return Err(SensitiveBoundaryError::BoundaryLimitExceeded);
    }

    if is_sensitive_webhook_key(payload) {
        return Err(SensitiveBoundaryError::PrivateFieldLeakage);
    }

    // Check for executable markup in webhook payload
    if contains_executable_markup(payload) {
        return Err(SensitiveBoundaryError::ExecutableContentRejected);
    }

    Ok(())
}

/// Enforces the webhook boundary on ingress:
/// 1. Payload size within bounds.
/// 2. Payload contains no executable script or markup.
/// 3. Validates timestamp window against replay attacks.
pub fn verify_webhook_ingress_boundary(
    event: &WebhookEvent,
    config: &WebhookConfig,
    current_time: u64,
) -> Result<(), SensitiveBoundaryError> {
    if event.payload.len() == 0 || event.payload.len() > MAX_WEBHOOK_PAYLOAD_LEN {
        return Err(SensitiveBoundaryError::BoundaryLimitExceeded);
    }

    if contains_executable_markup(&event.payload) {
        return Err(SensitiveBoundaryError::ExecutableContentRejected);
    }

    // Replay window check:
    // 1. Not older than replay_window_seconds
    let min_allowed = current_time.saturating_sub(config.replay_window_seconds);
    if event.timestamp < min_allowed {
        return Err(SensitiveBoundaryError::WebhookVerificationFailed);
    }

    // 2. Not further in future than max_future_skew_seconds
    let max_allowed = current_time.saturating_add(config.max_future_skew_seconds);
    if event.timestamp > max_allowed {
        return Err(SensitiveBoundaryError::WebhookVerificationFailed);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 4. Exports Boundary
// ---------------------------------------------------------------------------

/// Safe field allow-list for exports across all 6 modules:
/// Treasury, Aid, Referral, Governance, Oracle, and Marketplace.
pub fn is_export_allowlisted_field(field: &Symbol) -> bool {
    field == &symbol_short!("id")
        || field == &symbol_short!("type")
        || field == &symbol_short!("status")
        || field == &symbol_short!("amount")
        || field == &symbol_short!("created")
        || field == &symbol_short!("expiry")
        || field == &symbol_short!("region")
        || field == &symbol_short!("role")
        || field == &symbol_short!("tier")
        || field == &symbol_short!("version")
        || field == &symbol_short!("network")
        || field == &symbol_short!("count")
}

/// Strictly forbidden fields that must NEVER appear in any export.
pub fn is_forbidden_export_field(field: &Symbol) -> bool {
    field == &symbol_short!("priv_key")
        || field == &symbol_short!("sec_key")
        || field == &symbol_short!("seed")
        || field == &symbol_short!("entropy")
        || field == &symbol_short!("token_sec")
        || field == &symbol_short!("auth_sig")
        || field == &symbol_short!("password")
        || field == &symbol_short!("ssn")
        || field == &symbol_short!("tax_id")
        || field == &symbol_short!("bank_wire")
        || field == &symbol_short!("card_num")
        || field == &symbol_short!("admin_key")
        || field == &symbol_short!("res_seed")
        || field == &symbol_short!("raw_pii")
        || field == &symbol_short!("ballot_slt")
        || field == &symbol_short!("sign_key")
        || field == &symbol_short!("raw_nonce")
        || field == &symbol_short!("ip_addr")
}

/// Validates that an export record contains no forbidden fields.
pub fn assert_no_forbidden_fields(fields: &Vec<ExportField>) -> Result<(), SensitiveBoundaryError> {
    for i in 0..fields.len() {
        if let Some(f) = fields.get(i) {
            if is_forbidden_export_field(&f.name) {
                return Err(SensitiveBoundaryError::PrivateFieldLeakage);
            }
        }
    }
    Ok(())
}

/// Enforces export scope authorization boundaries:
/// - `OwnRecords`: Caller can only read their own records, and restricted operational data is forbidden.
/// - `Operational`: Authorized operator, but restricted secrets remain blocked.
/// - `Full`: Maintainer/Admin scope.
pub fn enforce_export_scope_boundary(
    record_owner: &Address,
    caller: &Address,
    sensitivity: RecordSensitivity,
    scope: ExportScope,
) -> Result<(), SensitiveBoundaryError> {
    match scope {
        ExportScope::OwnRecords => {
            if record_owner != caller {
                return Err(SensitiveBoundaryError::ScopeIsolationViolation);
            }
            if sensitivity != RecordSensitivity::Public {
                return Err(SensitiveBoundaryError::ScopeIsolationViolation);
            }
            Ok(())
        }
        ExportScope::Operational => {
            if sensitivity == RecordSensitivity::Restricted {
                return Err(SensitiveBoundaryError::ScopeIsolationViolation);
            }
            Ok(())
        }
        ExportScope::Full => Ok(()),
    }
}

/// Sanitizes an export record against the safe-field allow-list and purges any forbidden fields.
/// Returns the sanitized record and the count of purged fields.
pub fn sanitize_export_record(
    env: &Env,
    record: &ExportRecord,
) -> (ExportRecord, u32) {
    let mut safe_fields = Vec::new(env);
    let mut purged_count = 0u32;

    for i in 0..record.fields.len() {
        if let Some(f) = record.fields.get(i) {
            if is_export_allowlisted_field(&f.name) && !is_forbidden_export_field(&f.name) {
                safe_fields.push_back(f);
            } else {
                purged_count = purged_count.saturating_add(1);
            }
        }
    }

    let sanitized = ExportRecord {
        id: record.id.clone(),
        record_type: record.record_type.clone(),
        owner: record.owner.clone(),
        created_ledger: record.created_ledger,
        sensitivity: record.sensitivity,
        fields: safe_fields,
    };

    (sanitized, purged_count)
}

/// Enforces memory chunk boundedness for streaming exports.
pub fn validate_export_chunk_size(chunk_len: u32) -> Result<(), SensitiveBoundaryError> {
    if chunk_len > BOUNDARY_CHUNK_CEILING {
        return Err(SensitiveBoundaryError::BoundaryLimitExceeded);
    }
    Ok(())
}

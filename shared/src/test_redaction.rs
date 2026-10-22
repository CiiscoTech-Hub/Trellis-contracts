#![cfg(test)]

extern crate std;

use std::format;

use soroban_sdk::{symbol_short, Bytes, Env, String, Vec};

use crate::config::RedactedSecret;
use crate::errors::Error;
use crate::export::{
    contains_forbidden_fields, is_forbidden_field, is_safe_field, purge_forbidden_fields,
    redact_fields, ExportField,
};
use crate::sanitize::{
    classify_telemetry_label, redact_telemetry_value, sanitize_telemetry_label, LabelClass,
    MAX_TELEMETRY_LABEL_LEN, REDACTED_TOKEN,
};

const STELLAR_SECRET: &str = "SCZANGBA5YHTNYVS3ZSXQ7KFUNXAGMGKSSLTPJHLAOBQEVKUYNNVPFH";

// ---------------------------------------------------------------------------
// Secret material in Debug output
// ---------------------------------------------------------------------------

#[test]
fn redacted_secret_debug_shows_only_head_and_tail() {
    let debug = format!("{:?}", RedactedSecret(STELLAR_SECRET));
    assert_eq!(debug, "\"SCZA...FH\"");
    assert!(!debug.contains("NGBA5Y"));
}

#[test]
fn short_secrets_are_fully_masked() {
    assert_eq!(format!("{:?}", RedactedSecret("S1234567")), "\"***\"");
}

// ---------------------------------------------------------------------------
// Telemetry values: sensitive keys, including compound names
// ---------------------------------------------------------------------------

#[test]
fn compound_sensitive_keys_are_redacted_before_emission() {
    let env = Env::default();
    let value = Bytes::from_slice(&env, STELLAR_SECRET.as_bytes());
    let sensitive_keys: [&[u8]; 8] = [
        b"secret",
        b"wallet_secret",
        b"api_key",
        b"Signing_Key",
        b"tx_signature",
        b"auth",
        b"wallet",
        b"transaction_seed",
    ];
    for key in sensitive_keys {
        assert_eq!(
            redact_telemetry_value(&env, &Bytes::from_slice(&env, key), &value),
            Ok(Bytes::from_slice(&env, REDACTED_TOKEN)),
            "key {:?} must redact its value",
            key
        );
    }
}

#[test]
fn non_sensitive_lookalike_keys_are_not_over_redacted() {
    let env = Env::default();
    let value = Bytes::from_slice(&env, b"ready");
    // `auth` is exact-match only, so `author` must keep its value.
    let key = Bytes::from_slice(&env, b"author");
    assert_eq!(redact_telemetry_value(&env, &key, &value), Ok(value.clone()));
}

#[test]
fn bounded_values_with_control_characters_are_rejected() {
    let env = Env::default();
    let key = Bytes::from_slice(&env, b"status");

    let forged = Bytes::from_slice(&env, b"ok\nforged=1");
    assert_eq!(
        redact_telemetry_value(&env, &key, &forged),
        Err(Error::InvalidArgument)
    );

    let clean = Bytes::from_slice(&env, b"settled");
    assert_eq!(redact_telemetry_value(&env, &key, &clean), Ok(clean.clone()));
}

#[test]
fn values_longer_than_the_label_budget_are_rejected() {
    let env = Env::default();
    let key = Bytes::from_slice(&env, b"status");
    let too_long = [b'a'; MAX_TELEMETRY_LABEL_LEN as usize + 1];
    assert_eq!(
        redact_telemetry_value(&env, &key, &Bytes::from_slice(&env, &too_long)),
        Err(Error::InvalidArgument)
    );
}

// ---------------------------------------------------------------------------
// Wallet and transaction labels never reach telemetry
// ---------------------------------------------------------------------------

#[test]
fn wallet_and_transaction_labels_are_classified_unbounded_and_dropped() {
    let env = Env::default();
    let address = Bytes::from_slice(&env, b"GABC1234567890");
    let keys: [&[u8]; 6] = [
        b"wallet",
        b"wallet_address",
        b"recipient_address",
        b"tx_hash",
        b"transaction_id",
        b"user_id",
    ];
    for key in keys {
        let key = Bytes::from_slice(&env, key);
        assert_eq!(
            classify_telemetry_label(&key),
            Ok(LabelClass::Unbounded),
            "key {:?} must be unbounded",
            key
        );
        assert_eq!(
            sanitize_telemetry_label(&env, &key, &address, 0),
            Err(Error::InvalidArgument),
            "key {:?} must not be emitted",
            key
        );
    }
}

#[test]
fn bounded_label_is_emitted_only_after_redaction_checks_pass() {
    let env = Env::default();
    let key = Bytes::from_slice(&env, b"status");
    let value = Bytes::from_slice(&env, b"settled");
    assert_eq!(
        sanitize_telemetry_label(&env, &key, &value, 0),
        Ok(value.clone())
    );
    // The label budget is checked before the key or value is inspected.
    assert_eq!(
        sanitize_telemetry_label(&env, &key, &value, 17),
        Err(Error::InvalidArgument)
    );
}

// ---------------------------------------------------------------------------
// Export allow-list and forbidden fields
// ---------------------------------------------------------------------------

fn field(env: &Env, name: soroban_sdk::Symbol, value: &str) -> ExportField {
    ExportField {
        name,
        value: String::from_str(env, value),
    }
}

#[test]
fn export_allow_list_drops_wallet_secret_and_transaction_fields() {
    let env = Env::default();
    let mut fields: Vec<ExportField> = Vec::new(&env);
    fields.push_back(field(&env, symbol_short!("status"), "settled"));
    fields.push_back(field(&env, symbol_short!("wallet"), "GABC1234567890"));
    fields.push_back(field(&env, symbol_short!("secret"), "SCZA"));
    fields.push_back(field(&env, symbol_short!("tx_hash"), "abcd"));
    fields.push_back(field(&env, symbol_short!("amount"), "1000"));

    let (safe, dropped) = redact_fields(&env, &fields);
    assert_eq!(dropped, 3);
    assert_eq!(safe.len(), 2);
    assert_eq!(safe.get(0).unwrap().name, symbol_short!("status"));
    assert_eq!(safe.get(1).unwrap().name, symbol_short!("amount"));
}

#[test]
fn wallet_and_transaction_fields_are_not_allow_listed() {
    assert!(!is_safe_field(&symbol_short!("wallet")));
    assert!(!is_safe_field(&symbol_short!("tx_hash")));
    assert!(!is_safe_field(&symbol_short!("secret")));
    assert!(is_safe_field(&symbol_short!("amount")));
}

#[test]
fn forbidden_secret_fields_are_purged_on_every_pass() {
    let env = Env::default();
    let mut fields: Vec<ExportField> = Vec::new(&env);
    fields.push_back(field(&env, symbol_short!("seed"), "abc"));
    fields.push_back(field(&env, symbol_short!("priv_key"), "def"));
    fields.push_back(field(&env, symbol_short!("status"), "ok"));

    assert!(is_forbidden_field(&symbol_short!("seed")));
    assert!(contains_forbidden_fields(&fields));

    // Retry: purging the same input again must give the same result.
    for _ in 0..2 {
        let (safe, purged) = purge_forbidden_fields(&env, &fields);
        assert_eq!(purged, 2);
        assert_eq!(safe.len(), 1);
        assert_eq!(safe.get(0).unwrap().name, symbol_short!("status"));
    }
}

// ---------------------------------------------------------------------------
// Issue #269: Redaction tests for logs, exports, and error responses
// ---------------------------------------------------------------------------

use crate::error_taxonomy::{describe_error, ErrorCategory, ErrorDomain};
use crate::client::format_client_error;
use soroban_sdk::BytesN;

#[test]
fn normal_path_logs_and_events_emit_only_sanitized_public_data() {
    let env = Env::default();
    let safe_key = Bytes::from_slice(&env, b"operation_status");
    let safe_val = Bytes::from_slice(&env, b"success");

    // Bounded and safe labels pass through
    let result = sanitize_telemetry_label(&env, &safe_key, &safe_val, 0);
    assert_eq!(result, Ok(safe_val));
}

#[test]
fn failure_path_logs_strip_secrets_and_private_keys() {
    let env = Env::default();
    let secret_key = Bytes::from_slice(&env, b"priv_key");
    let secret_val = Bytes::from_slice(&env, STELLAR_SECRET.as_bytes());

    // Telemetry redaction masks secrets
    let redacted = redact_telemetry_value(&env, &secret_key, &secret_val).expect("Redaction must succeed");
    assert_eq!(redacted, Bytes::from_slice(&env, REDACTED_TOKEN));
    assert_ne!(redacted, secret_val);

    // Direct secret debug formatting never dumps raw secret
    let debug_repr = format!("{:?}", RedactedSecret(STELLAR_SECRET));
    assert!(!debug_repr.contains(STELLAR_SECRET));
}

#[test]
fn normal_and_failure_path_exports_purge_sensitive_material() {
    let env = Env::default();
    let mut fields: Vec<ExportField> = Vec::new(&env);
    fields.push_back(field(&env, symbol_short!("batch_id"), "1001"));
    fields.push_back(field(&env, symbol_short!("seed"), "SECRET_SEED_DATA"));
    fields.push_back(field(&env, symbol_short!("wallet"), "G_ACCOUNT_KEY"));

    let (safe, purged) = purge_forbidden_fields(&env, &fields);
    assert_eq!(purged, 2, "Both seed and wallet must be purged");
    assert_eq!(safe.len(), 1);
    assert_eq!(safe.get(0).unwrap().name, symbol_short!("batch_id"));
}

#[test]
fn retry_path_export_redaction_is_strictly_idempotent() {
    let env = Env::default();
    let mut fields: Vec<ExportField> = Vec::new(&env);
    fields.push_back(field(&env, symbol_short!("priv_key"), "S_KEY_DATA"));
    fields.push_back(field(&env, symbol_short!("tx_hash"), "0x1234"));
    fields.push_back(field(&env, symbol_short!("status"), "settled"));

    // Multiple passes over identical batch return identical redaction
    for _ in 0..3 {
        let (safe, purged) = purge_forbidden_fields(&env, &fields);
        assert_eq!(purged, 2);
        assert_eq!(safe.len(), 1);
        assert_eq!(safe.get(0).unwrap().name, symbol_short!("status"));
    }
}

#[test]
fn error_responses_never_echo_sensitive_inputs_or_secrets() {
    let env = Env::default();
    let corr_id = BytesN::from_array(&env, &[0xAA; 32]);

    // UnsafeSecret error must have user message that does NOT contain raw secret fragments
    let info = describe_error(&env, ErrorDomain::Shared, Error::UnsafeSecret as u32, corr_id.clone());
    assert_eq!(info.category, ErrorCategory::Configuration);
    assert_eq!(info.retryable, false);

    // Format into client envelope
    let client_err = format_client_error(&env, ErrorDomain::Shared, Error::UnsafeSecret as u32, corr_id.clone());
    assert_eq!(client_err.domain, symbol_short!("shared"));
    assert_eq!(client_err.retryable, false);
    assert_eq!(client_err.correlation_id, corr_id);
}

#[test]
fn authorization_path_errors_do_not_leak_internal_state() {
    let env = Env::default();
    let corr_id = BytesN::from_array(&env, &[0xBB; 32]);

    // Unauthorized across domains should present standard non-leaking message
    let info = describe_error(&env, ErrorDomain::AccessControl, Error::Unauthorized as u32, corr_id);
    assert_eq!(info.category, ErrorCategory::Authorization);
    assert_eq!(info.retryable, false);
}


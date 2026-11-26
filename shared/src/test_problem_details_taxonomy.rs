//! Comprehensive automated tests for the stable problem-details error taxonomy (Issue #576).
//!
//! This module provides end-to-end path coverage across all four required dimensions:
//!
//! | Path | What is verified |
//! |---|---|
//! | Normal | Known error codes produce correct stable fields with no leakage |
//! | Failure | Unknown / out-of-range codes fall back to a safe `SYS_ERR` / `UNEXPECTED_ERROR` record |
//! | Retry | Transient errors carry `is_retryable = true` and a positive `retry_after_ms` |
//! | Authorization | `inspect_problem_details` allows admins and rejects unauthorized callers |
//!
//! ## Design goals
//!
//! * **Exhaustive coverage**: every contract domain and error category is exercised.
//! * **Information-leakage prevention**: machine codes, messages, and remediation hints
//!   must never contain internal state, raw discriminant numbers, host addresses, or
//!   panic strings.
//! * **Stability contract**: numeric discriminants, machine codes, and retry semantics
//!   are part of the public API and must not silently drift.
//! * **Edge cases**: zero, `u32::MAX`, code boundaries, and dual-domain codes
//!   (e.g. 960 meaning different things in `SupportAccess` vs `FeatureFlags`).

use crate::{
    auth::{grant_role, set_admin, Role},
    error_taxonomy::{describe_error, is_documented, stable_code, ErrorCategory, ErrorDomain},
    errors::Error,
    problem_details::{problem_details_for_diagnostic_error, problem_details_for_error},
    problem_details_taxonomy::{
        inspect_problem_details, problem_details_from_error, resolve_problem_details,
        PROBLEM_TYPE_BASE_URI,
    },
    diagnostics::DiagnosticError,
};
use soroban_sdk::{
    contract, contractimpl, symbol_short,
    testutils::Address as _,
    Address, BytesN, Env, String,
};

// ---------------------------------------------------------------------------
// Test contract harness
// ---------------------------------------------------------------------------

#[contract]
struct TaxonomyHarness;
#[contractimpl]
impl TaxonomyHarness {}

fn setup_env() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, TaxonomyHarness);
    let admin = Address::generate(&env);
    let non_admin = Address::generate(&env);

    env.as_contract(&contract_id, || {
        set_admin(&env, &admin);
        grant_role(&env, &admin, &admin, Role::Admin).unwrap();
    });

    (env, contract_id, admin)
}

fn corr(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0xAB; 32])
}

// ---------------------------------------------------------------------------
// 1. NORMAL PATH — known error codes produce correct stable fields
// ---------------------------------------------------------------------------

#[test]
fn normal_path_shared_errors_map_to_stable_codes() {
    let env = Env::default();

    // Authorization class → UNAUTHORIZED, non-retryable
    let info = describe_error(&env, ErrorDomain::Shared, Error::Unauthorized as u32, corr(&env));
    assert_eq!(info.code, String::from_str(&env, "UNAUTHORIZED"));
    assert_eq!(info.category, ErrorCategory::Authorization);
    assert!(!info.retryable);
    assert!(info.recovery.is_some());

    // Validation class → VALIDATION_FAILED, non-retryable
    let info = describe_error(&env, ErrorDomain::Shared, Error::InvalidAmount as u32, corr(&env));
    assert_eq!(info.code, String::from_str(&env, "VALIDATION_FAILED"));
    assert_eq!(info.category, ErrorCategory::Validation);
    assert!(!info.retryable);

    // Not-found class → RESOURCE_NOT_FOUND, non-retryable
    let info = describe_error(&env, ErrorDomain::Shared, Error::NotFound as u32, corr(&env));
    assert_eq!(info.code, String::from_str(&env, "RESOURCE_NOT_FOUND"));
    assert_eq!(info.category, ErrorCategory::NotFound);
    assert!(!info.retryable);

    // Conflict class (already claimed) → INVALID_STATE, non-retryable
    let info = describe_error(&env, ErrorDomain::Shared, Error::AlreadyClaimed as u32, corr(&env));
    assert_eq!(info.code, String::from_str(&env, "INVALID_STATE"));
    assert_eq!(info.category, ErrorCategory::Conflict);
    assert!(!info.retryable);
}

#[test]
fn normal_path_resolve_problem_details_covers_all_primary_codes() {
    // Spot-check every primary code class in the taxonomy.
    let cases: &[(u32, &str, u32, bool)] = &[
        (1,   "AUTH_UNAU",  403, false),
        (2,   "NOT_FOUND",  404, false),
        (3,   "VAL_AMT",    422, false),
        (4,   "VAL_OVF",    422, false),
        (5,   "PAUSED",     503, true ),
        (6,   "ST_EXPIRE",  409, false),
        (7,   "ST_CLAIM",   409, false),
        (8,   "LOW_FUNDS",  409, false),
        (10,  "VAL_ARG",    400, false),
        (901, "DEGRADED",   503, true ),
        (940, "AUTH_ADM",   403, false),
        (941, "AUTH_ESC",   403, false),
    ];

    for &(code, expected_machine, expected_http, expected_retry) in cases {
        let rec = resolve_problem_details(code);
        assert_eq!(rec.error_code, code, "code mismatch for {code}");
        assert_eq!(rec.machine_code, symbol_short!(expected_machine), "machine_code for {code}");
        assert_eq!(rec.http_status, expected_http, "http_status for {code}");
        assert_eq!(rec.is_retryable, expected_retry, "is_retryable for {code}");
        assert!(rec.http_status >= 400 && rec.http_status < 600, "http_status must be 4xx or 5xx");
    }
}

#[test]
fn normal_path_problem_details_from_error_agrees_with_resolve() {
    let errors_and_codes: &[(Error, u32)] = &[
        (Error::Unauthorized,       1),
        (Error::NotFound,           2),
        (Error::InvalidAmount,      3),
        (Error::Overflow,           4),
        (Error::ContractPaused,     5),
        (Error::Expired,            6),
        (Error::AlreadyClaimed,     7),
        (Error::InsufficientBalance,8),
        (Error::InvalidArgument,   10),
    ];

    for &(err, expected_code) in errors_and_codes {
        let via_error = problem_details_from_error(err);
        let via_code  = resolve_problem_details(expected_code);
        assert_eq!(via_error, via_code, "problem_details_from_error must agree with resolve for {err:?}");
    }
}

#[test]
fn normal_path_all_domains_map_primary_codes_correctly() {
    let env = Env::default();

    // Aid domain
    let aid = describe_error(&env, ErrorDomain::Aid, 100, corr(&env));
    assert_eq!(aid.code, String::from_str(&env, "UNAUTHORIZED"));
    assert_eq!(aid.category, ErrorCategory::Authorization);

    // Oracle domain
    let oracle = describe_error(&env, ErrorDomain::Oracle, 501, corr(&env));
    assert_eq!(oracle.code, String::from_str(&env, "ORACLE_DUPLICATE_SUBMISSION"));
    assert_eq!(oracle.category, ErrorCategory::Conflict);

    // AccessControl domain
    let acl = describe_error(&env, ErrorDomain::AccessControl, 212, corr(&env));
    assert_eq!(acl.code, String::from_str(&env, "RATE_LIMITED"));
    assert_eq!(acl.category, ErrorCategory::Conflict);
    assert!(acl.retryable, "rate-limited access control must be retryable");

    // Treasury domain
    let treasury = describe_error(&env, ErrorDomain::Treasury, 301, corr(&env));
    assert_eq!(treasury.code, String::from_str(&env, "INSUFFICIENT_FUNDS"));
    assert_eq!(treasury.category, ErrorCategory::Settlement);

    // Governance domain
    let gov = describe_error(&env, ErrorDomain::Governance, 402, corr(&env));
    assert_eq!(gov.code, String::from_str(&env, "ALREADY_VOTED"));
    assert_eq!(gov.category, ErrorCategory::Conflict);

    // Referral domain
    let referral = describe_error(&env, ErrorDomain::Referral, 601, corr(&env));
    assert_eq!(referral.code, String::from_str(&env, "REFERRAL_NOT_FOUND"));
    assert_eq!(referral.category, ErrorCategory::NotFound);

    // Registry domain
    let registry = describe_error(&env, ErrorDomain::Registry, 1102, corr(&env));
    assert_eq!(registry.code, String::from_str(&env, "CONTRACT_ALREADY_REGISTERED"));
    assert_eq!(registry.category, ErrorCategory::Conflict);

    // Payments domain
    let pay = describe_error(&env, ErrorDomain::Payments, 708, corr(&env));
    assert_eq!(pay.code, String::from_str(&env, "INVALID_FEE_RATE"));
    assert_eq!(pay.category, ErrorCategory::Validation);

    // Batch domain
    let batch = describe_error(&env, ErrorDomain::Batch, 801, corr(&env));
    assert_eq!(batch.code, String::from_str(&env, "BATCH_OPERATION_FAILED"));

    // Jobs domain
    let job = describe_error(&env, ErrorDomain::Jobs, 3, corr(&env));
    assert_eq!(job.code, String::from_str(&env, "JOB_NOT_FOUND"));
    assert_eq!(job.category, ErrorCategory::NotFound);

    // Upgradeability domain
    let upg = describe_error(&env, ErrorDomain::Upgradeability, 915, corr(&env));
    assert_eq!(upg.code, String::from_str(&env, "TIMELOCK_NOT_EXPIRED"));
    assert_eq!(upg.category, ErrorCategory::Conflict);
    assert!(upg.retryable, "timelock-not-expired must be retryable");
}

#[test]
fn normal_path_import_and_export_domains() {
    let env = Env::default();

    let import = describe_error(&env, ErrorDomain::Import, 943, corr(&env));
    assert_eq!(import.code, String::from_str(&env, "DUPLICATE_ID"));
    assert_eq!(import.category, ErrorCategory::Conflict);

    let export = describe_error(&env, ErrorDomain::Export, 924, corr(&env));
    assert_eq!(export.code, String::from_str(&env, "EXPORT_EXPIRED"));
    assert_eq!(export.category, ErrorCategory::Conflict);
    assert!(!export.retryable);

    let export_auth = describe_error(&env, ErrorDomain::Export, 920, corr(&env));
    assert_eq!(export_auth.code, String::from_str(&env, "UNAUTHORIZED"));
    assert_eq!(export_auth.category, ErrorCategory::Authorization);
}

#[test]
fn normal_path_support_access_domain() {
    let env = Env::default();

    let session = describe_error(&env, ErrorDomain::SupportAccess, 960, corr(&env));
    assert_eq!(session.code, String::from_str(&env, "SUPPORT_SESSION_NOT_FOUND"));
    assert_eq!(session.category, ErrorCategory::NotFound);

    let expired = describe_error(&env, ErrorDomain::SupportAccess, 964, corr(&env));
    assert_eq!(expired.code, String::from_str(&env, "SUPPORT_SESSION_EXPIRED"));
    assert_eq!(expired.category, ErrorCategory::Conflict);
    assert!(!expired.retryable);
}

#[test]
fn normal_path_feature_flags_domain() {
    let env = Env::default();

    let disabled = describe_error(&env, ErrorDomain::FeatureFlags, 961, corr(&env));
    assert_eq!(disabled.code, String::from_str(&env, "FEATURE_DISABLED"));
    assert_eq!(disabled.category, ErrorCategory::Configuration);
    assert!(!disabled.retryable);

    let guard = describe_error(&env, ErrorDomain::FeatureFlags, 962, corr(&env));
    assert_eq!(guard.code, String::from_str(&env, "FEATURE_GUARD_BLOCKED"));
    assert!(guard.retryable, "guard-blocked feature is transient");
}

#[test]
fn normal_path_correlation_id_is_preserved() {
    let env = Env::default();
    let id = BytesN::from_array(&env, &[0xDE; 32]);
    let info = describe_error(&env, ErrorDomain::Payments, Error::Expired as u32, id.clone());
    assert_eq!(info.correlation_id, id);
}

#[test]
fn normal_path_stable_code_matches_describe_error() {
    let env = Env::default();
    let samples = [
        (ErrorDomain::Shared,       Error::Unauthorized as u32),
        (ErrorDomain::Shared,       Error::InvalidArgument as u32),
        (ErrorDomain::Aid,          100u32),
        (ErrorDomain::AccessControl,206u32),
        (ErrorDomain::Upgradeability,907u32),
        (ErrorDomain::Jobs,         7u32),
        (ErrorDomain::Registry,     1101u32),
    ];
    for (domain, code) in samples {
        let info = describe_error(&env, domain.clone(), code, corr(&env));
        assert_eq!(
            info.code,
            String::from_str(&env, stable_code(domain.clone(), code)),
            "stable_code must agree with describe_error for {domain:?}/{code}"
        );
        assert!(is_documented(domain, code), "code {code} must be documented");
    }
}

#[test]
fn normal_path_problem_details_for_error_covers_core_variants() {
    // Verifies the lighter `problem_details.rs` renderer on the same variants.
    let unauthorized = problem_details_for_error(&Error::Unauthorized);
    assert_eq!(unauthorized.code, "TRELLIS_UNAUTHORIZED");
    assert_eq!(unauthorized.kind, "auth.unauthorized");
    assert!(!unauthorized.message.is_empty());
    assert!(!unauthorized.remediation.is_empty());

    let not_found = problem_details_for_error(&Error::NotFound);
    assert_eq!(not_found.code, "TRELLIS_NOT_FOUND");
    assert_eq!(not_found.kind, "state.not_found");

    let paused = problem_details_for_error(&Error::ContractPaused);
    assert_eq!(paused.code, "TRELLIS_CONTRACT_PAUSED");
    assert_eq!(paused.kind, "state.paused");

    let invalid_amount = problem_details_for_error(&Error::InvalidAmount);
    assert_eq!(invalid_amount.code, "TRELLIS_INVALID_AMOUNT");
    assert_eq!(invalid_amount.kind, "validation.invalid_amount");
}

#[test]
fn normal_path_diagnostic_errors_render_safe_details() {
    let empty = problem_details_for_diagnostic_error(&DiagnosticError::EmptyDiagnosticsList);
    assert_eq!(empty.code, "TRELLIS_DIAG_EMPTY_LIST");
    assert!(!empty.message.is_empty());
    assert!(!empty.remediation.is_empty());

    let invalid = problem_details_for_diagnostic_error(&DiagnosticError::DiagnosticValidationFailed);
    assert_eq!(invalid.code, "TRELLIS_DIAG_VALIDATION_FAILED");

    let dep = problem_details_for_diagnostic_error(&DiagnosticError::DependencyInvariantViolated);
    assert_eq!(dep.code, "TRELLIS_DIAG_DEPENDENCY_INVARIANT");

    let schema = problem_details_for_diagnostic_error(&DiagnosticError::StorageSchemaInvalid);
    assert_eq!(schema.code, "TRELLIS_DIAG_STORAGE_SCHEMA");

    let unauth = problem_details_for_diagnostic_error(&DiagnosticError::Unauthorized);
    assert_eq!(unauth.code, "TRELLIS_DIAG_UNAUTHORIZED");
}

#[test]
fn normal_path_problem_type_base_uri_is_stable() {
    // The URN prefix is part of the public API surface for RFC 9457 consumers.
    assert_eq!(PROBLEM_TYPE_BASE_URI, "urn:trellis:error:");
}

// ---------------------------------------------------------------------------
// 2. FAILURE PATH — unknown codes fall back to safe SYS_ERR / UNEXPECTED_ERROR
// ---------------------------------------------------------------------------

#[test]
fn failure_path_unknown_code_returns_safe_fallback() {
    let rec = resolve_problem_details(999_999);
    assert_eq!(rec.machine_code, symbol_short!("SYS_ERR"));
    assert_eq!(rec.category, symbol_short!("internal"));
    assert_eq!(rec.http_status, 500);
    assert!(!rec.is_retryable, "unknown errors must not be retryable");
    assert_eq!(rec.retry_after_ms, 0, "no retry hint on fallback");
    // The error_code field must reflect the actual unknown code, not 0.
    assert_eq!(rec.error_code, 999_999);
}

#[test]
fn failure_path_zero_code_returns_safe_fallback() {
    let rec = resolve_problem_details(0);
    assert_eq!(rec.machine_code, symbol_short!("SYS_ERR"));
    assert_eq!(rec.http_status, 500);
    assert!(!rec.is_retryable);
}

#[test]
fn failure_path_max_u32_code_returns_safe_fallback() {
    let rec = resolve_problem_details(u32::MAX);
    assert_eq!(rec.machine_code, symbol_short!("SYS_ERR"));
    assert_eq!(rec.http_status, 500);
}

#[test]
fn failure_path_undocumented_domain_code_returns_unexpected_error() {
    let env = Env::default();
    let info = describe_error(&env, ErrorDomain::Oracle, 99_999, corr(&env));
    assert_eq!(info.code, String::from_str(&env, "UNEXPECTED_ERROR"));
    assert_eq!(info.category, ErrorCategory::Internal);
    assert!(!info.retryable);
    assert!(info.recovery.is_some(), "fallback must include a recovery hint");
}

#[test]
fn failure_path_undocumented_code_is_not_reported_as_documented() {
    // is_documented must return false for unregistered codes.
    assert!(!is_documented(ErrorDomain::Oracle, 99_999));
    assert!(!is_documented(ErrorDomain::Aid, 999));
    assert!(!is_documented(ErrorDomain::AccessControl, 9_999));
    assert!(!is_documented(ErrorDomain::Shared, 99_999));
}

#[test]
fn failure_path_problem_details_for_error_fallback_is_safe() {
    // DependencyDegraded has no explicit branch in problem_details.rs → fallback.
    let details = problem_details_for_error(&Error::DependencyDegraded);
    assert_eq!(details.code, "TRELLIS_UNEXPECTED_ERROR");
    assert!(!details.message.is_empty());
    assert!(!details.remediation.is_empty());
    assert!(!details.docs_url.is_empty());
}

#[test]
fn failure_path_message_never_contains_internal_identifiers() {
    // No user-facing message must contain internal Rust identifiers or panic keywords.
    let variants_to_check = [
        Error::Unauthorized,
        Error::InvalidAmount,
        Error::Overflow,
        Error::ContractPaused,
        Error::InsufficientBalance,
    ];
    let forbidden = ["panic", "unwrap", "expect", "::Err", "::Ok"];

    for err in variants_to_check {
        let details = problem_details_for_error(&err);
        for kw in forbidden {
            assert!(
                !details.message.contains(kw),
                "message for {err:?} leaks '{kw}': {}",
                details.message
            );
            assert!(
                !details.remediation.contains(kw),
                "remediation for {err:?} leaks '{kw}': {}",
                details.remediation
            );
        }
    }
}

#[test]
fn failure_path_all_domain_records_have_non_empty_safe_fields() {
    let env = Env::default();
    let ranges: &[(ErrorDomain, u32, u32)] = &[
        (ErrorDomain::Aid,           100, 117),
        (ErrorDomain::AccessControl, 200, 223),
        (ErrorDomain::Oracle,        500, 511),
        (ErrorDomain::Upgradeability,900, 915),
        (ErrorDomain::Import,        940, 949),
        (ErrorDomain::Export,        920, 934),
        (ErrorDomain::Jobs,          1,   9),
        (ErrorDomain::Marketplace,   2000,2023),
        (ErrorDomain::SupportAccess, 960, 973),
        (ErrorDomain::FeatureFlags,  960, 968),
        (ErrorDomain::Payments,      700, 711),
        (ErrorDomain::Treasury,      300, 305),
        (ErrorDomain::Governance,    400, 405),
        (ErrorDomain::Referral,      600, 603),
        (ErrorDomain::Registry,      1100,1102),
        (ErrorDomain::Batch,         800, 805),
    ];

    for (domain, first, last) in ranges {
        for code in *first..=*last {
            let info = describe_error(&env, domain.clone(), code, corr(&env));
            assert_ne!(
                info.code,
                String::from_str(&env, "UNEXPECTED_ERROR"),
                "{domain:?} code {code} must be documented"
            );
            assert!(
                !info.message.is_empty(),
                "{domain:?} code {code} must have a message"
            );
            assert!(
                info.recovery.is_some(),
                "{domain:?} code {code} must have a recovery hint"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 3. RETRY PATH — transient errors carry correct retry semantics
// ---------------------------------------------------------------------------

#[test]
fn retry_path_contract_paused_is_transient_with_backoff() {
    let rec = resolve_problem_details(5); // Error::ContractPaused
    assert!(rec.is_retryable, "ContractPaused must be retryable");
    assert!(rec.retry_after_ms > 0, "ContractPaused must suggest a backoff delay");
    assert_eq!(rec.http_status, 503);
}

#[test]
fn retry_path_dependency_degraded_is_transient() {
    let rec = resolve_problem_details(901); // DependencyDegraded
    assert!(rec.is_retryable, "DependencyDegraded must be retryable");
    assert!(rec.retry_after_ms > 0);
    assert_eq!(rec.http_status, 503);
}

#[test]
fn retry_path_permanent_errors_have_no_retry_hint() {
    // These errors are permanent: retrying unchanged will always fail.
    let permanent_codes = [1, 2, 3, 4, 6, 7, 8, 10, 940, 941];

    for code in permanent_codes {
        let rec = resolve_problem_details(code);
        assert!(!rec.is_retryable, "code {code} must not be retryable");
        assert_eq!(rec.retry_after_ms, 0, "permanent errors must have retry_after_ms = 0");
    }
}

#[test]
fn retry_path_transient_domain_errors_are_retryable() {
    let env = Env::default();

    // Rate-limited access control is retryable.
    let rate_limited = describe_error(&env, ErrorDomain::AccessControl, 212, corr(&env));
    assert!(rate_limited.retryable, "RATE_LIMITED must be retryable");

    // Settlement-not-ready for payments is retryable.
    let insuf_pay = describe_error(&env, ErrorDomain::Payments, 701, corr(&env));
    assert!(insuf_pay.retryable, "PaymentInsufficientBalance must be retryable");

    // Timelock-not-expired for upgrade is retryable.
    let timelock = describe_error(&env, ErrorDomain::Upgradeability, 915, corr(&env));
    assert!(timelock.retryable, "TIMELOCK_NOT_EXPIRED must be retryable");

    // Aid milestone not verified is retryable.
    let milestone = describe_error(&env, ErrorDomain::Aid, 116, corr(&env));
    assert!(milestone.retryable, "MILESTONE_NOT_VERIFIED must be retryable");

    // Jobs: job not due is retryable.
    let not_due = describe_error(&env, ErrorDomain::Jobs, 5, corr(&env));
    assert!(not_due.retryable, "JOB_NOT_DUE must be retryable");

    // Jobs: worker queue full is retryable.
    let queue_full = describe_error(&env, ErrorDomain::Jobs, 8, corr(&env));
    assert!(queue_full.retryable, "WORKER_QUEUE_FULL must be retryable");

    // Feature guard blocked is transient.
    let guard = describe_error(&env, ErrorDomain::FeatureFlags, 962, corr(&env));
    assert!(guard.retryable, "FEATURE_GUARD_BLOCKED must be retryable");

    // Treasury insufficient funds is retryable.
    let treasury = describe_error(&env, ErrorDomain::Treasury, 301, corr(&env));
    assert!(treasury.retryable, "INSUFFICIENT_FUNDS must be retryable");

    // Governance below threshold is retryable.
    let gov = describe_error(&env, ErrorDomain::Governance, 403, corr(&env));
    assert!(gov.retryable, "BELOW_THRESHOLD must be retryable");
}

#[test]
fn retry_path_permanent_domain_errors_are_not_retryable() {
    let env = Env::default();

    // Authorization failures are always permanent.
    let unauth_aid = describe_error(&env, ErrorDomain::Aid, 100, corr(&env));
    assert!(!unauth_aid.retryable);

    // Conflict/state errors are permanent.
    let already_voted = describe_error(&env, ErrorDomain::Governance, 402, corr(&env));
    assert!(!already_voted.retryable);

    // FeatureFlags rolled back is permanent.
    let rolled_back = describe_error(&env, ErrorDomain::FeatureFlags, 963, corr(&env));
    assert!(!rolled_back.retryable);

    // Escrow already released is permanent.
    let released = describe_error(&env, ErrorDomain::Payments, 703, corr(&env));
    assert!(!released.retryable);
}

#[test]
fn retry_path_contract_paused_vs_dependency_degraded_backoff_ordering() {
    // ContractPaused (operator-controlled) should suggest longer backoff than
    // DependencyDegraded (service recovery is typically faster).
    let paused = resolve_problem_details(5);
    let degraded = resolve_problem_details(901);
    assert!(paused.retry_after_ms >= degraded.retry_after_ms,
        "ContractPaused backoff ({}) must be >= DependencyDegraded backoff ({})",
        paused.retry_after_ms, degraded.retry_after_ms
    );
}

// ---------------------------------------------------------------------------
// 4. AUTHORIZATION PATH — inspect_problem_details gating
// ---------------------------------------------------------------------------

#[test]
fn authorization_path_admin_can_inspect_any_code() {
    let (env, contract_id, admin) = setup_env();

    env.as_contract(&contract_id, || {
        // Known code — returns the full record
        let rec = inspect_problem_details(&env, &admin, 3).unwrap();
        assert_eq!(rec.http_status, 422);
        assert!(!rec.is_retryable);

        // Unknown code — returns the safe fallback, not an error
        let fallback = inspect_problem_details(&env, &admin, 99_999).unwrap();
        assert_eq!(fallback.machine_code, symbol_short!("SYS_ERR"));
        assert_eq!(fallback.http_status, 500);
    });
}

#[test]
fn authorization_path_non_admin_is_rejected_with_unauthorized() {
    let (env, contract_id, _admin) = setup_env();
    let non_admin = Address::generate(&env);

    env.as_contract(&contract_id, || {
        let err = inspect_problem_details(&env, &non_admin, 3);
        assert_eq!(err, Err(Error::Unauthorized));
    });
}

#[test]
fn authorization_path_non_admin_cannot_inspect_transient_codes() {
    let (env, contract_id, _admin) = setup_env();
    let non_admin = Address::generate(&env);

    // Even publicly-known transient codes must require admin auth.
    env.as_contract(&contract_id, || {
        let err = inspect_problem_details(&env, &non_admin, 5); // ContractPaused
        assert_eq!(err, Err(Error::Unauthorized));
    });
}

#[test]
fn authorization_path_admin_inspect_returns_complete_record() {
    let (env, contract_id, admin) = setup_env();

    env.as_contract(&contract_id, || {
        for code in [1u32, 2, 3, 5, 10, 940] {
            let rec = inspect_problem_details(&env, &admin, code).unwrap();
            assert_eq!(rec.error_code, code);
            assert!(rec.http_status >= 400 && rec.http_status < 600);
        }
    });
}

// ---------------------------------------------------------------------------
// 5. EDGE CASES
// ---------------------------------------------------------------------------

#[test]
fn edge_case_code_960_is_domain_specific() {
    let env = Env::default();

    // In SupportAccess domain: 960 = SUPPORT_SESSION_NOT_FOUND
    let support = describe_error(&env, ErrorDomain::SupportAccess, 960, corr(&env));
    assert_eq!(support.code, String::from_str(&env, "SUPPORT_SESSION_NOT_FOUND"));
    assert_eq!(support.category, ErrorCategory::NotFound);

    // In FeatureFlags domain: 960 = FEATURE_ROLLOUT_INVALID
    let flag = describe_error(&env, ErrorDomain::FeatureFlags, 960, corr(&env));
    assert_eq!(flag.code, String::from_str(&env, "FEATURE_ROLLOUT_INVALID"));
    assert_eq!(flag.category, ErrorCategory::Validation);

    // The two must differ — same numeric code, different domain-specific meanings.
    assert_ne!(support.code, flag.code);
    assert_ne!(support.category, flag.category);
}

#[test]
fn edge_case_code_961_is_domain_specific() {
    let env = Env::default();

    // SupportAccess: 961 = SUPPORT_ACCESS_UNAUTHORIZED
    let support = describe_error(&env, ErrorDomain::SupportAccess, 961, corr(&env));
    assert_eq!(support.code, String::from_str(&env, "SUPPORT_ACCESS_UNAUTHORIZED"));

    // FeatureFlags: 961 = FEATURE_DISABLED
    let flag = describe_error(&env, ErrorDomain::FeatureFlags, 961, corr(&env));
    assert_eq!(flag.code, String::from_str(&env, "FEATURE_DISABLED"));

    assert_ne!(support.code, flag.code);
}

#[test]
fn edge_case_upgrade_rollback_is_permanent_do_not_retry() {
    let env = Env::default();
    let rollback = describe_error(&env, ErrorDomain::Upgradeability, 913, corr(&env));
    assert_eq!(rollback.code, String::from_str(&env, "UPGRADE_ROLLED_BACK"));
    assert!(!rollback.retryable, "rolled-back upgrade must not be retried automatically");
}

#[test]
fn edge_case_aid_milestone_boundary_codes() {
    let env = Env::default();

    // 114 = NOT_MILESTONE_BASED, 115 = INVALID_MILESTONE
    let not_ms = describe_error(&env, ErrorDomain::Aid, 114, corr(&env));
    assert_eq!(not_ms.code, String::from_str(&env, "NOT_MILESTONE_BASED"));
    assert!(!not_ms.retryable);

    let invalid_ms = describe_error(&env, ErrorDomain::Aid, 115, corr(&env));
    assert_eq!(invalid_ms.code, String::from_str(&env, "INVALID_MILESTONE"));
    assert!(!invalid_ms.retryable);

    let ms_claimed = describe_error(&env, ErrorDomain::Aid, 117, corr(&env));
    assert_eq!(ms_claimed.code, String::from_str(&env, "MILESTONE_ALREADY_CLAIMED"));
    assert!(!ms_claimed.retryable);
}

#[test]
fn edge_case_marketplace_boundary_codes() {
    let env = Env::default();

    // 2000 = listing not found, 2023 = last listed code
    let not_found = describe_error(&env, ErrorDomain::Marketplace, 2000, corr(&env));
    assert_ne!(not_found.code, String::from_str(&env, "UNEXPECTED_ERROR"));

    let last = describe_error(&env, ErrorDomain::Marketplace, 2023, corr(&env));
    assert_ne!(last.code, String::from_str(&env, "UNEXPECTED_ERROR"));

    // 2024 = out of range → fallback
    let out_of_range = describe_error(&env, ErrorDomain::Marketplace, 2024, corr(&env));
    assert_eq!(out_of_range.code, String::from_str(&env, "UNEXPECTED_ERROR"));
}

#[test]
fn edge_case_access_control_ownership_transfer_codes() {
    let env = Env::default();

    // 218 = NO_PENDING_TRANSFER, 219 = TRANSFER_EXPIRED, 220 = not-pending-owner
    let no_transfer = describe_error(&env, ErrorDomain::AccessControl, 218, corr(&env));
    assert_eq!(no_transfer.code, String::from_str(&env, "NO_PENDING_TRANSFER"));
    assert_eq!(no_transfer.category, ErrorCategory::NotFound);

    let expired = describe_error(&env, ErrorDomain::AccessControl, 219, corr(&env));
    assert_eq!(expired.code, String::from_str(&env, "TRANSFER_EXPIRED"));

    let wrong_owner = describe_error(&env, ErrorDomain::AccessControl, 220, corr(&env));
    assert_eq!(wrong_owner.code, String::from_str(&env, "UNAUTHORIZED"));
    assert!(!wrong_owner.retryable);

    let already_pending = describe_error(&env, ErrorDomain::AccessControl, 221, corr(&env));
    assert_eq!(already_pending.code, String::from_str(&env, "TRANSFER_ALREADY_PENDING"));
    assert!(!already_pending.retryable);
}

#[test]
fn edge_case_rollback_not_verified_before_reenable() {
    let env = Env::default();
    // 968 = ROLLBACK_NOT_VERIFIED — cannot re-enable until rollback is clean.
    let rec = describe_error(&env, ErrorDomain::FeatureFlags, 968, corr(&env));
    assert_eq!(rec.code, String::from_str(&env, "ROLLBACK_NOT_VERIFIED"));
    assert_eq!(rec.category, ErrorCategory::Conflict);
    assert!(!rec.retryable);
    assert!(rec.recovery.is_some());
}

#[test]
fn edge_case_support_audit_unavailable_is_permanent_internal() {
    let env = Env::default();
    let audit = describe_error(&env, ErrorDomain::SupportAccess, 971, corr(&env));
    assert_eq!(audit.code, String::from_str(&env, "SUPPORT_AUDIT_UNAVAILABLE"));
    assert_eq!(audit.category, ErrorCategory::Internal);
    assert!(!audit.retryable);
}

#[test]
fn edge_case_every_documented_code_has_a_recovery_hint() {
    let env = Env::default();
    let ranges: &[(ErrorDomain, u32, u32)] = &[
        (ErrorDomain::Aid,           100, 117),
        (ErrorDomain::AccessControl, 200, 223),
        (ErrorDomain::Oracle,        500, 511),
        (ErrorDomain::Upgradeability,900, 915),
        (ErrorDomain::Import,        940, 949),
        (ErrorDomain::Export,        920, 934),
        (ErrorDomain::Jobs,          1,   9),
        (ErrorDomain::Marketplace,   2000,2023),
        (ErrorDomain::SupportAccess, 960, 973),
        (ErrorDomain::FeatureFlags,  960, 968),
        (ErrorDomain::Payments,      700, 711),
        (ErrorDomain::Treasury,      300, 305),
        (ErrorDomain::Governance,    400, 405),
        (ErrorDomain::Referral,      600, 603),
        (ErrorDomain::Registry,      1100,1102),
        (ErrorDomain::Batch,         800, 805),
    ];

    for (domain, first, last) in ranges {
        for code in *first..=*last {
            let info = describe_error(&env, domain.clone(), code, corr(&env));
            assert!(
                info.recovery.is_some(),
                "{domain:?} code {code} must include a recovery hint"
            );
        }
    }
}

#[test]
fn edge_case_stable_code_for_undocumented_is_unexpected_error() {
    // Off-spec codes in documented domains must resolve to UNEXPECTED_ERROR.
    assert_eq!(stable_code(ErrorDomain::Oracle, 9_999), "UNEXPECTED_ERROR");
    assert_eq!(stable_code(ErrorDomain::AccessControl, 300), "UNEXPECTED_ERROR");
    assert_eq!(stable_code(ErrorDomain::Aid, 200), "UNEXPECTED_ERROR");
}

#[test]
fn edge_case_describe_error_does_not_panic_on_any_u32() {
    let env = Env::default();
    // Sample a wide range of potential codes — none should panic.
    let codes = [0u32, 1, 100, 500, 700, 900, 1000, 2000, 50_000, u32::MAX];
    for &code in &codes {
        for domain in [
            ErrorDomain::Shared,
            ErrorDomain::Aid,
            ErrorDomain::Oracle,
            ErrorDomain::Payments,
        ] {
            let info = describe_error(&env, domain, code, corr(&env));
            // Any result is acceptable — the important thing is no panic.
            let _ = info.code;
        }
    }
}

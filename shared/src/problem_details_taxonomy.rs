//! Stable API problem-details taxonomy and error resolution layer (Issue #497).
//!
//! Provides an RFC 7807 / RFC 9457 compliant error presentation taxonomy for Trellis
//! Soroban contracts:
//!
//! 1. **Stable Machine Codes**: Every known error variant maps to an immutable,
//!    human- and machine-readable code (e.g. `AUTH_UNAU`, `VAL_AMT`) and an assigned
//!    HTTP status class (400, 401, 403, 404, 409, 422, 500, 503).
//! 2. **Information Leakage Prevention**: Translates low-level internal errors into
//!    safe, non-leaking user messages and actionable remediation hints without exposing
//!    host memory, cryptographic keys, or storage addresses.
//! 3. **Retryability Classification**: Distinguishes transient failures (e.g., contract pause,
//!    rate limit, dependency degradation) from permanent rejections (e.g., unauthorized,
//!    invalid argument, boundary overflow) with deterministic retry recommendations.
//! 4. **Administrative Verification & Inspection**: Exposes permission-guarded introspection
//!    for contract maintainers and automated telemetry pipelines.
//! 5. **Path Coverage**: Thoroughly exercises normal, failure, retry, and authorization paths.

use soroban_sdk::{contracttype, symbol_short, Address, Env, Symbol};

use crate::auth::require_admin;
use crate::errors::Error;

/// Base URI for Trellis problem details type definitions.
pub const PROBLEM_TYPE_BASE_URI: &str = "urn:trellis:error:";

/// Standard problem details representation compliant with RFC 7807 / RFC 9457.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProblemDetailsRecord {
    /// Internal numeric error discriminant.
    pub error_code: u32,
    /// Stable machine code (e.g. `AUTH_UNAU`).
    pub machine_code: Symbol,
    /// Dotted category namespace (e.g. `auth`, `validate`, `conflict`, `internal`).
    pub category: Symbol,
    /// Equivalent HTTP transport status (e.g. 400, 403, 404, 409, 500, 503).
    pub http_status: u32,
    /// User-safe non-leaking error summary.
    pub title: Symbol,
    /// Actionable remediation advice.
    pub remediation: Symbol,
    /// Whether the error condition is considered transient and safe to retry.
    pub is_retryable: bool,
    /// Recommended backoff time in milliseconds before retry, if retryable.
    pub retry_after_ms: u32,
}

/// Authoritative mapping function converting contract error codes to problem details.
pub fn resolve_problem_details(error_code: u32) -> ProblemDetailsRecord {
    match error_code {
        // --- Authorization (401 / 403) ---
        1 => ProblemDetailsRecord {
            error_code: 1, // Error::Unauthorized
            machine_code: symbol_short!("AUTH_UNAU"),
            category: symbol_short!("auth"),
            http_status: 403,
            title: symbol_short!("Unauth"),
            remediation: symbol_short!("SignKey"),
            is_retryable: false,
            retry_after_ms: 0,
        },
        940 => ProblemDetailsRecord {
            error_code: 940, // AccessControlError::NotAdmin
            machine_code: symbol_short!("AUTH_ADM"),
            category: symbol_short!("auth"),
            http_status: 403,
            title: symbol_short!("AdminReq"),
            remediation: symbol_short!("UseAdmin"),
            is_retryable: false,
            retry_after_ms: 0,
        },
        941 => ProblemDetailsRecord {
            error_code: 941, // AccessControlError::RoleEscalation
            machine_code: symbol_short!("AUTH_ESC"),
            category: symbol_short!("auth"),
            http_status: 403,
            title: symbol_short!("RoleReq"),
            remediation: symbol_short!("ReqRole"),
            is_retryable: false,
            retry_after_ms: 0,
        },

        // --- Validation (400 / 422) ---
        3 => ProblemDetailsRecord {
            error_code: 3, // Error::InvalidAmount
            machine_code: symbol_short!("VAL_AMT"),
            category: symbol_short!("validate"),
            http_status: 422,
            title: symbol_short!("BadAmount"),
            remediation: symbol_short!("FixAmount"),
            is_retryable: false,
            retry_after_ms: 0,
        },
        10 => ProblemDetailsRecord {
            error_code: 10, // Error::InvalidArgument
            machine_code: symbol_short!("VAL_ARG"),
            category: symbol_short!("validate"),
            http_status: 400,
            title: symbol_short!("BadArg"),
            remediation: symbol_short!("FixArgs"),
            is_retryable: false,
            retry_after_ms: 0,
        },
        4 => ProblemDetailsRecord {
            error_code: 4, // Error::Overflow
            machine_code: symbol_short!("VAL_OVF"),
            category: symbol_short!("validate"),
            http_status: 422,
            title: symbol_short!("Overflow"),
            remediation: symbol_short!("ReduceVal"),
            is_retryable: false,
            retry_after_ms: 0,
        },

        // --- Not Found (404) ---
        2 => ProblemDetailsRecord {
            error_code: 2, // Error::NotFound
            machine_code: symbol_short!("NOT_FOUND"),
            category: symbol_short!("state"),
            http_status: 404,
            title: symbol_short!("NotFound"),
            remediation: symbol_short!("CheckId"),
            is_retryable: false,
            retry_after_ms: 0,
        },

        // --- Conflict & State (409) ---
        7 => ProblemDetailsRecord {
            error_code: 7, // Error::AlreadyClaimed
            machine_code: symbol_short!("ST_CLAIM"),
            category: symbol_short!("conflict"),
            http_status: 409,
            title: symbol_short!("Claimed"),
            remediation: symbol_short!("Refresh"),
            is_retryable: false,
            retry_after_ms: 0,
        },
        6 => ProblemDetailsRecord {
            error_code: 6, // Error::Expired
            machine_code: symbol_short!("ST_EXPIRE"),
            category: symbol_short!("conflict"),
            http_status: 409,
            title: symbol_short!("Expired"),
            remediation: symbol_short!("Resubmit"),
            is_retryable: false,
            retry_after_ms: 0,
        },
        8 => ProblemDetailsRecord {
            error_code: 8, // Error::InsufficientBalance
            machine_code: symbol_short!("LOW_FUNDS"),
            category: symbol_short!("conflict"),
            http_status: 409,
            title: symbol_short!("LowFunds"),
            remediation: symbol_short!("FundAcct"),
            is_retryable: false,
            retry_after_ms: 0,
        },

        // --- Transient / Retryable (503 / 429) ---
        5 => ProblemDetailsRecord {
            error_code: 5, // Error::ContractPaused
            machine_code: symbol_short!("PAUSED"),
            category: symbol_short!("transient"),
            http_status: 503,
            title: symbol_short!("Paused"),
            remediation: symbol_short!("WaitPause"),
            is_retryable: true,
            retry_after_ms: 5000,
        },
        901 => ProblemDetailsRecord {
            error_code: 901, // Error::DependencyDegraded
            machine_code: symbol_short!("DEGRADED"),
            category: symbol_short!("transient"),
            http_status: 503,
            title: symbol_short!("Degraded"),
            remediation: symbol_short!("RetrySoon"),
            is_retryable: true,
            retry_after_ms: 3000,
        },

        // --- Unknown / Internal Fallback (500) ---
        _ => ProblemDetailsRecord {
            error_code,
            machine_code: symbol_short!("SYS_ERR"),
            category: symbol_short!("internal"),
            http_status: 500,
            title: symbol_short!("SysError"),
            remediation: symbol_short!("ContactOp"),
            is_retryable: false,
            retry_after_ms: 0,
        },
    }
}

/// Maps a typed contract error to its stable problem details record.
pub fn problem_details_from_error(err: Error) -> ProblemDetailsRecord {
    resolve_problem_details(err as u32)
}

/// Administrative inspection entrypoint allowing maintainers to query the taxonomy.
pub fn inspect_problem_details(
    env: &Env,
    caller: &Address,
    error_code: u32,
) -> Result<ProblemDetailsRecord, Error> {
    require_admin(env, caller)?;
    Ok(resolve_problem_details(error_code))
}

// ---------------------------------------------------------------------------
// Automated Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{grant_role, set_admin, Role};
    use soroban_sdk::{contract, contractimpl, testutils::Address as _, Address, Env};

    #[contract]
    struct TaxonomyTestContract;
    #[contractimpl]
    impl TaxonomyTestContract {}

    fn setup() -> (Env, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, TaxonomyTestContract);
        let admin = Address::generate(&env);
        let user = Address::generate(&env);

        env.as_contract(&contract_id, || {
            set_admin(&env, &admin);
            grant_role(&env, &admin, &admin, Role::Admin).unwrap();
        });

        (env, contract_id, admin, user)
    }

    #[test]
    fn test_normal_path_problem_details_mapping() {
        // Check normal mapping for critical error classes
        let unauth = problem_details_from_error(Error::Unauthorized);
        assert_eq!(unauth.http_status, 403);
        assert_eq!(unauth.category, symbol_short!("auth"));
        assert!(!unauth.is_retryable);

        let bad_amt = problem_details_from_error(Error::InvalidAmount);
        assert_eq!(bad_amt.http_status, 422);
        assert_eq!(bad_amt.category, symbol_short!("validate"));
        assert!(!bad_amt.is_retryable);

        let not_found = problem_details_from_error(Error::NotFound);
        assert_eq!(not_found.http_status, 404);
        assert_eq!(not_found.category, symbol_short!("state"));
        assert!(!not_found.is_retryable);
    }

    #[test]
    fn test_failure_path_safe_fallback_for_unknown_error() {
        // Unknown or future error codes must return a safe internal fallback
        let fallback = resolve_problem_details(999_999);
        assert_eq!(fallback.http_status, 500);
        assert_eq!(fallback.machine_code, symbol_short!("SYS_ERR"));
        assert_eq!(fallback.category, symbol_short!("internal"));
        assert_eq!(fallback.title, symbol_short!("SysError"));
        assert!(!fallback.is_retryable);
    }

    #[test]
    fn test_retry_path_transient_error_classification() {
        // Contract paused is transient
        let paused = problem_details_from_error(Error::ContractPaused);
        assert_eq!(paused.http_status, 503);
        assert_eq!(paused.category, symbol_short!("transient"));
        assert!(paused.is_retryable);
        assert_eq!(paused.retry_after_ms, 5000);

        // Dependency degraded is transient
        let degraded = resolve_problem_details(901);
        assert_eq!(degraded.http_status, 503);
        assert!(degraded.is_retryable);
        assert!(degraded.retry_after_ms > 0);
    }

    #[test]
    fn test_authorization_path_admin_inspection() {
        let (env, contract_id, admin, unauthorized) = setup();

        env.as_contract(&contract_id, || {
            // Admin can inspect taxonomy
            let rec = inspect_problem_details(&env, &admin, 3).unwrap();
            assert_eq!(rec.http_status, 422);

            // Unauthorized caller is rejected with Error::Unauthorized
            let err = inspect_problem_details(&env, &unauthorized, 3);
            assert_eq!(err, Err(Error::Unauthorized));
        });
    }

    #[test]
    fn test_immutability_and_field_completeness() {
        let sample_codes = [1, 2, 3, 4, 5, 6, 7, 8, 10, 901, 940, 941];
        for code in sample_codes {
            let details = resolve_problem_details(code);
            assert_eq!(details.error_code, code);
            assert!(details.http_status >= 400 && details.http_status < 600);
        }
    }
}

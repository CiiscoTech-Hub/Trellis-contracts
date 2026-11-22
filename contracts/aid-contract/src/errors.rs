// API problem-details taxonomy for the Aid contract.
//
// The canonical `AidError` enum lives in `src/lib.rs` under the
// 100-199 numeric range (as documented in `shared/README.md`). This module
// provides a stable, machine-readable problem-details layer on top of that
// enum so off-chain clients can react to failures without parsing free
// text. The codes are stable: they must never be renumbered or reused.
//
// This module is deliberately pure (no storage access) so it is cheap to
// call from any contract entry point and trivially testable.

use crate::AidError;

/// Stable machine code for a problem details response.
///
/// The numeric value is the contract error code and is part of the
/// public API. It is assigned explicitly (never derived from the enum
/// discriminant) so reordering the enum cannot silently change the wire
/// format. New codes are appended; existing codes are never reused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Eq)]
#[repr(u32)]
pub enum AidProblemCode {
    /// The contract is not initialized.
    NotInitialized = 100,
    /// The contract has already been initialized.
    AlreadyInitialized = 101,
    /// The caller is not authorized for this operation.
    Unauthorized = 102,
    /// The requested aid package does not exist.
    PackageNotFound = 103,
    /// The requested aid package is not active.
    PackageInactive = 104,
    /// The recipient has already claimed this package.
    AlreadyClaimed = 105,
    /// The recipient is not eligible for this package.
    NotEligible = 106,
    /// The treasury lacks sufficient funds to settle the claim.
    InsufficientFunds = 107,
    /// An amount argument was zero or otherwise invalid.
    InvalidAmount = 108,
    /// A claim expired before being settled.
    ClaimExpired = 109,
    /// A referral code was not found or is inactive.
    InvalidReferral = 110,
    /// A governance proposal is not in a state that allows the action.
    InvalidProposalState = 111,
    /// An oracle price is stale or missing.
    OraclePriceUnavailable = 112,
    /// A marketplace listing is not available for purchase.
    ListingUnavailable = 113,
    /// An internal invariant was violated; treat as a bug.
    InternalInvariant = 199,
}

/// Safe, user-facing problem details derived from an `AidError`.
///
/// The `status` is an HTTP-like class (e.g. 400, 403, 409, 422, 500) and
/// the `type_uri` points at the documentation for the code. Messages are
/// deliberately generic and never include internal details or P2P data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AidProblemDetails {
    /// Stable machine code.
    pub code: AidProblemCode,
    /// HTTP-like status class for transport mapping.
    pub status: u32,
    /// Stable resolution identifier, e.g. `aid/not-initialized`.
    pub type_uri: &'static str,
    /// Safe, non-leaking message suitable for end users.
    pub title: &'static str,
    /// Actionable remediation hint for clients and operators.
    pub remediation: &'static str,
}

impl AidProblemDetails {
    /// Map an `AidError` to stable problem details.
    ///
    /// This function is the authoritative mapping from internal errors to
    /// stable machine codes and user-facing remediation hints. Never modify
    /// existing mappings; add new codes by appending to `AidProblemCode`.
    pub fn from_error(error: AidError) -> Self {
        match error {
            AidError::Unauthorized => Self {
                code: AidProblemCode::Unauthorized,
                status: 403,
                type_uri: "aid/unauthorized",
                title: "Caller is not authorized for this operation.",
                remediation: "Verify you have the required role or permissions. \
                    For claim operations, ensure you are the intended recipient. \
                    For donor/admin operations, use the appropriate account.",
            },
            AidError::NotFound => Self {
                code: AidProblemCode::PackageNotFound,
                status: 404,
                type_uri: "aid/not-found",
                title: "The requested aid package does not exist.",
                remediation: "Verify the aid ID is correct and has not been deleted. \
                    Check your transaction history or contact the donor.",
            },
            AidError::AlreadyClaimed => Self {
                code: AidProblemCode::AlreadyClaimed,
                status: 409,
                type_uri: "aid/already-claimed",
                title: "The aid package has already been claimed or processed.",
                remediation: "This aid has been settled or refunded. \
                    No further action is possible on this record.",
            },
            AidError::Expired => Self {
                code: AidProblemCode::ClaimExpired,
                status: 410,
                type_uri: "aid/expired",
                title: "The aid package has expired and can no longer be claimed.",
                remediation: "The expiration window has closed. \
                    Contact the donor to arrange a new disbursement. \
                    The donor may refund unclaimed aid after expiry.",
            },
            AidError::Paused => Self {
                code: AidProblemCode::PackageInactive,
                status: 503,
                type_uri: "aid/paused",
                title: "The contract is temporarily paused for maintenance.",
                remediation: "Wait for the contract to resume operations. \
                    Check the project status page for estimated resumption time. \
                    Retry your operation after the pause is lifted.",
            },
            AidError::NotExpiredYet => Self {
                code: AidProblemCode::PackageInactive,
                status: 409,
                type_uri: "aid/not-expired",
                title: "The aid package has not yet expired and cannot be refunded.",
                remediation: "Wait for the expiration ledger to pass, \
                    then retry the refund operation.",
            },
            AidError::AlreadyRefunded => Self {
                code: AidProblemCode::PackageInactive,
                status: 409,
                type_uri: "aid/already-refunded",
                title: "The aid package has already been refunded.",
                remediation: "No further action is possible on this record. \
                    Verify the refund reached the expected account.",
            },
            AidError::CannotDeletePending => Self {
                code: AidProblemCode::PackageInactive,
                status: 409,
                type_uri: "aid/cannot-delete-pending",
                title: "Pending aid records cannot be deleted directly.",
                remediation: "Either claim the aid or wait for expiry \
                    and refund it. Pending records remain until one of these \
                    terminal states is reached.",
            },
            AidError::InvalidCorrelationId => Self {
                code: AidProblemCode::PackageInactive,
                status: 400,
                type_uri: "aid/invalid-correlation-id",
                title: "The correlation ID is malformed or violates policy.",
                remediation: "Provide a valid correlation ID: \
                    a byte string <= 64 bytes, typically a UUID or request hash.",
            },
            AidError::UnsupportedSchemaVersion => Self {
                code: AidProblemCode::PackageInactive,
                status: 500,
                type_uri: "aid/unsupported-schema",
                title: "Contract storage uses a schema version this build does not support.",
                remediation: "Upgrade to a newer contract version that supports \
                    this schema version. Check the release notes for migration steps.",
            },
            AidError::SchemaMigrationFailed => Self {
                code: AidProblemCode::PackageInactive,
                status: 500,
                type_uri: "aid/schema-migration-failed",
                title: "A schema migration was attempted but failed validation.",
                remediation: "Contact the maintainers with the error details. \
                    Do not retry until the issue is resolved. Consider rolling back \
                    to the previous contract version.",
            },
            AidError::InvalidArgument => Self {
                code: AidProblemCode::PackageInactive,
                status: 400,
                type_uri: "aid/invalid-argument",
                title: "One or more arguments are structurally invalid.",
                remediation: "Verify all arguments are of the correct type and \
                    within valid ranges (amounts > 0, expiry in future, etc.). \
                    Check the contract documentation for parameter constraints.",
            },
            AidError::BatchTooLarge => Self {
                code: AidProblemCode::PackageInactive,
                status: 400,
                type_uri: "aid/batch-too-large",
                title: "The batch contains too many allocations.",
                remediation: "Split the batch into smaller groups \
                    (max 50 allocations per batch).",
            },
            AidError::EmptyBatch => Self {
                code: AidProblemCode::PackageInactive,
                status: 400,
                type_uri: "aid/empty-batch",
                title: "The batch contains no allocations.",
                remediation: "Provide at least one allocation per batch creation call.",
            },
            AidError::NotMilestoneBased => Self {
                code: AidProblemCode::PackageInactive,
                status: 409,
                type_uri: "aid/not-milestone-based",
                title: "This aid program is not milestone-based.",
                remediation: "This operation requires a milestone program. \
                    Ensure you created the aid with milestones, not as a single payout.",
            },
            AidError::InvalidMilestoneIndex => Self {
                code: AidProblemCode::PackageInactive,
                status: 400,
                type_uri: "aid/invalid-milestone-index",
                title: "The milestone index is out of range.",
                remediation: "Verify the milestone index is between 0 and \
                    the total number of milestones - 1.",
            },
            AidError::MilestoneNotVerified => Self {
                code: AidProblemCode::PackageInactive,
                status: 409,
                type_uri: "aid/milestone-not-verified",
                title: "The milestone has not been verified by an authorized inspector.",
                remediation: "Wait for the milestone to be verified by the contract admin \
                    or an authorized inspector before attempting to claim.",
            },
            AidError::MilestoneAlreadyClaimed => Self {
                code: AidProblemCode::AlreadyClaimed,
                status: 409,
                type_uri: "aid/milestone-already-claimed",
                title: "This milestone tranche has already been claimed.",
                remediation: "No further action is needed for this milestone. \
                    Proceed to the next unclaimed milestone if available.",
            },
            AidError::InvariantViolation => Self {
                code: AidProblemCode::InternalInvariant,
                status: 500,
                type_uri: "aid/invariant-violation",
                title: "An internal invariant was violated; this is a bug.",
                remediation: "Report this error to the maintainers with full transaction context. \
                    Do not retry; the contract state may be corrupted. \
                    A fix will be deployed as a priority.",
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_problem_codes_unique() {
        let codes = [
            AidProblemCode::NotInitialized,
            AidProblemCode::AlreadyInitialized,
            AidProblemCode::Unauthorized,
            AidProblemCode::PackageNotFound,
            AidProblemCode::PackageInactive,
            AidProblemCode::AlreadyClaimed,
            AidProblemCode::NotEligible,
            AidProblemCode::InsufficientFunds,
            AidProblemCode::InvalidAmount,
            AidProblemCode::ClaimExpired,
            AidProblemCode::InvalidReferral,
            AidProblemCode::InvalidProposalState,
            AidProblemCode::OraclePriceUnavailable,
            AidProblemCode::ListingUnavailable,
            AidProblemCode::InternalInvariant,
        ];

        let mut seen = std::collections::HashSet::new();
        for code in &codes {
            let value = *code as u32;
            assert!(
                seen.insert(value),
                "Duplicate problem code value: {}",
                value
            );
        }
    }

    #[test]
    fn test_error_mapping_completeness() {
        // Every AidError variant must map to a problem code
        let _ = AidProblemDetails::from_error(AidError::Unauthorized);
        let _ = AidProblemDetails::from_error(AidError::NotFound);
        let _ = AidProblemDetails::from_error(AidError::AlreadyClaimed);
        let _ = AidProblemDetails::from_error(AidError::Expired);
        let _ = AidProblemDetails::from_error(AidError::Paused);
        let _ = AidProblemDetails::from_error(AidError::NotExpiredYet);
        let _ = AidProblemDetails::from_error(AidError::AlreadyRefunded);
        let _ = AidProblemDetails::from_error(AidError::CannotDeletePending);
        let _ = AidProblemDetails::from_error(AidError::InvalidCorrelationId);
        let _ = AidProblemDetails::from_error(AidError::UnsupportedSchemaVersion);
        let _ = AidProblemDetails::from_error(AidError::SchemaMigrationFailed);
        let _ = AidProblemDetails::from_error(AidError::InvalidArgument);
        let _ = AidProblemDetails::from_error(AidError::BatchTooLarge);
        let _ = AidProblemDetails::from_error(AidError::EmptyBatch);
        let _ = AidProblemDetails::from_error(AidError::NotMilestoneBased);
        let _ = AidProblemDetails::from_error(AidError::InvalidMilestoneIndex);
        let _ = AidProblemDetails::from_error(AidError::MilestoneNotVerified);
        let _ = AidProblemDetails::from_error(AidError::MilestoneAlreadyClaimed);
        let _ = AidProblemDetails::from_error(AidError::InvariantViolation);
    }

    #[test]
    fn test_problem_details_remediation_not_empty() {
        let errors = vec![
            AidError::Unauthorized,
            AidError::NotFound,
            AidError::AlreadyClaimed,
            AidError::Expired,
            AidError::Paused,
            AidError::NotExpiredYet,
            AidError::AlreadyRefunded,
            AidError::CannotDeletePending,
            AidError::InvalidCorrelationId,
            AidError::UnsupportedSchemaVersion,
            AidError::SchemaMigrationFailed,
            AidError::InvalidArgument,
            AidError::BatchTooLarge,
            AidError::EmptyBatch,
            AidError::NotMilestoneBased,
            AidError::InvalidMilestoneIndex,
            AidError::MilestoneNotVerified,
            AidError::MilestoneAlreadyClaimed,
            AidError::InvariantViolation,
        ];

        for error in errors {
            let details = AidProblemDetails::from_error(error);
            assert!(
                !details.remediation.is_empty(),
                "Missing remediation hint for {:?}",
                error
            );
            assert!(
                !details.title.is_empty(),
                "Missing title for {:?}",
                error
            );
            assert!(
                !details.type_uri.is_empty(),
                "Missing type_uri for {:?}",
                error
            );
        }
    }

    #[test]
    fn test_problem_code_values_stable() {
        // These values are part of the public API and must never change
        assert_eq!(AidProblemCode::NotInitialized as u32, 100);
        assert_eq!(AidProblemCode::AlreadyInitialized as u32, 101);
        assert_eq!(AidProblemCode::Unauthorized as u32, 102);
        assert_eq!(AidProblemCode::PackageNotFound as u32, 103);
        assert_eq!(AidProblemCode::PackageInactive as u32, 104);
        assert_eq!(AidProblemCode::AlreadyClaimed as u32, 105);
        assert_eq!(AidProblemCode::NotEligible as u32, 106);
        assert_eq!(AidProblemCode::InsufficientFunds as u32, 107);
        assert_eq!(AidProblemCode::InvalidAmount as u32, 108);
        assert_eq!(AidProblemCode::ClaimExpired as u32, 109);
        assert_eq!(AidProblemCode::InvalidReferral as u32, 110);
        assert_eq!(AidProblemCode::InvalidProposalState as u32, 111);
        assert_eq!(AidProblemCode::OraclePriceUnavailable as u32, 112);
        assert_eq!(AidProblemCode::ListingUnavailable as u32, 113);
        assert_eq!(AidProblemCode::InternalInvariant as u32, 199);
    }
}

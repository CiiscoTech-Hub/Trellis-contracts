#![no_std]
pub mod abuse;
pub mod accessibility;
pub mod allowlist;
pub mod analytics;
pub mod admin_config_audit;
pub mod audit_ledger;
pub mod auth;
pub mod backfill;
pub mod batch;
pub mod batch_retry;
pub mod bounded_batch;
pub mod bounded_cache;
pub mod canonical;
pub mod chaos;
pub mod client;
pub mod client_validation;
pub mod compat;
pub mod conflict_resolver;
pub use conflict_resolver::{resolve_conflict_pair, ConflictCandidate, ConflictResolutionResult, ConflictWinner};
pub mod config;
pub mod config_audit;
pub mod config_version;
pub mod domain_events;
pub mod dry_run_policy;
pub mod dashboard;
pub mod degradation;
pub mod degraded_mode;
pub mod deployment_rollback_verification;
pub mod deterministic_sort;
pub mod diagnostics;
pub mod disclosure;
pub mod duplicate_suppression;
pub mod error_taxonomy;
pub mod errors;
pub mod event_dead_letter;
pub mod event_schema_drift;
pub mod events;
pub mod evidence;
pub mod external_evidence;
pub mod failure_registry;
pub mod export;
pub mod failure_fixtures;
pub mod feature_flags;
pub mod fuzz_boundary_inputs;
pub mod health;
pub mod health_guard;
pub mod history;
pub mod idempotency;
pub mod impersonation;
pub mod import;
pub mod init_rollback;
pub mod input_limits;
pub mod invariants;
pub mod jobs;
pub mod lifecycle;
pub mod lifecycle_events;
pub mod maintainer_approval;
pub mod math;
pub mod migration;
pub mod notification_dedup;
pub mod operational_metadata;
pub mod operator_runbook;
pub mod ownership_history;
pub mod ownership_transfer_manager;
pub mod pagination;
pub mod payments;
pub mod policy;
pub mod policy_preview;
pub mod permission_diff_preview;
pub mod preflight;
pub mod problem_details;
pub mod problem_details_taxonomy;
pub mod public_status;
pub mod projection_repair;
pub mod protocol_changelog;
pub mod quota;
pub mod regional_velocity;
pub mod reconciliation;
pub mod recovery;
pub mod rare_failure_fixtures;
pub mod release_artifacts;
pub mod release_readiness;
pub mod replay;
pub mod reentrancy_guard;
pub mod resumable_repair;
pub mod risk_scoring;
pub mod rollout_guard;
pub mod retention;
pub mod sanitize;
pub mod scan_guard;
pub mod schema_evolution;
pub mod semantic;
pub mod sensitive_boundary;
pub mod session_invalidation;
pub mod session_revocation;
pub mod signed_audit_receipt;
pub mod dry_run_repair;
pub mod synthetic_monitoring;
pub mod side_effect_checkpoint;
pub mod snapshot;
pub mod snapshot_restore;
pub mod storage;
pub mod storage_compaction;
pub mod stale_state;
pub mod storage_version;
pub mod telemetry;
pub mod timeline;
pub mod time_window;
pub mod utils;
pub mod versioned_replay;
pub mod webhook;
pub mod workflow_correlation;
pub mod workflow_failure_injection;
pub mod user_facing_degraded_status;
pub mod upgrade_compat_snapshot;
pub mod event_pagination;
pub mod treasury_conservation;
pub mod auth_fingerprint;
pub mod telemetry_protection;
pub mod duplicate_merge_review;
pub mod nft_guard;
pub mod recurring_payments;
pub mod registry_pinning;
pub mod wasm_determinism;
#[cfg(test)]
pub mod test_boundary_properties;
#[cfg(test)]
pub mod test_schema_compat;
// Re-export the most commonly-needed items at crate root for ergonomic use.
pub use abuse::{
    assess_high_impact_abuse, evaluate_high_impact_abuse, get_abuse_policy, get_abuse_state,
    is_abuse_blocked, record_abuse, set_abuse_policy, AbusePolicy, AbuseState,
    HighImpactAbuseContext,
};
pub use allowlist::{
    add_allowed_destination, add_allowed_extension, add_allowed_host,
    default_policy as default_allowlist_policy, get_policy as get_allowlist_policy,
    remove_allowed_destination, remove_allowed_extension, remove_allowed_host,
    restore_policy as restore_allowlist_policy,
    validate_destination as validate_allowlisted_destination,
    validate_url as validate_allowlisted_url, AllowlistError, AllowlistPolicy,
    MAX_ALLOWLIST_ENTRIES, MAX_EXTENSION_LEN, MAX_HOST_LEN,
};
pub use reentrancy_guard::{
    enter_guarded_call, exit_guarded_call, get_call_telemetry, reset_call_telemetry,
    CallDepthTelemetry, GuardError, GuardToken, MAX_CALL_DEPTH, TOPIC_REENTRANCY_GUARD,
};
pub use risk_scoring::{
    assess_and_record, evaluate_risk, get_actor_profile, get_risk_policy, reset_actor_risk,
    set_actor_exemption, set_risk_policy, ActionContext, ActorRiskProfile, HighImpactAction,
    RiskAssessment, RiskError, RiskFactor, RiskFactorType, RiskPolicy, RiskTier, RiskVerdict,
};
pub use audit_ledger::{
append_event, append_financial, append_privileged, checkpoint, entry_hash, export_digest,
export_ledger, genesis_hash, get_entry, head, length, publish_head_checkpoint,
record_admin_change, verify_admin_receipt, verify_chain, verify_export,
AdminChangeReceipt, AdminReceiptStatus,
AuditEventClass, AuditEventKind, AuditEventParams, AuditLedgerEntry, AuditLedgerExport,
AuditLedgerHead, AuditLedgerKey, AuditVerificationFailure, AuditVerificationReport,
AUDIT_DOMAIN, AUDIT_LEDGER_SCHEMA_VERSION, DEFAULT_EXPORT_LIMIT, MAX_EXPORT_LIMIT,
MAX_VERIFY_ENTRIES,
};
pub use analytics::{
aggregate_events, is_fully_suppressed, is_safe_dimension, is_sensitive_dimension,
AggregateBucket, AnalyticsReport, PrivacyConfig, RawObservation, ANALYTICS_METRIC_VERSION,
};
pub use auth::{
accept_ownership_transfer, cancel_ownership_transfer, expire_ownership_transfer, get_admin,
get_pending_ownership_transfer, has_permission, initialize_admin, is_ownership_transfer_expired,
ownership_transfer_time_remaining, propose_ownership_transfer, reject_ownership_transfer,
require_admin, require_not_paused, require_permission, role_for_permission, set_admin,
PendingOwnershipTransfer, Permission, Role,
};
pub use config_audit::{
    apply_sensitive_config_change, get_config_audit_evidence, get_sensitive_config_value,
    rollback_config_change, verify_config_audit_chain, ConfigAuditEvidence, ConfigAuditError,
};
pub use session_revocation::{
    derive_token_id, get_session_token, get_subject_security_state, issue_session_token,
    revoke_session_token, trigger_security_revocation, validate_session_token, SecurityEventKind,
    SessionToken, SubjectSecurityState, TokenStatus,
};
pub use side_effect_checkpoint::{
    begin_side_effect, commit_side_effect, derive_effect_id, fail_side_effect,
    get_side_effect_checkpoint, rollback_side_effect, BeginEffectOutcome, SideEffectCheckpoint,
    SideEffectKind, SideEffectState, DEFAULT_MAX_EFFECT_RETRIES,
};
pub use backfill::{
advance_checkpoint, begin_backfill, clear_checkpoint, complete_backfill, dedupe_items,
dry_run as dry_run_backfill, fail_backfill, is_resumable as is_backfill_resumable,
load_checkpoint as load_backfill_checkpoint, resume_backfill,
save_checkpoint as save_backfill_checkpoint,
BackfillAction, BackfillCheckpoint, BackfillDuplicatePolicy, BackfillError,
BackfillItem, BackfillMode, BackfillModule, BackfillPlan, BackfillReport, BackfillStatus,
};
pub use batch::{
batch_invoke_no_args, execute_multi_invoke, execute_multi_transfer, multi_transfer_all,
BatchConfig, BatchError, BatchMode, BatchResult, BatchTransfer, OperationResult,
ABSOLUTE_MAX_BATCH_SIZE, DEFAULT_MAX_BATCH_SIZE,
};
pub use batch_retry::{
    discard_batch_failure_report, get_batch_failure_report, record_batch_failures,
    retry_batch_failures, BatchFailureDetail, BatchFailureReport, BATCH_RETRY_TOPIC,
};
pub use canonical::{
canonical_bytes, canonical_fingerprint, canonicalize_legacy, ensure_supported_encoding,
is_legacy_encoding, normalize_int, normalize_text, parse_legacy_kv, CanonicalPart,
CANONICAL_ENCODING_VERSION, LEGACY_ENCODING_VERSION, MAX_FIELD_LEN,
canonical_bytes_strict, normalize_text_strict, verify_canonical_fingerprint,
MAX_CANONICAL_PARTS,
};
pub use client::{
client_schema_fingerprint, format_client_error, AidSummaryResponse, ClientErrorResponse,
ClientReceipt, CreateAidRequest, CreateEscrowRequest, CreateListingRequest,
CreateProposalRequest, EscrowSummaryResponse, ListingSummaryResponse, OperationStatus,
ProposalSummaryResponse, RebalanceRequest, RebalanceSummaryResponse, CLIENT_SCHEMA_VERSION,
};
pub use client_validation::{
    begin_idempotent_request, complete_idempotent_request, ensure_supported_client_schema_version,
    fingerprint_request, validate_create_aid_request, validate_create_escrow_request,
    validate_create_listing_request, validate_create_proposal_request, validate_rebalance_request,
    MAX_SLIPPAGE_BPS, MAX_SUPPORTED_CLIENT_SCHEMA_VERSION, MIN_SUPPORTED_CLIENT_SCHEMA_VERSION,
};
pub use compat::{
current_schema_version, downgrade_v2_to_v1, ensure_supported_version, from_latest,
is_deprecated_version, is_supported_version, migrate_v1_to_v2, new_current_record, to_latest,
CompatAidStatus, CurrentAidRecord, LegacyAidRecord, VersionedAidRecord,
CURRENT_RECORD_SCHEMA_VERSION, MAX_SUPPORTED_RECORD_SCHEMA_VERSION,
MIN_SUPPORTED_RECORD_SCHEMA_VERSION, RECORD_SCHEMA_V1, RECORD_SCHEMA_V2,
};
pub use config::{
validate_feature_flag, validate_full_config, validate_network_id, validate_rpc_url,
validate_secret_key, Environment, RedactedSecret,
};
pub use domain_events::{consumer_version, publish_event, validate_event, DomainEvent, EventSchema,
EventValidationError};
pub use dashboard::{
add_external_reference, create_partial_failure, generate_dashboard,
generate_enhanced_dashboard, group_by_age, group_by_operation_type, group_by_retryability,
group_by_severity, redact_partial_failure, DashboardReport, ExternalReference, FailureGroup,
FailureSeverity, FailureState, HealthCategory, OperationType, PartialFailure,
RedactedDeadLetter, RedactedPartialFailure,
};
pub use disclosure::{DetailField, DetailSeverity, TransactionDetail, TransactionDetailBuilder};
pub use error_taxonomy::{describe_error, ErrorCategory, ErrorDomain, ErrorInfo};
pub use errors::Error;
pub use export::{
authorize_export, authorize_module_export, cancel_export_stream, create_export,
ensure_supported_version as ensure_supported_export_version, finalize_export_stream,
generate_export, get_export_session, init_export_stream, is_forbidden_field, is_safe_field,
is_supported_version as is_supported_export_version, purge_forbidden_fields, redact_fields,
register_export_artifact, scope_allows_record, stream_export_chunk, assert_records_visible,
ExportArtifact, ExportCancellationReport, ExportError, ExportField, ExportFormat,
ExportMetadata, ExportModule, ExportRecord, ExportReport, ExportRequest, ExportScope,
ExportSession, ExportStreamStatus, RecordSensitivity, StreamChunkResult,
ABSOLUTE_MAX_EXPORT_RECORDS, CURRENT_EXPORT_SCHEMA_VERSION, DEFAULT_EXPORT_CHUNK_SIZE,
DEFAULT_EXPORT_TTL_LEDGERS, DEFAULT_MAX_EXPORT_RECORDS, EXPORT_SCHEMA_V1,
MAX_EXPORT_CHUNK_SIZE, MAX_EXPORT_TTL_LEDGERS, MAX_SUPPORTED_EXPORT_SCHEMA_VERSION,
MIN_SUPPORTED_EXPORT_SCHEMA_VERSION,
};
pub use events::{
emit, emit_collection_registered, emit_import_committed, emit_import_failed,
emit_import_simulated, emit_nft_auction, emit_nft_bid, emit_nft_listed, emit_nft_offer,
emit_nft_settle, emit_nft_sold, emit_royalty_paid, AID_CLAIMED, AID_CREATED, AID_REFUNDED,
AID_SETTLED, COMMISSION_PAID, CONTRACT_PAUSED, CONTRACT_RESUMED, CONTRACT_UPGRADED,
IMPORT_COMMITTED, IMPORT_FAILED, IMPORT_SIMULATED, PARAMETER_CHANGED, PAYMENT_ESCROW_CREATED,
PAYMENT_ESCROW_REFUNDED, PAYMENT_ESCROW_RELEASED, PAYMENT_FEE, PAYMENT_TRANSFER,
REFERRAL_ACCRUED, REFERRAL_REGISTERED, REFERRER_SET, TIER_CONFIG_SET, TREASURY_DEPOSIT,
TREASURY_EMERGENCY_WITHDRAW, TREASURY_SET, TREASURY_WITHDRAW,
};
pub use event_dead_letter::{
    dead_letter_ids as event_dead_letter_ids, discard_dead_letter as discard_event_dead_letter,
    dispatch_event, get_dead_letter as get_event_dead_letter, pending_dead_letter_ids,
    requeue_dead_letter as requeue_event_dead_letter, retry_dead_letter, DispatchOutcome,
    DomainEventHandler, EventDeadLetter, EventDispatchStatus, EVENT_DLQ_DEAD_LETTERED,
    EVENT_DLQ_REQUEUED, EVENT_DLQ_RESOLVED, EVENT_DLQ_RETRIED, EVENT_DLQ_TOPIC,
};
pub use evidence::*;
pub use chaos::*;
pub use health::{
get_dependency_health, list_dependency_health, set_dependency_health, DependencyHealth,
DependencyStatus,
};
pub use health_guard::{
    breaker_state, check_and_record_attempt, execute_guarded, get_retry_budget,
    is_registered_reporter, register_reporter, report_health_check, reset_breaker,
    revoke_reporter,
};
pub use nft_guard::{
    evaluate_wash_trade, record_clean_trade, verify_floor_price, FloorPriceGuardConfig,
    FloorPriceState, MarketGuardError, TokenOwnershipHistory, WashTradeConfig, WashTradeVerdict,
};
pub use recurring_payments::{
    create_recurring_authorization, execute_recurring_pull, get_remaining_budgets,
    pause_recurring_authorization, resume_recurring_authorization, revoke_recurring_authorization,
    update_spend_ceiling, RecurringPaymentError, RecurringPullAuth, RecurringPullExecutionResult,
    RecurringPullStatus,
};
pub use registry_pinning::{
    create_deprecation_notice, create_version_pin, resolve_target_version, validate_pin_target,
    DeprecationNotice, RegistryPinningError, VersionPin,
};
pub use wasm_determinism::{
    evaluate_budget_regression, verify_wasm_determinism, BudgetRegressionVerdict,
    DeterminismGateError, DeterminismReport, ResourceBudget, WasmArtifactFingerprint,
};

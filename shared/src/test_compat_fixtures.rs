//! Automated executable verification for compatibility fixtures and versioned migrations (Issue #435).

#![cfg(test)]

use crate::auth::{grant_role, set_admin, Role};
use crate::compat::{
    current_schema_version, downgrade_v2_to_v1, ensure_supported_version, is_deprecated_version,
    is_supported_version, migrate_v1_to_v2, to_latest, CompatAidStatus, CurrentAidRecord,
    LegacyAidRecord, VersionedAidRecord, CURRENT_RECORD_SCHEMA_VERSION, RECORD_SCHEMA_V1,
    RECORD_SCHEMA_V2,
};
use crate::errors::Error;
use soroban_sdk::{
    contract, contractimpl, testutils::Address as _, Address, Env,
};

#[contract]
struct CompatFixtureTestContract;

#[contractimpl]
impl CompatFixtureTestContract {}

fn setup() -> (Env, Address, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, CompatFixtureTestContract);
    let donor = Address::generate(&env);
    let recipient = Address::generate(&env);
    let token = Address::generate(&env);
    (env, contract_id, donor, recipient, token)
}

#[test]
fn test_normal_migration_path_v1_to_v2() {
    let (env, contract_id, donor, recipient, token) = setup();

    env.as_contract(&contract_id, || {
        // V1 legacy record fixture representation
        let v1 = LegacyAidRecord {
            id: 1001,
            donor: donor.clone(),
            recipient: recipient.clone(),
            amount: 5000000000,
            expiry_ledger: 125000,
            status: CompatAidStatus::Pending,
        };

        assert!(is_deprecated_version(RECORD_SCHEMA_V1));
        assert!(is_supported_version(RECORD_SCHEMA_V1));
        assert_eq!(current_schema_version(), RECORD_SCHEMA_V2);

        // Lossless forward migration
        let v2 = migrate_v1_to_v2(&v1, &token).expect("V1 to V2 migration must succeed");

        assert_eq!(v2.id, 1001);
        assert_eq!(v2.donor, donor);
        assert_eq!(v2.recipient, recipient);
        assert_eq!(v2.token, token);
        assert_eq!(v2.amount, 5000000000);
        assert_eq!(v2.expiry_ledger, 125000);
        assert_eq!(v2.status, CompatAidStatus::Pending);
        assert_eq!(v2.schema_version, CURRENT_RECORD_SCHEMA_VERSION);

        // Verify envelope reader converts V1 to latest canonical shape
        let envelope_v1 = VersionedAidRecord::V1(v1.clone());
        let latest = to_latest(&env, &envelope_v1).expect("to_latest must convert V1");
        assert_eq!(latest.id, 1001);
        assert_eq!(latest.amount, 5000000000);
        assert_eq!(latest.status, CompatAidStatus::Pending);
        assert_eq!(latest.schema_version, CURRENT_RECORD_SCHEMA_VERSION);
    });
}

#[test]
fn test_failure_paths_on_invalid_or_unsupported_fixtures() {
    let (env, contract_id, donor, recipient, token) = setup();

    env.as_contract(&contract_id, || {
        // Malformed fixture: negative amount must fail migration
        let bad_amount_v1 = LegacyAidRecord {
            id: 9001,
            donor: donor.clone(),
            recipient: recipient.clone(),
            amount: -1000,
            expiry_ledger: 125000,
            status: CompatAidStatus::Pending,
        };
        let err_amount = migrate_v1_to_v2(&bad_amount_v1, &token);
        assert_eq!(err_amount, Err(Error::SchemaMigrationFailed));

        // Unsupported schema versions must reject fail-fast
        assert_eq!(ensure_supported_version(0), Err(Error::UnsupportedSchemaVersion));
        assert_eq!(ensure_supported_version(99), Err(Error::UnsupportedSchemaVersion));

        // Envelope with unsupported version rejected
        let invalid_v2 = CurrentAidRecord {
            id: 9002,
            donor: donor.clone(),
            recipient: recipient.clone(),
            token: token.clone(),
            amount: 1000,
            expiry_ledger: 125000,
            status: CompatAidStatus::Pending,
            schema_version: 99,
        };
        let env_invalid = VersionedAidRecord::V2(invalid_v2);
        let err_unsupported = to_latest(&env, &env_invalid);
        assert_eq!(err_unsupported, Err(Error::UnsupportedSchemaVersion));
    });
}

#[test]
fn test_retry_idempotency_and_roundtrip_downgrade() {
    let (env, contract_id, donor, recipient, token) = setup();

    env.as_contract(&contract_id, || {
        let v2_original = CurrentAidRecord {
            id: 1002,
            donor: donor.clone(),
            recipient: recipient.clone(),
            token: token.clone(),
            amount: 2500000000,
            expiry_ledger: 130000,
            status: CompatAidStatus::Settled,
            schema_version: CURRENT_RECORD_SCHEMA_VERSION,
        };

        // Idempotency: to_latest on an already-migrated V2 record returns V2 unchanged
        let envelope_v2 = VersionedAidRecord::V2(v2_original.clone());
        let latest = to_latest(&env, &envelope_v2).expect("to_latest on V2 must succeed");
        assert_eq!(latest, v2_original);

        // Outbound downgrade for legacy client API
        let downgraded_v1 = downgrade_v2_to_v1(&v2_original).expect("downgrade must succeed");
        assert_eq!(downgraded_v1.id, 1002);
        assert_eq!(downgraded_v1.amount, 2500000000);
        assert_eq!(downgraded_v1.status, CompatAidStatus::Settled);

        // Re-migrating downgraded record recovers identical V2
        let re_migrated = migrate_v1_to_v2(&downgraded_v1, &token).expect("re-migration succeeds");
        assert_eq!(re_migrated, v2_original);
    });
}

#[test]
fn test_authorization_path_for_storage_migration() {
    let (env, contract_id, _, _, _) = setup();
    let admin = Address::generate(&env);
    let unauthorized = Address::generate(&env);

    env.as_contract(&contract_id, || {
        set_admin(&env, &admin);
        grant_role(&env, &admin, &admin, Role::Admin).unwrap();
    });

    // Non-admin attempting privileged administrative migration fails
    let non_admin_check = env.as_contract(&contract_id, || {
        crate::auth::require_admin(&env, &unauthorized)
    });
    assert_eq!(non_admin_check, Err(Error::Unauthorized));

    // Authorized admin passes
    let admin_check = env.as_contract(&contract_id, || {
        crate::auth::require_admin(&env, &admin)
    });
    assert!(admin_check.is_ok());
}

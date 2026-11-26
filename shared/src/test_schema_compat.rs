//! Schema compatibility tests for versioned records (Issue #425).
#[cfg(test)]
mod tests {
    use soroban_sdk::{symbol_short, testutils::Address as _, Address, Env, IntoVal, Map, Symbol, Val};

    use crate::compat::{
        downgrade_v2_to_v1, ensure_supported_version, from_latest, migrate_v1_to_v2,
        new_current_record, to_latest, CompatAidStatus, CurrentAidRecord, LegacyAidRecord,
        VersionedAidRecord, CURRENT_RECORD_SCHEMA_VERSION, RECORD_SCHEMA_V1, RECORD_SCHEMA_V2,
    };
    use crate::errors::Error;
    use crate::schema_evolution::{
        build_aid_record_schema, ensure_version_compatible, validate_fields,
        SchemaEvolutionError, StoredRecordEnvelope,
    };

    fn v1(env: &Env) -> LegacyAidRecord {
        LegacyAidRecord {
            id: 1,
            donor: Address::generate(env),
            recipient: Address::generate(env),
            amount: 1_000,
            expiry_ledger: 5_000,
            status: CompatAidStatus::Pending,
        }
    }

    fn v2(env: &Env) -> CurrentAidRecord {
        CurrentAidRecord {
            id: 2,
            donor: Address::generate(env),
            recipient: Address::generate(env),
            token: Address::generate(env),
            amount: 2_000,
            expiry_ledger: 9_000,
            status: CompatAidStatus::Pending,
            schema_version: CURRENT_RECORD_SCHEMA_VERSION,
        }
    }

    fn valid_payload(env: &Env) -> Map<Symbol, Val> {
        let mut m = Map::new(env);
        m.set(symbol_short!("id"),      1_u64.into_val(env));
        m.set(symbol_short!("donor"),   100_u32.into_val(env));
        m.set(symbol_short!("recip"),   200_u32.into_val(env));
        m.set(symbol_short!("amount"),  1_000_i128.into_val(env));
        m.set(symbol_short!("expiry"),  5_000_u32.into_val(env));
        m.set(symbol_short!("status"),  0_u32.into_val(env));
        m.set(symbol_short!("token"),   300_u32.into_val(env));
        m.set(symbol_short!("sch_ver"), 2_u32.into_val(env));
        m
    }

    // --- version guards ---

    #[test]
    fn supported_versions_pass_guard() {
        assert!(ensure_supported_version(RECORD_SCHEMA_V1).is_ok());
        assert!(ensure_supported_version(RECORD_SCHEMA_V2).is_ok());
        assert_eq!(ensure_supported_version(0),  Err(Error::UnsupportedSchemaVersion));
        assert_eq!(ensure_supported_version(99), Err(Error::UnsupportedSchemaVersion));
    }

    // --- forward migration V1 → V2 ---

    #[test]
    fn forward_migration_preserves_all_fields() {
        let env = Env::default();
        let v1 = v1(&env);
        let token = Address::generate(&env);
        let v2 = migrate_v1_to_v2(&v1, &token).unwrap();
        assert_eq!(v2.id, v1.id);
        assert_eq!(v2.amount, v1.amount);
        assert_eq!(v2.token, token);
        assert_eq!(v2.schema_version, CURRENT_RECORD_SCHEMA_VERSION);
    }

    #[test]
    fn forward_migration_fails_on_zero_or_negative_amount() {
        let env = Env::default();
        let token = Address::generate(&env);
        let mut r = v1(&env); r.amount = 0;
        assert_eq!(migrate_v1_to_v2(&r, &token), Err(Error::SchemaMigrationFailed));
        r.amount = -1;
        assert_eq!(migrate_v1_to_v2(&r, &token), Err(Error::SchemaMigrationFailed));
    }

    // --- downgrade V2 → V1 ---

    #[test]
    fn downgrade_drops_token_binding() {
        let env = Env::default();
        let v2 = v2(&env);
        let v1 = downgrade_v2_to_v1(&v2).unwrap();
        assert_eq!(v1.id, v2.id);
        assert_eq!(v1.amount, v2.amount);
    }

    #[test]
    fn downgrade_rejects_unsupported_schema_version() {
        let env = Env::default();
        let mut r = v2(&env); r.schema_version = 99;
        assert_eq!(downgrade_v2_to_v1(&r), Err(Error::UnsupportedSchemaVersion));
    }

    // --- round-trip ---

    #[test]
    fn round_trip_v1_migrates_and_downgrades_losslessly() {
        let env = Env::default();
        let orig = v1(&env);
        let token = Address::generate(&env);
        let restored = downgrade_v2_to_v1(&migrate_v1_to_v2(&orig, &token).unwrap()).unwrap();
        assert_eq!(restored, orig);
    }

    // --- envelope helpers ---

    #[test]
    fn from_latest_wraps_as_v2_envelope() {
        let env = Env::default();
        let r = v2(&env);
        let env = from_latest(&r).unwrap();
        assert!(matches!(env, VersionedAidRecord::V2(_)));
    }

    #[test]
    fn to_latest_on_v1_envelope_produces_v2_shape() {
        let env = Env::default();
        let r = v1(&env);
        let result = to_latest(&env, &VersionedAidRecord::V1(r.clone())).unwrap();
        assert_eq!(result.id, r.id);
        assert_eq!(result.schema_version, CURRENT_RECORD_SCHEMA_VERSION);
    }

    #[test]
    fn re_migrating_v2_via_to_latest_is_idempotent() {
        let env = Env::default();
        let r = v2(&env);
        let env2 = VersionedAidRecord::V2(r.clone());
        assert_eq!(to_latest(&env, &env2).unwrap(), to_latest(&env, &env2).unwrap());
    }

    // --- schema_evolution field validation ---

    #[test]
    fn valid_payload_passes_field_validation() {
        let env = Env::default();
        let schema = build_aid_record_schema(&env, 2);
        assert!(validate_fields(&schema, &valid_payload(&env), true).is_ok());
    }

    #[test]
    fn missing_required_field_fails_validation() {
        let env = Env::default();
        let schema = build_aid_record_schema(&env, 2);
        let mut p = valid_payload(&env);
        p.remove(symbol_short!("amount"));
        assert_eq!(validate_fields(&schema, &p, true), Err(SchemaEvolutionError::MissingRequiredField));
    }

    #[test]
    fn unknown_field_rejected_under_strict_policy() {
        let env = Env::default();
        let schema = build_aid_record_schema(&env, 2);
        let mut p = valid_payload(&env);
        p.set(symbol_short!("extra_f"), 1_u32.into_val(&env));
        assert_eq!(validate_fields(&schema, &p, true), Err(SchemaEvolutionError::UnknownField));
    }

    #[test]
    fn deprecated_field_allowed_on_read_rejected_on_write() {
        let env = Env::default();
        let schema = build_aid_record_schema(&env, 2);
        let mut p = valid_payload(&env);
        p.set(symbol_short!("raw_memo"), 1_u32.into_val(&env));
        assert!(validate_fields(&schema, &p, false).is_ok());
        assert_eq!(validate_fields(&schema, &p, true), Err(SchemaEvolutionError::DeprecatedField));
    }

    #[test]
    fn tombstoned_field_rejected_on_all_paths() {
        let env = Env::default();
        let schema = build_aid_record_schema(&env, 3);
        let mut p = valid_payload(&env);
        p.set(symbol_short!("raw_memo"), 1_u32.into_val(&env));
        assert_eq!(validate_fields(&schema, &p, false), Err(SchemaEvolutionError::TombstonedField));
        assert_eq!(validate_fields(&schema, &p, true),  Err(SchemaEvolutionError::TombstonedField));
    }

    // --- version compatibility across modules ---

    #[test]
    fn aid_schema_accepts_v1_and_v2_rejects_out_of_range() {
        let env = Env::default();
        let schema = build_aid_record_schema(&env, 2);
        assert!(ensure_version_compatible(&schema, 1).is_ok());
        assert!(ensure_version_compatible(&schema, 2).is_ok());
        assert_eq!(ensure_version_compatible(&schema, 0),  Err(SchemaEvolutionError::MigrationRequired));
        assert_eq!(ensure_version_compatible(&schema, 99), Err(SchemaEvolutionError::UnsupportedVersion));
    }

    // --- stored record envelope ---

    #[test]
    fn stored_envelope_read_guard_accepts_matching_schema() {
        let env = Env::default();
        let schema = build_aid_record_schema(&env, 2);
        let env2: StoredRecordEnvelope<u32> = StoredRecordEnvelope::new(2, symbol_short!("aid_rec"), 42);
        assert!(env2.validate_read(&schema).is_ok());
    }

    #[test]
    fn stored_envelope_rejects_wrong_schema_id() {
        let env = Env::default();
        let schema = build_aid_record_schema(&env, 2);
        let env2: StoredRecordEnvelope<u32> = StoredRecordEnvelope::new(2, symbol_short!("other"), 0);
        assert_eq!(env2.validate_read(&schema), Err(SchemaEvolutionError::UnsupportedVersion));
    }

    // --- rollback: downgrade restores original shape ---

    #[test]
    fn rollback_scenario_restores_v1_shape_after_migration() {
        let env = Env::default();
        let orig = v1(&env);
        let token = Address::generate(&env);
        let migrated = migrate_v1_to_v2(&orig, &token).unwrap();
        let rolled_back = downgrade_v2_to_v1(&migrated).unwrap();
        assert_eq!(rolled_back, orig);
    }
}

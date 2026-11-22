//! Cross-service event schema drift detection (Issue #449).
//!
//! Producers and consumers each hold a [`domain_events::EventSchema`] for an
//! event. [`detect_drift`] compares two of them and classifies the change, so
//! a consumer (or CI) can fail before a producer ships an incompatible event.
//!
//! The admin registers the agreed baseline per event name. Additive changes
//! with a version bump replace the baseline; breaking changes are refused.
//! The previous baseline is kept so [`rollback_baseline`] can restore it.
//! See `docs/EVENT_SCHEMA_DRIFT.md`.

use soroban_sdk::{contracterror, contracttype, Address, Env, Symbol};

use crate::auth;
use crate::domain_events::EventSchema;

const BASELINE_KEY: u32 = 0x4553_4442; // "ESDB"
const PREVIOUS_KEY: u32 = 0x4553_4450; // "ESDP"

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SchemaDriftError {
    Unauthorized = 1,
    BaselineMissing = 2,
    BreakingDrift = 3,
    NoPreviousBaseline = 4,
}

#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DriftKind {
    /// Same name and field set.
    None,
    /// New fields with a version bump; old consumers can ignore them.
    FieldsAdded,
    /// Fields were removed; consumers that read them break.
    FieldsRemoved,
    /// The field set changed without a version bump.
    UnversionedChange,
    /// The observed version is older than the baseline.
    VersionRegressed,
    /// The schemas describe different events.
    NameMismatch,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DriftReport {
    pub kind: DriftKind,
    pub added: u32,
    pub removed: u32,
    pub breaking: bool,
}

fn report(kind: DriftKind, added: u32, removed: u32) -> DriftReport {
    let breaking = !matches!(kind, DriftKind::None | DriftKind::FieldsAdded);
    DriftReport {
        kind,
        added,
        removed,
        breaking,
    }
}

/// Classifies the change from `baseline` to `observed`.
pub fn detect_drift(baseline: &EventSchema, observed: &EventSchema) -> DriftReport {
    if baseline.name != observed.name {
        return report(DriftKind::NameMismatch, 0, 0);
    }
    if observed.version < baseline.version {
        return report(DriftKind::VersionRegressed, 0, 0);
    }
    let added = observed
        .required_fields
        .iter()
        .filter(|f| !baseline.required_fields.contains(f))
        .count() as u32;
    let removed = baseline
        .required_fields
        .iter()
        .filter(|f| !observed.required_fields.contains(f))
        .count() as u32;
    if added == 0 && removed == 0 {
        return report(DriftKind::None, 0, 0);
    }
    if observed.version == baseline.version {
        return report(DriftKind::UnversionedChange, added, removed);
    }
    if removed > 0 {
        return report(DriftKind::FieldsRemoved, added, removed);
    }
    report(DriftKind::FieldsAdded, added, removed)
}

pub fn get_baseline(env: &Env, name: &Symbol) -> Option<EventSchema> {
    env.storage()
        .persistent()
        .get(&(BASELINE_KEY, name.clone()))
}

/// Registers or upgrades the baseline for `schema.name`. Admin only.
///
/// Registering the current baseline again is a no-op, so retries are safe.
pub fn register_baseline(
    env: &Env,
    caller: &Address,
    schema: &EventSchema,
) -> Result<DriftReport, SchemaDriftError> {
    auth::require_admin(env, caller).map_err(|_| SchemaDriftError::Unauthorized)?;
    let key = (BASELINE_KEY, schema.name.clone());
    let drift = match get_baseline(env, &schema.name) {
        None => report(DriftKind::None, 0, 0),
        Some(current) => {
            let drift = detect_drift(&current, schema);
            if drift.breaking {
                return Err(SchemaDriftError::BreakingDrift);
            }
            if drift.kind == DriftKind::None && current.version == schema.version {
                return Ok(drift);
            }
            env.storage()
                .persistent()
                .set(&(PREVIOUS_KEY, schema.name.clone()), &current);
            drift
        }
    };
    env.storage().persistent().set(&key, schema);
    Ok(drift)
}

/// Checks an observed producer or consumer schema against the baseline.
pub fn check_drift(env: &Env, observed: &EventSchema) -> Result<DriftReport, SchemaDriftError> {
    let baseline = get_baseline(env, &observed.name).ok_or(SchemaDriftError::BaselineMissing)?;
    Ok(detect_drift(&baseline, observed))
}

/// Restores the previous baseline after a bad upgrade. Admin only.
pub fn rollback_baseline(
    env: &Env,
    caller: &Address,
    name: &Symbol,
) -> Result<EventSchema, SchemaDriftError> {
    auth::require_admin(env, caller).map_err(|_| SchemaDriftError::Unauthorized)?;
    let previous_key = (PREVIOUS_KEY, name.clone());
    let previous: EventSchema = env
        .storage()
        .persistent()
        .get(&previous_key)
        .ok_or(SchemaDriftError::NoPreviousBaseline)?;
    env.storage()
        .persistent()
        .set(&(BASELINE_KEY, name.clone()), &previous);
    env.storage().persistent().remove(&previous_key);
    Ok(previous)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{contract, contractimpl, symbol_short, Vec};

    #[contract]
    pub struct SchemaDriftFixture;

    #[contractimpl]
    impl SchemaDriftFixture {
        pub fn schema_drift_ping() -> u32 {
            1
        }
    }

    fn schema(env: &Env, version: u32, fields: &[Symbol]) -> EventSchema {
        let mut required_fields = Vec::new(env);
        for f in fields {
            required_fields.push_back(f.clone());
        }
        EventSchema {
            name: symbol_short!("paid"),
            version,
            required_fields,
        }
    }

    fn base(env: &Env) -> EventSchema {
        schema(env, 1, &[symbol_short!("id"), symbol_short!("amount")])
    }

    #[test]
    fn classifies_each_kind_of_drift() {
        let env = Env::default();
        let b = base(&env);

        assert_eq!(detect_drift(&b, &b), report(DriftKind::None, 0, 0));

        let reordered = schema(&env, 1, &[symbol_short!("amount"), symbol_short!("id")]);
        assert_eq!(detect_drift(&b, &reordered).kind, DriftKind::None);

        let added = schema(
            &env,
            2,
            &[symbol_short!("id"), symbol_short!("amount"), symbol_short!("memo")],
        );
        let r = detect_drift(&b, &added);
        assert_eq!(r, report(DriftKind::FieldsAdded, 1, 0));
        assert!(!r.breaking);

        let removed = schema(&env, 2, &[symbol_short!("id")]);
        let r = detect_drift(&b, &removed);
        assert_eq!(r.kind, DriftKind::FieldsRemoved);
        assert!(r.breaking);

        let silent = schema(
            &env,
            1,
            &[symbol_short!("id"), symbol_short!("amount"), symbol_short!("memo")],
        );
        assert_eq!(detect_drift(&b, &silent).kind, DriftKind::UnversionedChange);

        let older = schema(&env, 0, &[symbol_short!("id"), symbol_short!("amount")]);
        assert_eq!(detect_drift(&b, &older).kind, DriftKind::VersionRegressed);

        let mut other = base(&env);
        other.name = symbol_short!("refunded");
        assert_eq!(detect_drift(&b, &other).kind, DriftKind::NameMismatch);
    }

    #[test]
    fn baseline_registry_enforces_compatibility_and_supports_rollback() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SchemaDriftFixture);
        let admin = Address::generate(&env);
        let stranger = Address::generate(&env);
        env.as_contract(&contract_id, || {
            auth::set_admin(&env, &admin);
            let name = symbol_short!("paid");

            assert_eq!(
                check_drift(&env, &base(&env)),
                Err(SchemaDriftError::BaselineMissing)
            );
            assert_eq!(
                register_baseline(&env, &stranger, &base(&env)),
                Err(SchemaDriftError::Unauthorized)
            );
            register_baseline(&env, &admin, &base(&env)).unwrap();
            // Retry is a no-op and leaves no rollback target.
            register_baseline(&env, &admin, &base(&env)).unwrap();
            assert_eq!(
                rollback_baseline(&env, &admin, &name),
                Err(SchemaDriftError::NoPreviousBaseline)
            );

            let breaking = schema(&env, 2, &[symbol_short!("id")]);
            assert_eq!(
                register_baseline(&env, &admin, &breaking),
                Err(SchemaDriftError::BreakingDrift)
            );
            assert_eq!(get_baseline(&env, &name), Some(base(&env)));

            let v2 = schema(
                &env,
                2,
                &[symbol_short!("id"), symbol_short!("amount"), symbol_short!("memo")],
            );
            assert_eq!(
                register_baseline(&env, &admin, &v2).unwrap().kind,
                DriftKind::FieldsAdded
            );
            // A consumer still on v1 is now behind the baseline.
            assert_eq!(
                check_drift(&env, &base(&env)).unwrap().kind,
                DriftKind::VersionRegressed
            );

            assert_eq!(
                rollback_baseline(&env, &stranger, &name),
                Err(SchemaDriftError::Unauthorized)
            );
            assert_eq!(rollback_baseline(&env, &admin, &name), Ok(base(&env)));
            assert_eq!(get_baseline(&env, &name), Some(base(&env)));
            assert_eq!(
                check_drift(&env, &base(&env)).unwrap(),
                report(DriftKind::None, 0, 0)
            );
        });
    }
}

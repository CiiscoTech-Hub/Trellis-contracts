//! # Registry Contract Version Pinning and Deprecation Notice
//!
//! Production-grade contract version management primitives for the Trellis Registry.
//!
//! ## Key Capabilities
//! - **Version Pinning**: Locks resolution of a contract name to a specific approved version.
//! - **Unpinning**: Reverts resolution to the dynamic latest registered version.
//! - **Deprecation Notices**: Structured sunset timeline with migration target pointers.
//! - **Sunset Decommissioning Guard**: Enforces end-of-life status once `current_time >= sunset_at`.
//! - **Zero Downtime Migration**: Backward-compatible resolution with fallback to unpinned state.

use soroban_sdk::{contracterror, contracttype, Address, Symbol};

// ── Error taxonomy ─────────────────────────────────────────────────────────────

#[contracterror(export = false)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RegistryPinningError {
    /// Caller is not authorized to modify pinning or deprecation notices.
    Unauthorized = 921,
    /// Requested version does not exist in registry history.
    VersionNotFound = 922,
    /// The requested contract version has reached its sunset timestamp and is decommissioned.
    ContractSunset = 923,
    /// Sunset timestamp must be strictly in the future compared to deprecation announcement.
    InvalidSunsetTimestamp = 924,
    /// No deprecation notice exists for the specified contract and version.
    NoticeNotFound = 925,
    /// No pinned version is set for the specified contract name.
    PinNotFound = 926,
    /// Contract is not registered in the registry.
    ContractNotRegistered = 927,
    /// Version number must be strictly positive.
    InvalidVersion = 928,
}

// ── Data structures ────────────────────────────────────────────────────────────

/// Pin record locking a contract name to a specific version.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionPin {
    pub name: Symbol,
    pub pinned_version: u32,
    pub pinned_by: Address,
    pub pinned_at: u64,
}

/// Deprecation notice declaring the sunset schedule and migration target.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeprecationNotice {
    pub name: Symbol,
    pub version: u32,
    pub deprecated_at: u64,
    pub sunset_at: u64,
    pub migration_target: Option<Address>,
    pub notice_symbol: Symbol,
}

impl DeprecationNotice {
    /// Checks whether the contract has passed its scheduled sunset timestamp.
    pub fn is_sunset(&self, current_time: u64) -> bool {
        current_time >= self.sunset_at
    }

    /// Calculates remaining seconds/ledgers until sunset.
    pub fn time_to_sunset(&self, current_time: u64) -> u64 {
        self.sunset_at.saturating_sub(current_time)
    }
}

// ── Core Operations ────────────────────────────────────────────────────────────

/// Evaluates whether a version is eligible to be pinned.
///
/// Requires that the target version exists in the historical versions list.
pub fn validate_pin_target(
    available_versions: &[u32],
    target_version: u32,
) -> Result<(), RegistryPinningError> {
    if target_version == 0 {
        return Err(RegistryPinningError::InvalidVersion);
    }
    if !available_versions.contains(&target_version) {
        return Err(RegistryPinningError::VersionNotFound);
    }
    Ok(())
}

/// Creates a new `VersionPin` record.
pub fn create_version_pin(
    name: Symbol,
    version: u32,
    pinned_by: Address,
    current_time: u64,
    available_versions: &[u32],
) -> Result<VersionPin, RegistryPinningError> {
    validate_pin_target(available_versions, version)?;

    Ok(VersionPin {
        name,
        pinned_version: version,
        pinned_by,
        pinned_at: current_time,
    })
}

/// Creates a new `DeprecationNotice`.
pub fn create_deprecation_notice(
    name: Symbol,
    version: u32,
    current_time: u64,
    sunset_at: u64,
    migration_target: Option<Address>,
    notice_symbol: Symbol,
    available_versions: &[u32],
) -> Result<DeprecationNotice, RegistryPinningError> {
    validate_pin_target(available_versions, version)?;

    if sunset_at <= current_time {
        return Err(RegistryPinningError::InvalidSunsetTimestamp);
    }

    Ok(DeprecationNotice {
        name,
        version,
        deprecated_at: current_time,
        sunset_at,
        migration_target,
        notice_symbol,
    })
}

/// Resolves which version of a contract should be used.
///
/// If a pin is present, the pinned version is selected; otherwise, the latest version is used.
/// If a deprecation notice is present and the version is sunset, resolution fails with `ContractSunset`.
pub fn resolve_target_version(
    pinned: Option<&VersionPin>,
    latest_version: u32,
    notice: Option<&DeprecationNotice>,
    current_time: u64,
) -> Result<u32, RegistryPinningError> {
    let selected_version = match pinned {
        Some(pin) => pin.pinned_version,
        None => {
            if latest_version == 0 {
                return Err(RegistryPinningError::ContractNotRegistered);
            }
            latest_version
        }
    };

    if let Some(dep) = notice {
        if dep.version == selected_version && dep.is_sunset(current_time) {
            return Err(RegistryPinningError::ContractSunset);
        }
    }

    Ok(selected_version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{symbol_short, testutils::Address as _, Env};

    #[test]
    fn test_pin_and_resolve() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let name = symbol_short!("treasury");
        let versions = [1u32, 2u32, 3u32];

        // 1. Unpinned resolution yields latest version (3)
        let unpinned_res = resolve_target_version(None, 3, None, 1000).unwrap();
        assert_eq!(unpinned_res, 3);

        // 2. Pin to version 2
        let pin = create_version_pin(name.clone(), 2, admin.clone(), 1000, &versions).unwrap();
        assert_eq!(pin.pinned_version, 2);

        // 3. Pinned resolution yields pinned version (2) even when latest is 3
        let pinned_res = resolve_target_version(Some(&pin), 3, None, 1001).unwrap();
        assert_eq!(pinned_res, 2);

        // 4. Pinning to non-existent version fails
        let err = create_version_pin(name.clone(), 99, admin.clone(), 1002, &versions);
        assert_eq!(err, Err(RegistryPinningError::VersionNotFound));
    }

    #[test]
    fn test_deprecation_lifecycle_and_sunset() {
        let env = Env::default();
        let name = symbol_short!("token_gate");
        let versions = [1u32, 2u32];
        let replacement = Address::generate(&env);

        // Create deprecation notice: deprecated at 1000, sunset at 2000
        let notice = create_deprecation_notice(
            name.clone(),
            1,
            1000,
            2000,
            Some(replacement.clone()),
            symbol_short!("use_v2"),
            &versions,
        ).unwrap();

        assert_eq!(notice.is_sunset(1500), false);
        assert_eq!(notice.time_to_sunset(1500), 500);

        // Resolution before sunset succeeds
        let res_before = resolve_target_version(None, 1, Some(&notice), 1999).unwrap();
        assert_eq!(res_before, 1);

        // At or after sunset (2000), resolution fails with ContractSunset
        let err_sunset = resolve_target_version(None, 1, Some(&notice), 2000);
        assert_eq!(err_sunset, Err(RegistryPinningError::ContractSunset));

        // Invalid sunset in past or present fails
        let err_invalid = create_deprecation_notice(
            name.clone(),
            1,
            1000,
            1000, // same as current
            None,
            symbol_short!("bad_time"),
            &versions,
        );
        assert_eq!(err_invalid, Err(RegistryPinningError::InvalidSunsetTimestamp));
    }
}

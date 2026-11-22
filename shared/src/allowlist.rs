//! Strict allow-list validation for external URLs, referenced file types, and
//! settlement destination addresses (Issue #277).
//!
//! [`sanitize::validate_external_url`] already rejects dangerous *schemes*
//! (`javascript:`, `data:`, …) and malformed bytes. This module adds a second,
//! **admin-managed** layer on top of that: once a contract's admin populates
//! `allowed_hosts`, `allowed_extensions`, or `allowed_destinations`, only the
//! configured entries are accepted for that dimension.
//!
//! ## Design: additive, backward compatible, and fail-closed once enabled
//!
//! Each dimension (`hosts`, `extensions`, `destinations`) starts
//! **unenforced**: `*_enforced` is `false` and its list is empty, so a
//! contract that adopts this module keeps its current behaviour (pass-
//! through) until an admin explicitly opts in. Opting in is implicit and
//! one-directional: the first successful `add_allowed_*` call for a
//! dimension flips its `*_enforced` flag to `true`, and **removing entries
//! never clears it** — so once enabled, emptying a list by removing its
//! last entry means "reject everything" for that dimension, not "accept
//! everything". This is deliberate: a fail-open fallback on removal would
//! let an admin accidentally reopen an allow-list they meant to keep
//! locked down. The only way back to pass-through is [`restore_policy`]
//! with an explicit (e.g. [`default_policy`]) snapshot — see
//! `docs/ALLOWLIST_VALIDATION.md` for the full migration and rollback plan.
//! This mirrors the existing `is_currency_whitelisted` pattern in
//! `nft-marketplace`, generalised to URLs/hosts, file extensions, and
//! destination addresses, and reuses
//! [`crate::auth::Permission::ManageConfiguration`] for authorization so it
//! composes with the role system every contract already uses.
//!
//! ## Covered paths
//! - **Normal**: value matches an enforced allow-list, or the relevant
//!   dimension is not yet enforced -> `Ok(())`.
//! - **Rejection**: a dimension is enforced and the value does not match ->
//!   a specific [`AllowlistError`] variant.
//! - **Retry**: rejected submissions can be resubmitted unchanged after an
//!   admin adds the missing entry; add/remove are idempotent so retried
//!   admin calls are also safe.
//! - **Authorization**: only callers holding `Permission::ManageConfiguration`
//!   may mutate a policy; state is left untouched on an unauthorized call.

use soroban_sdk::{contracttype, Address, Bytes, Env, Vec};

use crate::auth::{require_permission, Permission};
use crate::sanitize::{
    starts_with_case_insensitive, to_ascii_lower, validate_external_url, MAX_URL_LEN,
};
use crate::storage::{instance_get, instance_set};

/// Maximum number of entries permitted in any single allow-list dimension.
/// Bounds storage growth and iteration cost.
pub const MAX_ALLOWLIST_ENTRIES: u32 = 64;

/// Maximum byte length of a single host entry.
pub const MAX_HOST_LEN: u32 = 255;

/// Maximum byte length of a single file-extension entry (without the dot).
pub const MAX_EXTENSION_LEN: u32 = 16;

/// URL schemes this module knows how to extract an authority/host from.
/// `did:` identifiers have no authority component and are intentionally
/// excluded: a `did:` value is rejected by the host dimension whenever that
/// dimension is enforced (non-empty `allowed_hosts`).
const HOST_BEARING_SCHEMES: &[&[u8]] = &[b"https://", b"http://", b"ipfs://", b"ipns://", b"ar://"];

/// Stable error taxonomy for allow-list validation and management.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllowlistError {
    /// The caller does not hold `Permission::ManageConfiguration`.
    Unauthorized,
    /// The URL failed baseline scheme/byte safety validation
    /// (see [`crate::sanitize::validate_external_url`]).
    InvalidUrl,
    /// `allowed_hosts` is non-empty and the URL's host is not on it (or the
    /// URL's scheme has no extractable host, e.g. `did:`).
    HostNotAllowed,
    /// `allowed_extensions` is non-empty and the URL has no recognizable
    /// file extension, or that extension is not on the list.
    ExtensionNotAllowed,
    /// `allowed_destinations` is non-empty and the destination address is
    /// not on it.
    DestinationNotAllowed,
    /// Adding this entry would exceed `MAX_ALLOWLIST_ENTRIES` for that
    /// dimension.
    BoundExceeded,
    /// The supplied entry is structurally invalid (empty or oversized).
    InvalidEntry,
}

/// A contract's configured allow-lists for URLs, file types, and settlement
/// destinations. Stored once per contract instance.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowlistPolicy {
    /// Lowercase host entries (e.g. `b"ipfs.io"`).
    pub allowed_hosts: Vec<Bytes>,
    /// Lowercase file-extension entries without a leading dot (e.g.
    /// `b"json"`).
    pub allowed_extensions: Vec<Bytes>,
    /// Allow-listed destination addresses.
    pub allowed_destinations: Vec<Address>,
    /// Whether the host dimension is enforced. Set automatically the first
    /// time a host is added; **not** cleared automatically when the list is
    /// later emptied by removals (see `docs/ALLOWLIST_VALIDATION.md`) — once
    /// a contract has opted in, an emptied list means "reject every host",
    /// not "accept every host". Use [`restore_policy`] to deliberately
    /// return to an unconfigured (pass-through) state.
    pub hosts_enforced: bool,
    /// Same semantics as `hosts_enforced`, for `allowed_extensions`.
    pub extensions_enforced: bool,
    /// Same semantics as `hosts_enforced`, for `allowed_destinations`.
    pub destinations_enforced: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum AllowlistDataKey {
    Policy,
}

/// Returns an empty (fully permissive / unconfigured) policy.
pub fn default_policy(env: &Env) -> AllowlistPolicy {
    AllowlistPolicy {
        allowed_hosts: Vec::new(env),
        allowed_extensions: Vec::new(env),
        allowed_destinations: Vec::new(env),
        hosts_enforced: false,
        extensions_enforced: false,
        destinations_enforced: false,
    }
}

/// Reads the current allow-list policy for this contract instance, or the
/// empty default if none has been configured yet.
pub fn get_policy(env: &Env) -> AllowlistPolicy {
    instance_get(env, &AllowlistDataKey::Policy).unwrap_or_else(|| default_policy(env))
}

fn put_policy(env: &Env, policy: &AllowlistPolicy) {
    instance_set(env, &AllowlistDataKey::Policy, policy);
}

fn normalize_entry(env: &Env, raw: &Bytes, max_len: u32) -> Result<Bytes, AllowlistError> {
    let len = raw.len();
    if len == 0 || len > max_len {
        return Err(AllowlistError::InvalidEntry);
    }
    let mut out = Bytes::new(env);
    let mut i = 0u32;
    while i < len {
        out.push_back(to_ascii_lower(raw.get(i).unwrap_or(0)));
        i += 1;
    }
    Ok(out)
}

/// Strips a single leading `.` so admins may pass either `"json"` or
/// `".json"` and get the same stored entry.
fn strip_leading_dot(env: &Env, normalized: &Bytes) -> Bytes {
    if normalized.get(0) != Some(b'.') {
        return normalized.clone();
    }
    let len = normalized.len();
    let mut out = Bytes::new(env);
    let mut i = 1u32;
    while i < len {
        out.push_back(normalized.get(i).unwrap_or(0));
        i += 1;
    }
    out
}

/// Extracts the lowercased authority/host component from a URL whose scheme
/// is in [`HOST_BEARING_SCHEMES`]. Returns `None` for schemes with no host
/// (e.g. `did:`) or a URL with an empty host.
fn extract_host(env: &Env, url: &Bytes) -> Option<Bytes> {
    let mut prefix_len: Option<u32> = None;
    for prefix in HOST_BEARING_SCHEMES {
        if starts_with_case_insensitive(url, prefix, 0) {
            prefix_len = Some(prefix.len() as u32);
            break;
        }
    }
    let start = prefix_len?;
    let len = url.len();
    let mut host = Bytes::new(env);
    let mut i = start;
    while i < len {
        let b = url.get(i).unwrap_or(0);
        if b == b'/' || b == b'?' || b == b'#' {
            break;
        }
        host.push_back(to_ascii_lower(b));
        i += 1;
    }
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// Extracts the lowercased file extension (text after the final `.` in the
/// path component, before any `?query` or `#fragment`) referenced by a URL.
/// Returns `None` when there is no dot in the path component, the trailing
/// segment is empty, it exceeds [`MAX_EXTENSION_LEN`], or the candidate
/// spans a `/` (the dot belonged to a directory name, not a file).
fn extract_extension(env: &Env, url: &Bytes) -> Option<Bytes> {
    let len = url.len();
    let mut last_dot: Option<u32> = None;
    let mut path_end = len;
    let mut i = 0u32;
    while i < len {
        let b = url.get(i).unwrap_or(0);
        if b == b'?' || b == b'#' {
            path_end = i;
            break;
        }
        if b == b'.' {
            last_dot = Some(i);
        }
        i += 1;
    }
    let dot = last_dot?;
    if dot + 1 >= path_end {
        return None;
    }
    let ext_len = path_end - (dot + 1);
    if ext_len == 0 || ext_len > MAX_EXTENSION_LEN {
        return None;
    }
    let mut ext = Bytes::new(env);
    let mut j = dot + 1;
    while j < path_end {
        let b = url.get(j).unwrap_or(0);
        if b == b'/' {
            // The last '.' before the query/fragment was inside a path
            // segment (e.g. ".well-known"), not a file extension.
            return None;
        }
        ext.push_back(to_ascii_lower(b));
        j += 1;
    }
    Some(ext)
}

// ---------------------------------------------------------------------------
// Validation (normal + rejection paths)
// ---------------------------------------------------------------------------

/// Validates `url` against baseline scheme safety and, when configured, the
/// host and file-extension allow-lists.
///
/// Composes with [`crate::sanitize::validate_external_url`] rather than
/// replacing it: a URL must first pass the existing scheme/control-byte
/// checks before the allow-list dimensions are even considered.
pub fn validate_url(env: &Env, url: &Bytes) -> Result<(), AllowlistError> {
    validate_external_url(url, MAX_URL_LEN, false).map_err(|_| AllowlistError::InvalidUrl)?;

    let policy = get_policy(env);

    if policy.hosts_enforced {
        let host = extract_host(env, url).ok_or(AllowlistError::HostNotAllowed)?;
        if !policy.allowed_hosts.iter().any(|h| h == host) {
            return Err(AllowlistError::HostNotAllowed);
        }
    }

    if policy.extensions_enforced {
        let ext = extract_extension(env, url).ok_or(AllowlistError::ExtensionNotAllowed)?;
        if !policy.allowed_extensions.iter().any(|e| e == ext) {
            return Err(AllowlistError::ExtensionNotAllowed);
        }
    }

    Ok(())
}

/// Validates `destination` against the destination allow-list, when
/// configured (`destinations_enforced`). Pass-through (`Ok(())`) until an
/// admin has added at least one destination.
pub fn validate_destination(env: &Env, destination: &Address) -> Result<(), AllowlistError> {
    let policy = get_policy(env);
    if policy.destinations_enforced
        && !policy
            .allowed_destinations
            .iter()
            .any(|d| d == *destination)
    {
        return Err(AllowlistError::DestinationNotAllowed);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Authorized mutation (authorization path) — idempotent add/remove so a
// retried admin call (e.g. after a submitted transaction's status was
// unclear) is always safe.
// ---------------------------------------------------------------------------

/// Adds `host` to `allowed_hosts`. Requires `Permission::ManageConfiguration`.
/// Idempotent: adding an already-present host returns `Ok(())` without
/// mutating storage.
pub fn add_allowed_host(env: &Env, caller: &Address, host: Bytes) -> Result<(), AllowlistError> {
    require_permission(env, caller, Permission::ManageConfiguration)
        .map_err(|_| AllowlistError::Unauthorized)?;
    let normalized = normalize_entry(env, &host, MAX_HOST_LEN)?;
    let mut policy = get_policy(env);
    let already_present = policy.allowed_hosts.iter().any(|h| h == normalized);
    if already_present && policy.hosts_enforced {
        return Ok(());
    }
    if !already_present {
        if policy.allowed_hosts.len() >= MAX_ALLOWLIST_ENTRIES {
            return Err(AllowlistError::BoundExceeded);
        }
        policy.allowed_hosts.push_back(normalized);
    }
    policy.hosts_enforced = true;
    put_policy(env, &policy);
    Ok(())
}

/// Removes `host` from `allowed_hosts`. Requires
/// `Permission::ManageConfiguration`. Idempotent: removing an absent host
/// returns `Ok(())`.
///
/// Note: this does not retroactively affect data already stored while the
/// host was allow-listed — see `docs/ALLOWLIST_VALIDATION.md`.
pub fn remove_allowed_host(env: &Env, caller: &Address, host: Bytes) -> Result<(), AllowlistError> {
    require_permission(env, caller, Permission::ManageConfiguration)
        .map_err(|_| AllowlistError::Unauthorized)?;
    let normalized = normalize_entry(env, &host, MAX_HOST_LEN)?;
    let mut policy = get_policy(env);
    let mut remaining = Vec::new(env);
    for h in policy.allowed_hosts.iter() {
        if h != normalized {
            remaining.push_back(h);
        }
    }
    policy.allowed_hosts = remaining;
    put_policy(env, &policy);
    Ok(())
}

/// Adds `extension` (with or without a leading dot) to `allowed_extensions`.
/// Requires `Permission::ManageConfiguration`. Idempotent.
pub fn add_allowed_extension(
    env: &Env,
    caller: &Address,
    extension: Bytes,
) -> Result<(), AllowlistError> {
    require_permission(env, caller, Permission::ManageConfiguration)
        .map_err(|_| AllowlistError::Unauthorized)?;
    let normalized = strip_leading_dot(
        env,
        &normalize_entry(env, &extension, MAX_EXTENSION_LEN + 1)?,
    );
    if normalized.is_empty() || normalized.len() > MAX_EXTENSION_LEN {
        return Err(AllowlistError::InvalidEntry);
    }
    let mut policy = get_policy(env);
    let already_present = policy.allowed_extensions.iter().any(|e| e == normalized);
    if already_present && policy.extensions_enforced {
        return Ok(());
    }
    if !already_present {
        if policy.allowed_extensions.len() >= MAX_ALLOWLIST_ENTRIES {
            return Err(AllowlistError::BoundExceeded);
        }
        policy.allowed_extensions.push_back(normalized);
    }
    policy.extensions_enforced = true;
    put_policy(env, &policy);
    Ok(())
}

/// Removes `extension` from `allowed_extensions`. Requires
/// `Permission::ManageConfiguration`. Idempotent.
pub fn remove_allowed_extension(
    env: &Env,
    caller: &Address,
    extension: Bytes,
) -> Result<(), AllowlistError> {
    require_permission(env, caller, Permission::ManageConfiguration)
        .map_err(|_| AllowlistError::Unauthorized)?;
    let normalized = strip_leading_dot(
        env,
        &normalize_entry(env, &extension, MAX_EXTENSION_LEN + 1)?,
    );
    let mut policy = get_policy(env);
    let mut remaining = Vec::new(env);
    for e in policy.allowed_extensions.iter() {
        if e != normalized {
            remaining.push_back(e);
        }
    }
    policy.allowed_extensions = remaining;
    put_policy(env, &policy);
    Ok(())
}

/// Adds `destination` to `allowed_destinations`. Requires
/// `Permission::ManageConfiguration`. Idempotent.
pub fn add_allowed_destination(
    env: &Env,
    caller: &Address,
    destination: Address,
) -> Result<(), AllowlistError> {
    require_permission(env, caller, Permission::ManageConfiguration)
        .map_err(|_| AllowlistError::Unauthorized)?;
    let mut policy = get_policy(env);
    let already_present = policy.allowed_destinations.iter().any(|d| d == destination);
    if already_present && policy.destinations_enforced {
        return Ok(());
    }
    if !already_present {
        if policy.allowed_destinations.len() >= MAX_ALLOWLIST_ENTRIES {
            return Err(AllowlistError::BoundExceeded);
        }
        policy.allowed_destinations.push_back(destination);
    }
    policy.destinations_enforced = true;
    put_policy(env, &policy);
    Ok(())
}

/// Removes `destination` from `allowed_destinations`. Requires
/// `Permission::ManageConfiguration`. Idempotent.
pub fn remove_allowed_destination(
    env: &Env,
    caller: &Address,
    destination: Address,
) -> Result<(), AllowlistError> {
    require_permission(env, caller, Permission::ManageConfiguration)
        .map_err(|_| AllowlistError::Unauthorized)?;
    let mut policy = get_policy(env);
    let mut remaining = Vec::new(env);
    for d in policy.allowed_destinations.iter() {
        if d != destination {
            remaining.push_back(d);
        }
    }
    policy.allowed_destinations = remaining;
    put_policy(env, &policy);
    Ok(())
}

/// Rollback helper: atomically replaces the whole policy with a previously
/// captured snapshot (e.g. one read via [`get_policy`] before a risky change).
/// Requires `Permission::ManageConfiguration`. Rejects a snapshot that
/// violates `MAX_ALLOWLIST_ENTRIES` so a corrupt snapshot cannot be restored.
pub fn restore_policy(
    env: &Env,
    caller: &Address,
    policy: AllowlistPolicy,
) -> Result<(), AllowlistError> {
    require_permission(env, caller, Permission::ManageConfiguration)
        .map_err(|_| AllowlistError::Unauthorized)?;
    if policy.allowed_hosts.len() > MAX_ALLOWLIST_ENTRIES
        || policy.allowed_extensions.len() > MAX_ALLOWLIST_ENTRIES
        || policy.allowed_destinations.len() > MAX_ALLOWLIST_ENTRIES
    {
        return Err(AllowlistError::BoundExceeded);
    }
    put_policy(env, &policy);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{contract, testutils::Address as _};

    #[contract]
    struct Fixture;

    fn setup() -> (Env, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, Fixture);
        let admin = Address::generate(&env);
        exec(&env, &id, || {
            crate::auth::initialize_admin(&env, &admin).unwrap()
        });
        let stranger = Address::generate(&env);
        (env, id, admin, stranger)
    }

    /// Runs `f` as its own top-level contract invocation.
    ///
    /// Each call that performs `Address::require_auth` (every allow-list
    /// mutator) must be its own root invocation: the mocked-auth host
    /// rejects authorizing the exact same (address, invocation) twice within
    /// one still-open frame ("frame is already authorized"), the same way a
    /// real caller would submit each admin action as its own transaction.
    fn exec<T>(env: &Env, id: &Address, f: impl FnOnce() -> T) -> T {
        env.as_contract(id, f)
    }

    fn url(env: &Env, s: &str) -> Bytes {
        Bytes::from_slice(env, s.as_bytes())
    }

    /// Builds a distinct `host-<n>.example` value without pulling in `alloc`.
    fn unique_host(env: &Env, n: u32) -> Bytes {
        let mut b = Bytes::new(env);
        b.append(&Bytes::from_slice(env, b"host-"));
        let tens = (n / 10) as u8;
        let ones = (n % 10) as u8;
        if tens > 0 {
            b.push_back(b'0' + tens);
        }
        b.push_back(b'0' + ones);
        b.append(&Bytes::from_slice(env, b".example"));
        b
    }

    #[test]
    fn normal_path_unconfigured_lists_pass_through() {
        let (env, id, _admin, _stranger) = setup();
        assert_eq!(
            exec(&env, &id, || validate_url(
                &env,
                &url(&env, "https://arbitrary.example/metadata.json")
            )),
            Ok(())
        );
        let dest = exec(&env, &id, || Address::generate(&env));
        assert_eq!(
            exec(&env, &id, || validate_destination(&env, &dest)),
            Ok(())
        );
    }

    #[test]
    fn rejection_path_blocks_values_outside_configured_allowlist() {
        let (env, id, admin, _stranger) = setup();
        exec(&env, &id, || {
            add_allowed_host(&env, &admin, url(&env, "ipfs.io")).unwrap()
        });
        exec(&env, &id, || {
            add_allowed_extension(&env, &admin, url(&env, ".json")).unwrap()
        });

        // Allow-listed host + extension succeeds.
        assert_eq!(
            exec(&env, &id, || validate_url(
                &env,
                &url(&env, "https://ipfs.io/ipfs/CID/metadata.json")
            )),
            Ok(())
        );
        // Wrong host is rejected even though the extension is fine.
        assert_eq!(
            exec(&env, &id, || validate_url(
                &env,
                &url(&env, "https://evil.example/metadata.json")
            )),
            Err(AllowlistError::HostNotAllowed)
        );
        // Right host, wrong (disallowed) extension is rejected.
        assert_eq!(
            exec(&env, &id, || validate_url(
                &env,
                &url(&env, "https://ipfs.io/ipfs/CID/payload.exe")
            )),
            Err(AllowlistError::ExtensionNotAllowed)
        );
        // A scheme with no extractable host (did:) is rejected once the
        // host dimension is enforced.
        assert_eq!(
            exec(&env, &id, || validate_url(
                &env,
                &url(&env, "did:example:1234")
            )),
            Err(AllowlistError::HostNotAllowed)
        );

        let allowed_dest = exec(&env, &id, || Address::generate(&env));
        let other_dest = exec(&env, &id, || Address::generate(&env));
        exec(&env, &id, || {
            add_allowed_destination(&env, &admin, allowed_dest.clone()).unwrap()
        });
        assert_eq!(
            exec(&env, &id, || validate_destination(&env, &allowed_dest)),
            Ok(())
        );
        assert_eq!(
            exec(&env, &id, || validate_destination(&env, &other_dest)),
            Err(AllowlistError::DestinationNotAllowed)
        );
    }

    #[test]
    fn retry_path_succeeds_after_allowlist_is_updated() {
        let (env, id, admin, _stranger) = setup();
        exec(&env, &id, || {
            add_allowed_host(&env, &admin, url(&env, "ipfs.io")).unwrap()
        });
        let candidate = url(&env, "https://gateway.pinata.cloud/ipfs/CID");

        // First submission is rejected: host not yet on the list.
        assert_eq!(
            exec(&env, &id, || validate_url(&env, &candidate)),
            Err(AllowlistError::HostNotAllowed)
        );

        // Admin updates the allow-list.
        exec(&env, &id, || {
            add_allowed_host(&env, &admin, url(&env, "gateway.pinata.cloud")).unwrap()
        });

        // Resubmitting the exact same value now succeeds.
        assert_eq!(exec(&env, &id, || validate_url(&env, &candidate)), Ok(()));

        // Retrying the same admin call again is idempotent (no duplicate entry,
        // no error).
        assert_eq!(
            exec(&env, &id, || add_allowed_host(
                &env,
                &admin,
                url(&env, "gateway.pinata.cloud")
            )),
            Ok(())
        );
        assert_eq!(exec(&env, &id, || get_policy(&env).allowed_hosts.len()), 2);
    }

    #[test]
    fn authorization_path_rejects_non_admin_mutation_without_side_effects() {
        let (env, id, admin, stranger) = setup();
        let before = exec(&env, &id, || get_policy(&env));
        assert_eq!(
            exec(&env, &id, || add_allowed_host(
                &env,
                &stranger,
                url(&env, "ipfs.io")
            )),
            Err(AllowlistError::Unauthorized)
        );
        assert_eq!(
            exec(&env, &id, || add_allowed_extension(
                &env,
                &stranger,
                url(&env, "json")
            )),
            Err(AllowlistError::Unauthorized)
        );
        let dest = exec(&env, &id, || Address::generate(&env));
        assert_eq!(
            exec(&env, &id, || add_allowed_destination(
                &env,
                &stranger,
                dest.clone()
            )),
            Err(AllowlistError::Unauthorized)
        );
        assert_eq!(
            exec(&env, &id, || remove_allowed_host(
                &env,
                &stranger,
                url(&env, "ipfs.io")
            )),
            Err(AllowlistError::Unauthorized)
        );
        assert_eq!(
            exec(&env, &id, || restore_policy(
                &env,
                &stranger,
                default_policy(&env)
            )),
            Err(AllowlistError::Unauthorized)
        );
        assert_eq!(exec(&env, &id, || get_policy(&env)), before);

        // The admin can do what the stranger could not.
        assert_eq!(
            exec(&env, &id, || add_allowed_host(
                &env,
                &admin,
                url(&env, "ipfs.io")
            )),
            Ok(())
        );
        assert_eq!(exec(&env, &id, || get_policy(&env).allowed_hosts.len()), 1);
    }

    #[test]
    fn rollback_restores_a_previously_captured_snapshot() {
        let (env, id, admin, _stranger) = setup();
        exec(&env, &id, || {
            add_allowed_host(&env, &admin, url(&env, "ipfs.io")).unwrap()
        });
        exec(&env, &id, || {
            add_allowed_extension(&env, &admin, url(&env, "json")).unwrap()
        });
        let snapshot = exec(&env, &id, || get_policy(&env));

        // A risky change: drop the host that other stored records relied on.
        exec(&env, &id, || {
            remove_allowed_host(&env, &admin, url(&env, "ipfs.io")).unwrap()
        });
        assert!(exec(&env, &id, || get_policy(&env)
            .allowed_hosts
            .is_empty()));
        assert_eq!(
            exec(&env, &id, || validate_url(
                &env,
                &url(&env, "https://ipfs.io/ipfs/CID/metadata.json")
            )),
            Err(AllowlistError::HostNotAllowed)
        );

        // Roll back to the snapshot taken before the change.
        let snapshot_for_restore = snapshot.clone();
        exec(&env, &id, || {
            restore_policy(&env, &admin, snapshot_for_restore).unwrap()
        });
        assert_eq!(exec(&env, &id, || get_policy(&env)), snapshot);
        assert_eq!(
            exec(&env, &id, || validate_url(
                &env,
                &url(&env, "https://ipfs.io/ipfs/CID/metadata.json")
            )),
            Ok(())
        );
    }

    #[test]
    fn bound_exceeded_is_enforced_per_dimension() {
        let (env, id, admin, _stranger) = setup();
        for i in 0..MAX_ALLOWLIST_ENTRIES {
            exec(&env, &id, || {
                add_allowed_host(&env, &admin, unique_host(&env, i)).unwrap()
            });
        }
        assert_eq!(
            exec(&env, &id, || add_allowed_host(
                &env,
                &admin,
                url(&env, "one-too-many.example")
            )),
            Err(AllowlistError::BoundExceeded)
        );

        let mut oversized_snapshot = exec(&env, &id, || get_policy(&env));
        for _ in 0..=MAX_ALLOWLIST_ENTRIES {
            let addr = exec(&env, &id, || Address::generate(&env));
            oversized_snapshot.allowed_destinations.push_back(addr);
        }
        assert_eq!(
            exec(&env, &id, || restore_policy(
                &env,
                &admin,
                oversized_snapshot.clone()
            )),
            Err(AllowlistError::BoundExceeded)
        );
    }

    #[test]
    fn invalid_entries_and_malformed_urls_are_rejected() {
        let (env, id, admin, _stranger) = setup();
        assert_eq!(
            exec(&env, &id, || add_allowed_host(
                &env,
                &admin,
                Bytes::new(&env)
            )),
            Err(AllowlistError::InvalidEntry)
        );
        assert_eq!(
            exec(&env, &id, || validate_url(
                &env,
                &url(&env, "javascript:alert(1)")
            )),
            Err(AllowlistError::InvalidUrl)
        );
    }
}

//! Reproducible release artifact manifests and verification (Issue #446).
//!
//! A release is described by a [`ReleaseManifest`]: the source commit, the
//! toolchain it was built with, and the SHA-256 digest and size of every
//! contract artifact. The manifest has exactly one canonical form (artifacts
//! strictly sorted by name, no duplicates), so two independent builds of the
//! same commit must produce the same [`manifest_digest`].
//!
//! The admin publishes the digest for a release version once. Anyone can then
//! check a locally rebuilt manifest against it with [`verify_published`], and
//! compare observed artifacts against a manifest with [`verify_artifacts`].
//! See `docs/RELEASE_ARTIFACTS.md` for the operator flow and rollback notes.

use soroban_sdk::{contracterror, contracttype, xdr::ToXdr, Address, BytesN, Env, Symbol, Vec};

use crate::auth;

pub const RELEASE_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const MAX_RELEASE_ARTIFACTS: u32 = 32;

const RELEASE_DIGEST_KEY: u32 = 0x5241_4446; // "RADF"

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ReleaseArtifactError {
    EmptyManifest = 1,
    TooManyArtifacts = 2,
    UnsortedOrDuplicateArtifact = 3,
    UnsupportedSchemaVersion = 4,
    ManifestMismatch = 5,
    Unauthorized = 6,
    AlreadyPublished = 7,
    NotPublished = 8,
    EmptyArtifact = 9,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseArtifact {
    pub name: Symbol,
    pub sha256: BytesN<32>,
    pub size: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseManifest {
    pub schema_version: u32,
    pub release: u32,
    pub source_commit: BytesN<20>,
    pub toolchain: Symbol,
    pub artifacts: Vec<ReleaseArtifact>,
}

/// Outcome of comparing observed artifacts with a manifest.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactVerificationReport {
    pub matched: u32,
    pub missing: u32,
    pub mismatched: u32,
    pub unexpected: u32,
}

impl ArtifactVerificationReport {
    pub fn is_clean(&self) -> bool {
        self.missing == 0 && self.mismatched == 0 && self.unexpected == 0
    }
}

/// Checks that a manifest is in canonical form.
pub fn validate_manifest(manifest: &ReleaseManifest) -> Result<(), ReleaseArtifactError> {
    if manifest.schema_version != RELEASE_MANIFEST_SCHEMA_VERSION {
        return Err(ReleaseArtifactError::UnsupportedSchemaVersion);
    }
    let len = manifest.artifacts.len();
    if len == 0 {
        return Err(ReleaseArtifactError::EmptyManifest);
    }
    if len > MAX_RELEASE_ARTIFACTS {
        return Err(ReleaseArtifactError::TooManyArtifacts);
    }
    let mut previous: Option<Symbol> = None;
    for artifact in manifest.artifacts.iter() {
        if artifact.size == 0 {
            return Err(ReleaseArtifactError::EmptyArtifact);
        }
        if let Some(prev) = previous {
            if prev >= artifact.name {
                return Err(ReleaseArtifactError::UnsortedOrDuplicateArtifact);
            }
        }
        previous = Some(artifact.name.clone());
    }
    Ok(())
}

/// Canonical digest of a validated manifest.
pub fn manifest_digest(
    env: &Env,
    manifest: &ReleaseManifest,
) -> Result<BytesN<32>, ReleaseArtifactError> {
    validate_manifest(manifest)?;
    Ok(env.crypto().sha256(&manifest.clone().to_xdr(env)).to_bytes())
}

/// Compares artifacts produced by a local rebuild with the manifest.
pub fn verify_artifacts(
    manifest: &ReleaseManifest,
    observed: &Vec<ReleaseArtifact>,
) -> ArtifactVerificationReport {
    let mut report = ArtifactVerificationReport {
        matched: 0,
        missing: 0,
        mismatched: 0,
        unexpected: 0,
    };
    for expected in manifest.artifacts.iter() {
        match observed.iter().find(|a| a.name == expected.name) {
            None => report.missing += 1,
            Some(found) if found.sha256 == expected.sha256 && found.size == expected.size => {
                report.matched += 1
            }
            Some(_) => report.mismatched += 1,
        }
    }
    for found in observed.iter() {
        if !manifest.artifacts.iter().any(|a| a.name == found.name) {
            report.unexpected += 1;
        }
    }
    report
}

/// Publishes the digest for `manifest.release`. Admin only.
///
/// Retrying with the same manifest returns the stored digest; a different
/// manifest for an already-published release is rejected, because release
/// digests are immutable.
pub fn publish_manifest(
    env: &Env,
    caller: &Address,
    manifest: &ReleaseManifest,
) -> Result<BytesN<32>, ReleaseArtifactError> {
    auth::require_admin(env, caller).map_err(|_| ReleaseArtifactError::Unauthorized)?;
    let digest = manifest_digest(env, manifest)?;
    let key = (RELEASE_DIGEST_KEY, manifest.release);
    if let Some(existing) = env.storage().persistent().get::<_, BytesN<32>>(&key) {
        if existing == digest {
            return Ok(existing);
        }
        return Err(ReleaseArtifactError::AlreadyPublished);
    }
    env.storage().persistent().set(&key, &digest);
    Ok(digest)
}

pub fn published_digest(env: &Env, release: u32) -> Option<BytesN<32>> {
    env.storage()
        .persistent()
        .get::<_, BytesN<32>>(&(RELEASE_DIGEST_KEY, release))
}

/// Checks a locally rebuilt manifest against the published digest.
pub fn verify_published(env: &Env, manifest: &ReleaseManifest) -> Result<(), ReleaseArtifactError> {
    let published =
        published_digest(env, manifest.release).ok_or(ReleaseArtifactError::NotPublished)?;
    if manifest_digest(env, manifest)? != published {
        return Err(ReleaseArtifactError::ManifestMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{contract, contractimpl, symbol_short, vec};

    #[contract]
    pub struct ReleaseArtifactsFixture;

    #[contractimpl]
    impl ReleaseArtifactsFixture {
        pub fn release_artifacts_ping() -> u32 {
            1
        }
    }

    fn artifact(env: &Env, name: Symbol, byte: u8, size: u32) -> ReleaseArtifact {
        ReleaseArtifact {
            name,
            sha256: BytesN::from_array(env, &[byte; 32]),
            size,
        }
    }

    fn manifest(env: &Env, release: u32) -> ReleaseManifest {
        ReleaseManifest {
            schema_version: RELEASE_MANIFEST_SCHEMA_VERSION,
            release,
            source_commit: BytesN::from_array(env, &[7; 20]),
            toolchain: symbol_short!("rust_1_81"),
            artifacts: vec![
                env,
                artifact(env, symbol_short!("aid"), 1, 100),
                artifact(env, symbol_short!("payments"), 2, 200),
                artifact(env, symbol_short!("treasury"), 3, 300),
            ],
        }
    }

    fn setup(env: &Env) -> (Address, Address) {
        env.mock_all_auths();
        let contract_id = env.register_contract(None, ReleaseArtifactsFixture);
        let admin = Address::generate(env);
        env.as_contract(&contract_id, || auth::set_admin(env, &admin));
        (contract_id, admin)
    }

    #[test]
    fn digest_is_deterministic_for_identical_builds() {
        let env = Env::default();
        let a = manifest_digest(&env, &manifest(&env, 1)).unwrap();
        let b = manifest_digest(&env, &manifest(&env, 1)).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn digest_changes_when_any_artifact_changes() {
        let env = Env::default();
        let base = manifest_digest(&env, &manifest(&env, 1)).unwrap();
        let mut changed = manifest(&env, 1);
        changed
            .artifacts
            .set(1, artifact(&env, symbol_short!("payments"), 9, 200));
        assert_ne!(base, manifest_digest(&env, &changed).unwrap());
    }

    #[test]
    fn rejects_non_canonical_manifests() {
        let env = Env::default();
        let mut unsorted = manifest(&env, 1);
        unsorted.artifacts = vec![
            &env,
            artifact(&env, symbol_short!("treasury"), 3, 300),
            artifact(&env, symbol_short!("aid"), 1, 100),
        ];
        assert_eq!(
            validate_manifest(&unsorted),
            Err(ReleaseArtifactError::UnsortedOrDuplicateArtifact)
        );

        let mut duplicate = manifest(&env, 1);
        duplicate.artifacts = vec![
            &env,
            artifact(&env, symbol_short!("aid"), 1, 100),
            artifact(&env, symbol_short!("aid"), 1, 100),
        ];
        assert_eq!(
            validate_manifest(&duplicate),
            Err(ReleaseArtifactError::UnsortedOrDuplicateArtifact)
        );

        let mut empty = manifest(&env, 1);
        empty.artifacts = Vec::new(&env);
        assert_eq!(validate_manifest(&empty), Err(ReleaseArtifactError::EmptyManifest));

        let mut zero = manifest(&env, 1);
        zero.artifacts = vec![&env, artifact(&env, symbol_short!("aid"), 1, 0)];
        assert_eq!(validate_manifest(&zero), Err(ReleaseArtifactError::EmptyArtifact));

        let mut future = manifest(&env, 1);
        future.schema_version = 2;
        assert_eq!(
            validate_manifest(&future),
            Err(ReleaseArtifactError::UnsupportedSchemaVersion)
        );
    }

    #[test]
    fn verify_artifacts_reports_missing_mismatched_and_unexpected() {
        let env = Env::default();
        let m = manifest(&env, 1);
        assert!(verify_artifacts(&m, &m.artifacts).is_clean());

        let observed = vec![
            &env,
            artifact(&env, symbol_short!("aid"), 1, 100),
            artifact(&env, symbol_short!("payments"), 8, 200),
            artifact(&env, symbol_short!("rogue"), 4, 10),
        ];
        let report = verify_artifacts(&m, &observed);
        assert_eq!(
            report,
            ArtifactVerificationReport {
                matched: 1,
                missing: 1,
                mismatched: 1,
                unexpected: 1,
            }
        );
        assert!(!report.is_clean());
    }

    #[test]
    fn publish_is_admin_only_idempotent_and_immutable() {
        let env = Env::default();
        let (contract_id, admin) = setup(&env);
        env.as_contract(&contract_id, || {
            let stranger = Address::generate(&env);
            assert_eq!(
                publish_manifest(&env, &stranger, &manifest(&env, 1)),
                Err(ReleaseArtifactError::Unauthorized)
            );

            let digest = publish_manifest(&env, &admin, &manifest(&env, 1)).unwrap();
            // Retrying the same publish is safe.
            assert_eq!(publish_manifest(&env, &admin, &manifest(&env, 1)), Ok(digest.clone()));

            let mut other = manifest(&env, 1);
            other.toolchain = symbol_short!("rust_1_82");
            assert_eq!(
                publish_manifest(&env, &admin, &other),
                Err(ReleaseArtifactError::AlreadyPublished)
            );
            assert_eq!(published_digest(&env, 1), Some(digest));
        });
    }

    #[test]
    fn verify_published_detects_drifted_rebuild() {
        let env = Env::default();
        let (contract_id, admin) = setup(&env);
        env.as_contract(&contract_id, || {
            assert_eq!(
                verify_published(&env, &manifest(&env, 2)),
                Err(ReleaseArtifactError::NotPublished)
            );
            publish_manifest(&env, &admin, &manifest(&env, 2)).unwrap();
            assert_eq!(verify_published(&env, &manifest(&env, 2)), Ok(()));

            let mut rebuilt = manifest(&env, 2);
            rebuilt
                .artifacts
                .set(0, artifact(&env, symbol_short!("aid"), 5, 100));
            assert_eq!(
                verify_published(&env, &rebuilt),
                Err(ReleaseArtifactError::ManifestMismatch)
            );
        });
    }
}

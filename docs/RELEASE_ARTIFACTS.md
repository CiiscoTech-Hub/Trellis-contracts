# Reproducible Release Artifacts (Issue #446)

Module: `shared/src/release_artifacts.rs`

## Manifest

A `ReleaseManifest` records:

- `schema_version` (currently `1`)
- `release` number
- the 20-byte `source_commit`
- the `toolchain` symbol (pin it to `rust-toolchain.toml`)
- one `ReleaseArtifact { name, sha256, size }` per contract wasm

The manifest has exactly one canonical form:

- artifacts are strictly sorted by name, with no duplicates
- at most `MAX_RELEASE_ARTIFACTS` (32) entries
- no zero-size artifact

`manifest_digest` hashes the XDR encoding of a validated manifest. Two builds of the same commit with the same toolchain must produce the same digest.

## Flow

1. Build the release from a clean checkout of `source_commit` with the pinned toolchain.
2. Fill the manifest with the sha256 and size of every wasm, sorted by name.
3. The admin calls `publish_manifest`, which stores the digest for that release.
4. A verifier rebuilds the release independently and calls:
   - `verify_published` to compare the whole manifest
   - `verify_artifacts` to get per-artifact `missing` / `mismatched` / `unexpected` counts

## Paths and edge cases

| Path | Behaviour |
|---|---|
| Normal | publish stores the digest; verify returns `Ok(())` |
| Failure | a non-canonical manifest returns `UnsortedOrDuplicateArtifact`, `EmptyManifest`, `TooManyArtifacts`, `EmptyArtifact` or `UnsupportedSchemaVersion`; a drifted rebuild returns `ManifestMismatch`; an unknown release returns `NotPublished` |
| Retry | publishing the same manifest again returns the stored digest |
| Authorization | only the admin can publish (`Unauthorized` otherwise); verification is public |

## Recovery and rollback

Published digests are immutable: publishing a different manifest for the same release returns `AlreadyPublished`. To recover from a bad release, publish a new release number. That release can point at the previous good artifacts. Never overwrite a published digest.

## Compatibility

This is a new module with new storage keys. No existing contract or storage layout changes.

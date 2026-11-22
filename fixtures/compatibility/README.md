# Compatibility Fixtures

This directory contains versioned compatibility test fixtures for Trellis smart contract records across schema generations.

## Fixture Index

| File | Schema Version | Description | Target Tests |
|---|---|---|---|
| `v1_legacy_record.json` | 1 | Legacy record format without token binding or schema version tagging. | Backward-compatibility reads, lazy migration to V2. |
| `v2_current_record.json` | 2 | Current production record format with explicit token binding and schema version. | Current reads/writes, downgrade to V1. |
| `v3_forward_record.json` | 3 | Forward-compatible record format with metadata digest anchoring. | Forward-evolution preview and schema extension tests. |
| `malformed_record.json` | N/A | Malformed entries (negative amounts, unsupported schema version numbers). | Validation rejection and error code assertion tests. |

## Verification Command

Compatibility fixture integrity and migration roundtrips are verified via:

```bash
cargo test --package shared test_compat_fixtures
```


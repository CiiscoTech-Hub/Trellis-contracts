# Registry Contract Version Pinning and Deprecation Notice (#545)

## Overview

The Registry Contract Version Pinning and Deprecation Notice module (`shared::registry_pinning` and `contracts/registry-contract`) provides controlled lifecycle governance for Trellis contract discovery:

1. **Version Pinning**:
   - Allows pinning contract resolution for a given contract name to a specific historical version rather than always defaulting to the latest version.
   - Prevents unexpected breaking changes from auto-propagating to conservative consumers.
   - `unpin_version` cleanly restores dynamic latest-version resolution.
2. **Deprecation Notices & Sunset Decommissioning**:
   - `deprecate_contract`: Records a structured deprecation notice including announcement timestamp, future sunset deadline, and optional migration target address.
   - Automatic sunset enforcement: When `current_time >= sunset_at`, calls resolving the contract version are blocked with `ContractSunset`, failing closed against obsolete contracts.
   - `cancel_deprecation`: Allows administrators to roll back or postpone deprecation notices if migration schedules shift.
3. **Historical Version Queries**:
   - Every registered version is persisted under `(KEY_VER_REG, (name, version))` enabling $O(1)$ lookups of historical contract addresses.

## State Transitions

```text
Active (Unpinned / Dynamic Latest)
   │
   ├─► pin_version() ───────► Pinned (Specific Version)
   │                             │
   │                             └─► unpin_version() ──► Active (Dynamic Latest)
   │
   └─► deprecate_contract() ──► Deprecated (Grace Period)
                                 │
                                 ├─► cancel_deprecation() ──► Active
                                 │
                                 └─► current_time >= sunset_at ──► Sunset / Decommissioned
```

## Algorithmic Complexity

- **Time Complexity**: $O(1)$ lookup and state update operations.
- **Space Complexity**: $O(1)$ storage record per pin and deprecation notice.

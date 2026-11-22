# Input Size and Cardinality Limits (Issue #448)

Module: `shared/src/input_limits.rs`

Entry points call these before doing any work:

- `enforce_bytes(env, scope, &bytes)` returns `InputTooLarge` when the payload is over `max_bytes`
- `enforce_items(env, scope, count)` returns `TooManyItems` when there are more than `max_items`
- `enforce_cardinality(env, scope, &keys)` returns `CardinalityExceeded` when there are more than `max_distinct` distinct keys

Each `scope` (for example `batch` or `metadata`) has its own `InputLimitPolicy`.

## Defaults and ceilings

| | Default | Absolute maximum |
|---|---|---|
| `max_bytes` | 4096 | 65536 |
| `max_items` | 100 | 1000 |
| `max_distinct` | 100 | must be `<= max_items` |

A policy with a zero limit, or a limit above the ceilings, is rejected with `InvalidPolicy`.

## Paths

| Path | Behaviour |
|---|---|
| Normal | inputs at the limit pass; one over fails |
| Failure | the stable error codes above; nothing is written |
| Retry | `set_input_limits` with the same policy is a no-op |
| Authorization | only the admin can set or clear a policy (`Unauthorized`) |

## Edge cases

- Empty input always passes.
- The cardinality check runs `check_items` first. It then stops counting as soon as the distinct limit is exceeded, so an oversized input cannot force a full quadratic scan.
- Policies are per scope: tightening `batch` does not affect `meta`.

## Rollback

`clear_input_limits` removes a scope's policy, and that scope falls back to the defaults.

## Compatibility

Scopes without a stored policy use the defaults, so no migration is needed. Contracts opt in by calling `enforce_*`.

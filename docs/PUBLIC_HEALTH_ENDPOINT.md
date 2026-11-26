# Public dependency-aware health endpoint

`RegistryContract::health` is an unauthenticated, read-only health surface.
It returns the top-level public status, the bounded list of dependency health
records, and the current ledger sequence as a freshness marker. It never
returns error text, credentials, or internal logs.

Operators update the top-level status with `set_health_status` and record
dependency results with `report_dependency`. Both writes require the registry
admin. A `Down` or `Degraded` report increments the dependency failure count;
a `Healthy` report resets it. Clients should retry reads using normal Soroban
retry/backoff policy and treat `Unknown` or stale ledger markers as degraded,
not as healthy.

Recovery is additive: report the dependency as healthy, then publish
`Operational/Normal`. If a deployment must be rolled back, the previous
contract remains compatible because the new methods only add storage and
read/write entry points.

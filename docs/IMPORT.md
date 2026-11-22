# Import cancellation

Import batches expose a deterministic fingerprint before commit. Operators can
call `shared::cancel_import` with that fingerprint to place a durable,
authenticated cancellation marker. `execute_import` checks the marker before
writing any records and returns `ImportCancelled` when cancellation was
requested.

Cancellation is cooperative: a request racing with a commit that has already
started cannot roll back writes. For a safe retry, recompute the fingerprint
and run a dry-run first; the same cancelled fingerprint remains blocked until
the marker is removed by the contract's normal storage lifecycle.

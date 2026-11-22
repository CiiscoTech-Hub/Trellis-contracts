# Contract pagination and authorization

Aid owner and recipient listings use bounded pages and now require the address
being enumerated to authorize the request. Search pages require viewer
authorization and apply the existing visibility and delegated-access rules.
Cursor pages remain stable across inserts, removals, and permission changes:
callers resume strictly after the returned record ID and should continue until
`has_more` is false. Unauthorized queries fail before records are read.

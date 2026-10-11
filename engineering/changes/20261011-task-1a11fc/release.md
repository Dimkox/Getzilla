# Local delivery

Deliver the repair on fix/verify-control-env-20261011 through a pull request. Require exact-head public Actions and independent review before any conditional L5 merge. Do not tag or publish a new release for this repair task. Install the corrected source locally and rebuild the 2.2.1 archive only after local checks pass.

The parent full-scope policy and provider defaults remain unchanged. Go: full local gate, fresh review receipts, clean source and identical rebuild hashes. No-go: any failed mandatory check, stale source/report, or changed reviewed product.

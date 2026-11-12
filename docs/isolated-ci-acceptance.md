# Disposable component observations

The live entrypoints produce candidate test observations. They do not issue an independent attestation, activate hosted workflows, change branch protection, or grant production authority.

This implementation-only stage ships Factory/lifecycle support and Trust parser, binding and unavailable-producer refusal. The Trust suite producer is deferred to a separate source delivery. Both public and direct Trust entrypoints refuse its absence before external work. Real runtime acceptance remains OPEN.

`scripts/getzilla_live.py` selects the Factory, Trust CI, or lifecycle cell. Each invocation uses a new output directory and namespace. The invocation binds the committed source head and tree, run, attempt, cell, nonce and producer source digest. Component envelopes bind the exact suite or restart report and ownership journal bytes. The strict ownership journal remains `getzilla-disposable-owner-v1`.

The Factory cell requires a primary PostgreSQL17 cluster and an independently fresh cluster. Both use pinned images and owned internal networks with no host port. Preflight checks the original container and network identities, exact internal endpoint, login, database, PostgreSQL version and cluster identity before database access. Restart repeats the ownership check before waiting for PostgreSQL. The existing001..025 migration and result replay controls remain mandatory. Replaying a persisted result must not send a second POST.

The live suite entrypoint validates both owned endpoints before identity SQL or discovery. It requires distinct primary and fresh containers and cluster identifiers. Cluster verification uses read-only identity SQL before fixture or mutation SQL. Raw direct invocation of the legacy fresh-cluster test class still trusts its configured database URL; it does not establish live acceptance. That existing limitation remains OPEN.

Live suite results use `getzilla-live-suite-v1`. The recorder retains actual collected, started, executed, skipped and problem identities. `tests_run` counts started cases. Executed cases exclude skips. Empty discovery, loader errors, missing declared or required cases, source mutation, failed fixtures and required database skips refuse acceptance. The unit runner's database exemption cannot discharge a live obligation. Trust CI permits no skips.

The observer uses the native bounded process runner. It retains its2MiB capture limit, cancellation and typed cleanup facts. The observer remains outside the child process group. A missing journal, missing cleanup acknowledgement, unreadable cleanup fact or unconfirmed resource absence refuses success. Recovery can remove leaked resources; it cannot change a failed, timed out or cancelled primary result into success. Exported command logs redact database credentials. The digest covers retained native decoded capture, encoded as UTF-8 before redaction. The original undecoded stream and bytes beyond the native capture limit are unavailable.

The lifecycle cell requires100 actual complete cycles. It checks each owned container, volume, network and directory, protects concurrent resources and retained evidence, and measures payload bytes. It includes restart, failure, timeout, cancellation and abrupt-death cases. Native timeout cleanup has a bounded grace. If cleanup cannot acknowledge within that bound, the cell fails. Incomplete cycles, leaked resources or changed protected data refuse success.

The Trust CI fixtures remain source-only. A consumer installation can use installed Factory and lifecycle support. It must report an absent Trust CI source tree clearly when the Trust cell is selected. Consumer architecture, rules and adoption state remain target-owned.

No entrypoint pulls an image automatically. The operator must supply the exact pinned images and authorize any real runtime execution separately. Source controls use owned synthetic fixtures with child processes, Docker, PostgreSQL and network denied. Those controls prove source behavior only.

Real Docker/PostgreSQL/restart/100-cycle acceptance remains OPEN. Parent51, all149 bindings, raw20, both original specifications, Jira9, BMAD/operator/private acceptance and parent closure remain OPEN. P3c aggregation/export and hosted workflow activation are separate work. This source cut does not produce security-feed, image-acquisition, license, private-key, provider or deployment evidence.

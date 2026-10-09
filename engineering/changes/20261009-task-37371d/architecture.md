# Architecture

Current receipts bind coordinator HEAD but do not identify reviewer source. Fresh-agent bootstrap still selects predecessor continuation. Root causes: receipt envelope omits reviewed identity; current and historical documentation state are mixed.

Add a focused review-source validator consumed by receipt writing and evidence validation. It resolves exact commit/tree with safe bounded Git commands, verifies ancestry and report-only delta, and rejects unsafe or dirty candidate state. Keep receipt atomicity and existing spec/architecture/governance binding. CLI pass needs --reviewed-commit; failure observations keep compatibility. No OS isolation claim or new runtime service.

Update current Getzilla identity, release and continuation. Keep predecessor records and immutable artifacts. Align repository process delegation with AGENTS L5; production mutation remains a real-risk gate.

Governance: rederive existing canonical rules and node mappings with verifier; no deployed policy change. Risks: legacy passes become gaps, old tests require real review source fixtures, Windows Git paths and timeouts need coverage. Recovery: forward fix through new PR; never roll back security controls silently.

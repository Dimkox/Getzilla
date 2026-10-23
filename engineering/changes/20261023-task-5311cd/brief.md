# PR127 follow-up validation

PR127 merged at ea481a9 on 2026-10-22. Its owner override deferred local PostgreSQL verification and fresh reviews. This successor starts at main 8a02bab3d3e2a4e4cf8e023068a9652cbb89a5be.

The wheel fix in local dc3d66bc is superseded by ab3791a. The old checkpoint f6df5325 has no product repair. Preserve those commits; do not restore the stale inventory.

Repair the controller pidfd preflight gap. Run the deferred controls with system Python 3.12. Preserve process identity checks, audit V1/V2 contracts, dependency locks and production state. Status remains UNVERIFIED until current checks pass.

# Moved

Canonical log is /decisions.md. Do not append here.

The [2026-11-25 decision on license evidence for internal CI images (#456)](../decisions.md#2026-11-25--license-evidence-for-internal-ci-images-456) records the report-only scope. Redistributed outputs and shared layers retain strict checks.
## 2026-10-02 — Bind dormant dispatch rows with a composite foreign key

Redundant outbox identity is constrained to the immutable result source across repository, task,
run, fence, packet, attempt and envelope, so neither fixtures nor future enqueue code can create a
cross-authority handoff. Claim/start/record additionally revalidate live run authority.

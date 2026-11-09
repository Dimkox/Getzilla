# Inactive security checker bootstrap

This checkout contains an optional scanner library and CLI. It supplies checker
source bytes. It does not activate a workflow, admission check, GitHub App,
protection rule, deployed producer or trusted checker pin.

Run `python3 scripts/getzilla_security.py --help` to inspect the CLI. The checker
requires Python 3.11 or newer. Structural YAML inventory requires PyYAML; missing
capability remains a coverage gap. Acquisition needs explicit `--refresh` and a
current source/run input profile. A profile declares work; it is not evidence.
Importing the checker performs no network access or process execution.

`security_osv_snapshot.py` owns the strict snapshot contract used by the new
checker. It requires bounded validated inputs and acquisition evidence no older
than 72 hours. Malformed, stale, partial and substituted sources fail closed.
A failure before publication preserves the previous pointer and acquisition time.
A failure after pointer replacement reports uncertain durability. Reconcile that
state before any further publication; do not retry or claim a rollback.
Legacy `known_vulns.py`, `updater.py`, `scripts/getzilla_vulns.py` and their existing
consumers retain their current behavior. Their migration remains separate work.

Cargo coverage accepts default-registry lock entries and the exact local project
identity from its manifest. Git, path, workspace, alternate-registry and source
override forms remain unresolved gaps. The final report rejects contradictory
per-check bindings, incomplete sources and unresolved findings. Accepted OSV
exceptions, reviewed secret dispositions and informational EPSS/license records
retain their distinct meanings. These API checks add no authentication authority.

Artifact evidence distinguishes exact source, digest, platform/ABI and use/output
context. Extracted Factory output needs its actual archive, detached identity,
complete source-wheel composition and retained license/notice members. The six
approved licenses remain unchanged. The copied policy's approved Factory pins
differ from main's inputs; this remains `license-factory-profile-changed`.
Synthetic positive controls do not reanchor that project decision or establish
acceptance of the current real release. Missing or unsupported tool, Action,
image and source/output proofs retain their explicit gaps.

Local synthetic tests qualify source and refusal behavior only. They do not
establish successful live feed acquisition, legal approval, independent runner
qualification or complete Getzilla security acceptance. Choosing the reviewed
checker pin, deploying the independent producer/App, binding protection and
qualifying final merge-time admission remain owner steps. Required full local
verification, independent reviews and exact-head external checks still apply.

## Explicit public input preparation

The public CLI separates `--write-input-profile PATH` from `--prepare-inputs`.
The former reads source declarations and Git identities. It performs no scan or
acquisition. The latter requires `--input-profile PATH`; `--refresh` and
`--provision-tools` remain explicit. Both commands require named database,
artifact and tool roots. The profile binds exact candidate/checker commits and
trees, policy, inventory, GitHub repository/run/attempt, roots and finite limits.
It cannot authorize an operation or create an external attestation. A preparation
result says `prepared` or `unavailable`, never security PASS. Actual scans remain
the existing separate consumer. Missing required sources refuse.

Fixed-commit Actions use retained official commit/tree responses and complete
ZIP-to-Git blob/tree proofs. Release ZIPs need the exact source-owned digest,
platform and retained release metadata. OCI ZIP layouts bind one platform,
manifest/config, every compressed and uncompressed layer and complete component
file/license/notice graph. All three use one reader in evaluation and final
catalog binding. These are integrity contracts, not legal or publisher authority.
Opaque binaries without a qualified license/source adapter remain unavailable.
Vulnerability-only reports do not substitute for an image component graph.

Selected family descriptors can be published with the existing package owner
using `--family-records PATH` during preparation/refresh. The descriptor object
contains only schema_version=1, inventory_sha256 and records. Every referenced
artifact/proof must already exist under the explicit artifact root. This option
does not download or install a family or invent missing provenance. Package
refresh preserves verified family records and their original acquisition times.
The catalog timestamp cannot renew an older record. Freshness is inclusive at
259200 seconds; future or older sources refuse.

Existing bounds stay: 512 selected dependencies/family imports, 128 MiB artifact,
16 MiB index/report, 2 MiB selected metadata/license, 10000 archive members,
256 MiB expanded archive, and 512 MiB aggregate catalog. The existing process
runner supervises the explicit preparation CLI with a 600-second deadline and
its existing bounded group-stop/reap cleanup. Cleanup uncertainty refuses;
existing Core/CI limits do not increase. Images need exact finite count,
compressed/unpacked/storage/manifest/layer/time limits before transport selection.
The existing daemon pull cannot enforce these byte/storage ceilings, so image
acquisition currently refuses before tool/process selection. No descriptor
estimate or empty inventory can turn this into image qualification.

This earlier capability is **unactivated**. Own Linux, generated consumer CI and
their existing tests remain byte-exact to the accepted baseline. Proposed CI
activation is deferred until real inputs and missing adapters are qualified.
That later change must declare exact current inputs, require actual preparation
success and retain run/attempt-bound results. Unsupported snapshot platforms
must refuse; required Windows smoke is not seven-family qualification. The
baseline generated verifier still has its legacy OSV API selector. That selector
does not supply structured OSV/KEV/EPSS/catalog evidence. The standalone legacy
OSV API remains unchanged.
An unconfigured project, absent family proof or unsupported binary therefore
remains unavailable. Real input counts, hashes, ABI, findings, timing and cost
need a separately admitted data run. Synthetic source tests establish none of
those facts, and source delivery alone is not Gate/CI readiness.

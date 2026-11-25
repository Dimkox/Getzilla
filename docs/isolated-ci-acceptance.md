# Disposable component observations

The live entrypoints produce candidate test observations. They do not issue an independent attestation, activate hosted workflows, change branch protection, or grant production authority.

This source stage ships Factory/lifecycle support and a complete source-bound Trust suite producer with discovery, accounting, restart and cleanup observations. The hosted caller prepares a hash-locked wheelhouse before the offline Trust cell; missing or unapproved inputs refuse before resource allocation. Real runtime and operator acceptance remain OPEN.

`scripts/getzilla_live.py` selects the Factory, Trust CI, or lifecycle cell. Each invocation uses a new output directory and namespace. The invocation binds the committed source head and tree, run, attempt, cell, nonce and producer source digest. Component envelopes bind the exact suite or restart report and ownership journal bytes. The strict ownership journal remains `getzilla-disposable-owner-v1`.

The Factory cell requires a primary PostgreSQL17 cluster and an independently fresh cluster. Both use pinned images and owned internal networks with no host port. Preflight checks the original container and network identities, exact internal endpoint, login, database, PostgreSQL version and cluster identity before database access. Restart repeats the ownership check before waiting for PostgreSQL. The existing001..025 migration and result replay controls remain mandatory. Replaying a persisted result must not send a second POST.

The live suite entrypoint validates both owned endpoints before identity SQL or discovery. It requires distinct primary and fresh containers and cluster identifiers. Cluster verification uses read-only identity SQL before fixture or mutation SQL. Raw direct invocation of the legacy fresh-cluster test class still trusts its configured database URL; it does not establish live acceptance. That existing limitation remains OPEN.

Live suite results use `getzilla-live-suite-v1`. The recorder retains actual collected, started, executed, skipped and problem identities. `tests_run` counts started cases. Executed cases exclude skips. Empty discovery, loader errors, missing declared or required cases, source mutation, failed fixtures and required database skips refuse acceptance. The unit runner's database exemption cannot discharge a live obligation. Trust CI permits no skips.

Only the exact source-owned complementary PDF parser cases can be inapplicable. The unchanged canonical skip policy uses fresh isolated dependency observations from the same interpreter before discovery, after discovery, after execution and at final consumption. The imported module must return matching discovery and final facts. Policy/source/interpreter/reason mismatches, stale or unknown observations and caller-provided allowance JSON refuse acceptance. A required parser profile cannot become optional. All expected and started cases remain visible; executed, skipped, inapplicable and required identities remain separate. Every database case stays required.

The outer Factory controller owns its private environment through final same-interpreter validation. A report never selects the interpreter or cleanup path. After confirmed child exit, the controller captures the environment into a new private anchor with atomic no-replace rename. It compares the opened capture with the retained original birth before traversing the original descriptor. PASS requires the original descriptor to report zero links, confirmed anchor removal and no replacement at the original public name. Wrong captures remain intact. Uncertain identity or removal fails. The anchor name remains private to the controller; reports contain identity and outcome facts only. The default non-live runner keeps its existing cleanup behavior.

This source stage treats the new anchor as a trusted workflow boundary with no legitimate concurrent writer. It does not provide hostile same-user operating-system isolation. A forced swap inside that anchor at the final directory-removal primitive can remove an empty replacement while retaining the original. The owned limitation control preserves that observation: cleanup returns unknown and blocks PASS. Preservation against arbitrary mutation inside the trusted anchor remains UNPROVEN and OPEN in the parent scope. A lost child, changed directory, cleanup failure or cancellation cannot be masked by a passing suite report.

The observer uses the native bounded process runner. It retains its2MiB capture limit, cancellation and typed cleanup facts. The observer remains outside the child process group. A missing journal, missing cleanup acknowledgement, unreadable cleanup fact or unconfirmed resource absence refuses success. Recovery can remove leaked resources; it cannot change a failed, timed out or cancelled primary result into success. Exported command logs redact database credentials. The digest covers retained native decoded capture, encoded as UTF-8 before redaction. The original undecoded stream and bytes beyond the native capture limit are unavailable.

The lifecycle cell requires100 actual complete cycles. It checks each owned container, volume, network and directory, protects concurrent resources and retained evidence, and measures payload bytes. It includes restart, failure, timeout, cancellation and abrupt-death cases. Native timeout cleanup has a bounded grace. If cleanup cannot acknowledge within that bound, the cell fails. Incomplete cycles, leaked resources or changed protected data refuse success.

The Trust CI fixtures remain source-only. A consumer installation can use installed Factory and lifecycle support. It must report an absent Trust CI source tree clearly when the Trust cell is selected. Consumer architecture, rules and adoption state remain target-owned.

No entrypoint pulls an image automatically. The operator must supply the exact pinned images and authorize any real runtime execution separately. Source controls use owned synthetic fixtures with child processes, Docker, PostgreSQL and network denied. Those controls prove source behavior only.

Real Docker/PostgreSQL/restart/100-cycle acceptance remains OPEN. Parent51, all149 bindings, raw20, both original specifications, Jira9, BMAD/operator/private acceptance and parent closure remain OPEN. P3c aggregation/export and hosted workflow activation are separate work. This source cut does not produce security-feed, image-acquisition, license, private-key, provider or deployment evidence.


## Earlier parent318 contract and retained obligations

The complete earlier parent contract follows. Current source-bound reports and owned cleanup extend this contract; older report wire details are historical and do not grant acceptance.

# Isolated acceptance for public Getzilla

The existing required GitHub check `linux` aggregates `linux-core`, `linux-core-tests`, and the three
`live-acceptance` matrix cells. Each must succeed. The independent
`security-expanded` job publishes an informational report.
Missing evidence, cancellation, timeout, an unexpected skip, a different source
commit or run attempt, and unconfirmed cleanup block this check. The required
`windows` name and the macOS workflow remain in place. This change does not edit
repository protection settings.

## Commands and scope

Run these commands from the Getzilla source repository. A local invocation is an
observation; it does not replace the exact-source external checks.

```sh
uv run --locked --project factory python .getzilla/getzilla/factory_tests.py --root .
python scripts/getzilla_live.py --cell factory --output .getzilla/runtime/live/factory-run --timeout-seconds 1500
python scripts/getzilla_live.py --cell trust-ci --output .getzilla/runtime/live/trust-ci-run --timeout-seconds 1200
python scripts/getzilla_live.py --cell lifecycle --output .getzilla/runtime/live/lifecycle-run --timeout-seconds 900
```

Use a new output directory for each run. The hosted Linux jobs use Ubuntu 24.04, the supported native adapter profile.
Linux, Docker, and the pinned component
images are required for live acceptance. The harness can pull the exact image
digests in `.getzilla/config/ci-images.json` and checks their configuration IDs.
It does not use an existing PostgreSQL instance or an ambient database URL.

Factory unit mode collects every `factory/tests/test_*.py` module. It removes
database/container environment bindings before importing tests. It records IDs,
failures, and skips. Empty and entirely skipped suites fail. Database-dependent
unit skips retain a live obligation. The required cleanup and fixture-reset
unit classes must execute.

The Factory live cell creates two disposable PostgreSQL clusters. The ordinary
cluster runs full Factory discovery and the actual two-restart recovery probe.
The separate empty cluster runs the historical migration-014 setup, unsafe-role
rollback, and least-privilege migration test against the current migration
inventory. The restart probe still models its workspace broker; it does not
claim to test live Factory workspace cleanup.

The Trust CI cell uses pinned PostgreSQL and Python images. A disposable volume
holds dependencies installed with `pip --require-hashes` before the private
database network is created. The test container uses read-only source mounts and
an internal network. It runs the existing PostgreSQL integration suite, seeds a
synthetic job, restarts the bound database, and verifies persistence in the same
cluster. Both historical shell entrypoints delegate to this complete cell. This
tests the component code; it does not build `Dockerfile.test`, deploy Trust CI,
activate a GitHub App, or issue an external attestation.

The lifecycle cell performs 100 real container, volume, network, and bounded
payload-directory cycles. Ninety-five ordinary cycles include periodic process
restart. The last five exercise verifier SIGINT, verifier SIGTERM, a deliberate
test failure, a timeout, and abrupt child death with a new recovery process. A
second active resource set and retained evidence survive each cycle unchanged.
Each row records its resource identities, measured payload sizes, primary result,
cleanup result, and return to the disposable resource baseline. This scope does
not close the separate Git/worktree, remote-asset, or universal disk-retention
requirements of issue #168.

## Cleanup and cancellation

The harness writes an ownership intent before allocation and binds it to live
Docker IDs, labels, image IDs, mounts, and allocator process birth identity.
Deletion rechecks the live identity. A successful independent resource listing
must confirm absence. The harness does not prune Docker globally or delete by a
name prefix. A recovery process refuses a still-live allocator.

The outer observer runs outside its child's process group. Verifier cancellation
allows a bounded acknowledgement period. A child cleanup failure remains a
failure; observer rescue is recorded separately and does not turn a failed cell
into success. Cleanup has a shared deadline, including when the Docker daemon is
unavailable. CI reserves five minutes for cleanup and evidence before its job
deadline. Loss of the observer or hosted VM leaves cleanup unknown. A missing
artifact cannot satisfy the required check.

## Security checker bootstrap and trust boundary

The security job checks out candidate source as data and checks out its scanner
separately. `GETZILLA_SECURITY_CHECKER_SHA`, an operator-controlled repository
variable, selects an exact reviewed checker commit. Without the variable, the
job uses the PR base commit, or the push's preceding commit. A missing scanner at
that ref is **BLOCKED**, including the first implementation PR. There is no
candidate-scanner fallback or green bootstrap placeholder.

The scanner uses trusted quality-tool requirements and its pinned scanner
provisioning. The informational job checks its security families,
structural inventory-bound non-applicability, candidate/checker Git identities,
and the report's shortest validity bound. Evidence age from 0 through 72 hours
is admitted; older evidence fails. Failure to acquire or verify a required tool,
feed, or artifact is not non-applicability.

An ordinary PR workflow can itself be edited by the candidate. Separate scanner
checkout and a JSON aggregator do not establish independent workflow authority.
That rollout boundary needs a separately reviewed checker reference and the
operator's trusted workflow controls. Reports retain this limitation and never
promote local input-integrity observations into independent attestation.

## Evidence and qualification

Artifacts retain exact source HEAD/tree, base/event/workflow identities, run and
attempt, test IDs, separate primary/cleanup outcomes, and file hashes for 30
days. Exports select bounded observation files and omit runtime approvals and
credentials. PR source HEAD is distinct from GitHub's test merge event SHA.

Docker-free controls and process-signal probes can validate orchestration locally.
Only a completed real Docker/GitHub Actions run qualifies the live acceptance
claims. A green unit test or boundary double is never recorded as Docker proof.

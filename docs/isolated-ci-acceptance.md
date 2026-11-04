# Isolated acceptance for public Getzilla

The existing required GitHub check `linux` aggregates `linux-core`, the three
`live-acceptance` matrix cells, and `security-expanded`. Every job must succeed.
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
provisioning. The aggregate checks all eleven required security families,
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

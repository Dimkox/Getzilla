# Producer preparation: UNVERIFIED

Date: 2026-10-21. Route: `4667515abad1`. Writer: `ai_implementer`.

This is a source preparation checkpoint. It does not qualify phase 2, a release, or a merge. Core integration, committed controls, independent reviews, the final local gate and external exact-head checks remain pending.

After the initial producer commit, Core architecture fitness found that `FIT-SIGNED-PAYLOAD-EXACT` forbids adding argv to the signed v1 contract. The architect approved a separate v2 contract. The correction is committed below. The initial optional-v1 design and its focused evidence are historical preparation only. The v1 contract remains unchanged.

## Source identity and inventory

- Trusted initial base and initial HEAD: `e158ddc7263a55f5308944c5a426eb1e9f1a4327`.
- Initial producer commit: `2b77dfa8373c1e156954ad9d7c067054c1924b67`; tree `9edcaa1eef8dbd555783bdf895931ae0b2d9b5d8`.
- Corrected v2 producer commit: `eb6e6a9eb87ae7d6bc633d17f93e37a404c05623`; tree `6de2d2dd87436e9d8a9c9904619f94bd81aafd6c`.
- Branch: `feat/eu-ai-act-trustci-20261021`.
- Worktree: `/home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-trustci`.
- Initial tracked staged and unstaged inventories were empty. Only this package was untracked.
- Product changed paths: `trust-ci/README.md`; `trust-ci/config/eu-ai-act-audit.command.example.json`; `trust-ci/src/adaptive_trust_ci/models.py`, `policy.py`, `runner.py`; `trust-ci/tests/test_api.py`, `test_policy.py`, `test_runner.py`, `test_signing.py`.
- Workflow changes are confined to `engineering/changes/20261021-task-466751/`.
- After the producer commit, `git status --porcelain=v1 --untracked-files=all` returned no entries.

The observations below identify the source stage they cover. This report is a later documentation change. No fingerprint-bound verification or review receipt exists. The final scope selector has not run; no skipped check is claimed as passed or reused.

## Initial test-first observations at 2b77dfa

Tests preceded the product implementation. The first test invocation failed to collect because `_support` was absent from the Python path. A relative pytest `pythonpath` override also resolved against the Trust CI root. Absolute paths fixed collection without source changes. A handwritten 13-character check-name expectation was corrected to the actual 12-character prefix before the final RED run.

Final RED command, from the worktree above:

```sh
taskset -c 20-25 python3 -m pytest -q -n 6 -p no:cacheprovider -o 'pythonpath=/home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-trustci/trust-ci/src /home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-trustci/trust-ci/tests' --tb=short trust-ci/tests/test_policy.py trust-ci/tests/test_runner.py trust-ci/tests/test_signing.py
```

Observed before implementation: `51 failed, 87 passed, 32 subtests passed in 4.79s`, exit 1. Pytest counts failed subtests separately. Failures covered missing optional fields, absent strict validation and reserved-environment checks, absent argument stamping and the missing fragment. Existing tests and synthetic-result characterization passed.

The same command after the minimal implementation returned `92 passed, 78 subtests passed in 1.81s`, exit 0.

Final focused command includes the API preservation characterization:

```sh
taskset -c 20-25 python3 -m pytest -q -n 6 -p no:cacheprovider -o 'pythonpath=/home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-trustci/trust-ci/src /home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-trustci/trust-ci/tests' --tb=short trust-ci/tests/test_policy.py trust-ci/tests/test_runner.py trust-ci/tests/test_signing.py trust-ci/tests/test_api.py
```

Observed: `114 passed, 80 subtests passed in 4.95s`, exit 0.

```sh
python3 -m ruff check --no-cache trust-ci/src/adaptive_trust_ci/policy.py trust-ci/src/adaptive_trust_ci/models.py trust-ci/src/adaptive_trust_ci/runner.py trust-ci/tests/test_policy.py trust-ci/tests/test_runner.py trust-ci/tests/test_signing.py trust-ci/tests/test_api.py
git diff --check
```

Observed: `All checks passed!`, exit 0; diff check returned no output, exit 0. These are bounded development observations, not a qualifying local gate.

## V2 correction observations at eb6e6a9

New regression tests preceded the v2 correction. The RED command was:

```sh
taskset -c 20-25 python3 -m pytest -q -n 6 -p no:cacheprovider -o 'pythonpath=/home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-trustci/trust-ci/src /home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-trustci/trust-ci/tests' --tb=line trust-ci/tests/test_signing.py trust-ci/tests/test_runner.py trust-ci/tests/test_api.py
```

Observed before implementation: `25 failed, 68 passed, 17 subtests passed in 1.82s`, exit 1. Failures showed that v2 was unsupported, boolean/float v1 versions were accepted, metadata presence was not strict for v2, and opted-in runners emitted v1.

After the correction, the focused suite returned `120 passed, 105 subtests passed in 1.89s`. A rollback characterization then verified that disabling opt-in returns future jobs to v1 while stored v2 envelopes remain valid. The final command was:

```sh
taskset -c 20-25 python3 -m pytest -q -n 6 -p no:cacheprovider -o 'pythonpath=/home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-trustci/trust-ci/src /home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-trustci/trust-ci/tests' --tb=short trust-ci/tests/test_policy.py trust-ci/tests/test_signing.py trust-ci/tests/test_runner.py trust-ci/tests/test_api.py
```

Observed: `121 passed, 105 subtests passed in 2.18s`, exit 0. Product bytes are those in `eb6e6a9eb87ae7d6bc633d17f93e37a404c05623`.

```sh
python3 -m ruff check --no-cache trust-ci/src/adaptive_trust_ci/policy.py trust-ci/src/adaptive_trust_ci/models.py trust-ci/src/adaptive_trust_ci/runner.py trust-ci/tests/test_policy.py trust-ci/tests/test_signing.py trust-ci/tests/test_runner.py trust-ci/tests/test_api.py
git diff --check
```

Observed: `All checks passed!`, exit 0; diff check returned no output, exit 0. No code changed after these observations before the corrected source commit.

## V2 exit-code boundary correction at ce231e3

Source commit: `ce231e3d877d0dbd620c1ffa7daee0af0effd3be`. Source tree: `09a449ff62bbb1d8bda366d323b7b4880be8b560`. The trusted comparison base remains `e158ddc7263a55f5308944c5a426eb1e9f1a4327`. The worktree was clean after this source commit. These focused observations do not qualify the branch for merge.

Inspection found that the model and verification CLI preserve raw command-result types. They do not convert a signed boolean or float exit code to integer zero. However, the v2 reader accepted those invalid exit codes. The v2 branch now requires an actual integer for each command result's `exit_code`. V1 parsing and exact signed-envelope replay remain unchanged. No CLI, API or storage implementation changed.

Regression tests preceded the repair. The RED command was:

```sh
taskset -c 22-25 python3 -m pytest -q -n 4 -p no:cacheprovider -o 'pythonpath=/home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-trustci/trust-ci/src /home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-trustci/trust-ci/tests' --tb=line trust-ci/tests/test_signing.py -k 'non_integer'
```

Observed: `9 failed, 1 passed, 3 subtests passed in 1.15s`, exit 1. The failures showed that invalid v2 exit-code types passed verification. The regression covers booleans, floats, strings, null and a missing field. A signed-envelope CLI test also checks invalid versions, rejection without JSON output, valid integer v2 output, and exact preservation of legacy v1 boolean and float values.

The final focused command was:

```sh
taskset -c 22-25 python3 -m pytest -q -n 4 -p no:cacheprovider -o 'pythonpath=/home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-trustci/trust-ci/src /home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-trustci/trust-ci/tests' --tb=short trust-ci/tests/test_policy.py trust-ci/tests/test_signing.py trust-ci/tests/test_runner.py trust-ci/tests/test_api.py
```

Observed: `123 passed, 119 subtests passed in 1.80s`, exit 0. The tests used ephemeral test attestation signing material. No human approval key or deployed key was used.

```sh
python3 -m ruff check --no-cache trust-ci/src/adaptive_trust_ci/models.py trust-ci/tests/test_signing.py
git diff --check
```

Observed: `All checks passed!`, exit 0; diff check returned no output, exit 0. Product bytes did not change after these checks. All test and lint processes ended, and the four-worker allocation was released to the coordinator. Joined Core integration, independent reviews and final gates remain pending. Status remains **UNVERIFIED**.

## Behavior covered

- Omitted/false flags keep the fixture digest `198a4655a16ba7fb36cfe4729e110127860b97286a12aa43f41e91ecf7a7750d` and its legacy check name.
- The unchanged shipped example catalog digest remains `c23bab5c5881cf4254e1587cebf7a14ec0a9b599d048d6a1c82b77d29fd95b04`.
- Strict booleans, isolated profile epochs, mandatory explicit audit fragment and reserved `TRUST_CI_*` environment rejection work as specified.
- Selected policy argv replaces forged executor argv on successful and failed commands. Default commands discard forged argv. Stdout cannot set argument evidence.
- Synthetic holdout, spec-metadata and source-integrity results omit argv.
- Signed argv tampering fails. Exact stored envelopes survive runner retries and repeated authenticated API reads. Committed legacy golden envelopes remain unchanged.
- Explicit v2 requires both metadata keys and permits a null spec digest. V2 argv has 1 to 128 nonempty strings of at most 4096 characters each. Boolean, string, float and unknown versions fail.
- Any selected repository or holdout opt-in emits v2, including synthetic failures before command execution. Default and disabled profiles emit v1. Version tampering fails signature checks. Raw signed v1 argv remains v1 and cannot upgrade its contract version.

## Pending dependency and delivery

Core/schema must merge before this producer's final qualification. Rebase onto the actual agreed merged base, record both base identities, then add and run a real signed audit integration case. Execute enabled, disabled and absent EU opt-in input through real Core and the installed trusted verifier outside the candidate. Include v2 tampering, rejection of legacy v1 for EU authority, repeated authenticated GET and replay without command re-execution. Use only ephemeral test attestation signing material. Current runner tests use a stub executor and do not prove Core audit execution or joined consumer qualification.

The complete Trust CI suite, PostgreSQL integration, committed-HEAD controls, route reviews, mutation probes, final local PR verifier and external checks have not run for this candidate. The coordinator owns those later stages. State remains `implementing`. Production approval remains pending and out of scope.

## Decisions and mistakes for handoff

Decision: omit false/absent optional fields to preserve legacy identities; fixed baseline digests proved this worked. Decision: stamp argv in the runner to keep the sandbox, signing, API and stores unchanged. Decision: restrict environment override rejection to opted-in profiles to preserve unrelated legacy behavior.

Mistake: the initial pytest command omitted the Trust CI test import path, and the first correction used paths relative to the wrong pytest root. Use absolute pytest `pythonpath` entries in this nested worktree. A separate read-only inline Python digest probe hit the hook's ambiguous-root parser; one rewrite to a named canonical scratch script succeeded.

Mistake: the initial design treated an optional signed field as compatible with the closed v1 contract. Architecture fitness correctly rejected it. Use an explicit contract version before changing signed payload fields; keep old readers and replay rules exact.

## Rollback and residual risk

This branch does not deploy policy or emit production attestations. After separately approved deployment, disable argv opt-in to return future emissions to v1. Keep the dual reader for stored v2 envelopes and stop new v2 emission before rolling consumers back. Preserve signed envelopes; do not backfill or rewrite them. No database migration or recovery is needed.

Arguments become durable evidence and can expose secrets if an operator includes them. V1-only consumers reject v2. Signed invocation proves command execution and status; it does not prove legal conformity, published transparency effectiveness, or release readiness.

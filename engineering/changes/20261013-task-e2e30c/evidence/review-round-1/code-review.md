# Code review: FAIL

- **High — task-grant bypass through shell selection.** `.getzilla/getzilla/execution_admission.py:59` checks the command but ignores the native `shell` argument. A safe command with a caller-selected executable receives `allow`. The executable can write files without a task grant. A full hook probe confirmed this with a harmless marker. Validate the complete native execution envelope before applying the observation exception. Add a regression test.
- **High — task-grant bypass through Git configuration.** `.getzilla/getzilla/execution_admission.py:70` admits Git diff without suppressing configured external diff drivers. The option blacklist does not prevent `diff.external` from running. A full hook probe admitted the command and the configured scratch driver wrote a marker. Require a constrained Git execution form that disables executable extensions. Test configuration-driven execution, not only explicit command options.

Source: `/home/pall/projects/getzilla/.getzilla/runtime/worktrees/all-issues-20261013`. Route `e2e30c9f2878` selects `code_reviewer`. Comparison base `540c12f93e798c2f483455a5086ab0018ac3216e`. HEAD before/after: `f995a5ab35a26abf967516fffccfbf1b3ba42063`. Git tree before/after: `8ed90be2368af8abc653beba10c38c057bd6d7b3`. Candidate fingerprint before/after: `c8edeebeaab9ec8764de395fb176a896ff281c57711460854ce66b61f4dc8dbe`. Staged, unstaged and untracked inventory: empty.

Scratch: `/home/pall/projects/getzilla/.getzilla/runtime/reviews/all-issues-f995a5a/code`; private parent mode `0700`, with trusted non-sticky ancestors. `candidate/` is a private Git clone at the exact HEAD. File content and mode manifest matched after correcting clone-created permission differences. Manifest before/after: `bb8cc0baf4ffc900077c2d68d89b2611a4e8bb509c4527e5811cdde405cf41ae`. No probe ran before snapshot validation. Capacity was recorded first in `capacity.json`: 14 physical cores, 28 online CPUs, effective cpuset 0–27, unlimited applicable quota, successful child affinity 0–5. Tests used this six-CPU allocation and at most two workers.

reviewed-tree-modified: no

Executed commands from private `candidate/`:

```text
taskset -c 0-5 env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.getzilla:factory/src python3 -m unittest tests.test_task_execution_admission tests.test_execution_admission factory.tests.test_paid_admission -q
```

Observed: 41 tests, OK. These cover exact task grants, mandatory hook denial, paid admission and replay.

```text
taskset -c 0-5 env PYTHONDONTWRITEBYTECODE=1 TMPDIR=/home/pall/projects/getzilla/.getzilla/runtime/reviews/all-issues-f995a5a/code PYTHONPATH=.getzilla:factory/src python3 -m unittest tests.test_fsx tests.test_trust_ci_locks tests.test_installer.InstallerTests.test_materialize_new_publishes_verified_payload_once tests.test_installer.InstallerTests.test_existing_target_modes_are_read_only -q
```

Observed: 21 tests, OK, two Windows-only tests skipped.

```text
taskset -c 0-5 env PYTHONDONTWRITEBYTECODE=1 TMPDIR=/home/pall/projects/getzilla/.getzilla/runtime/reviews/all-issues-f995a5a/code python3 /home/pall/projects/getzilla/.getzilla/runtime/reviews/all-issues-f995a5a/code/probe_observation.py
```

Observed for both findings: hook exit 0, decision `allow`, marker write `True`. This local probe creates only disposable repositories and harmless scripts. It does not claim native host interception.

Mutation claims and results: each baseline passed. Commands below ran in private `candidate/`, with `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH=.getzilla:factory/src` and `TMPDIR` set to the private scratch parent. Exact mutations, commands and full observed outputs are retained in `mutations.json`; the driver is `mutations.py`.

| Claim and mutation | Exact command | Outcome |
|---|---|---|
| One-shot grants: remove consumed-resource rejection | `taskset -c 0-5 python3 -m unittest tests.test_task_execution_admission.TaskExecutionAdmissionTests.test_exact_task_action_is_one_shot -q` | Killed: second admission returned True; assertion failed. |
| Paid replay: disable duplicate-reservation rejection | `taskset -c 0-5 python3 -m unittest factory.tests.test_paid_admission.PaidAdmissionTests.test_duplicate_does_not_resend_and_survives_restart -q` | Killed: SQLite UNIQUE rejected duplicate; expected domain error was lost. This proves error-contract detection, not a second network send. |
| Mandatory hook: change outer exception denial to allow | `taskset -c 0-5 python3 -m unittest tests.test_execution_admission.MandatoryHookTests.test_outer_exception_rejects -q` | Killed: observed allow instead of deny. |
| Shared budget: remove aggregate inflight check | `taskset -c 0-5 python3 -m unittest factory.tests.test_paid_admission.PaidAdmissionTests.test_race_one_shared_inflight_slot_across_tasks -q` | Killed: two reservations admitted for one slot. |

No mutants survived. The two real bypasses remain findings. Static inspection covered surrounding hooks, installer preservation, filesystem revalidation, paid store transactions, transport dispatch and lock closure logic. Those static claims are unexecuted beyond the named tests. Native harness loading, deployed policy, production credentials, live paid calls, Windows filesystem behavior and the full qualifying gate were not executed. They need separate evidence. Generated-launcher observations do not establish native host enforcement. Filesystem revalidation still does not lock the namespace against a rename after its last check, as the implementation states.

Return both findings to the single write owner. Repeat bounded controls and independent reviews on the repaired commit.

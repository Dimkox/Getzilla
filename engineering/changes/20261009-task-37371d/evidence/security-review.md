# Security review — repaired candidate

Verdict: PASS for local security review. No blocking findings. This fresh report replaces the older report as source-review evidence; historical reports do not qualify this candidate.

- Exact commit format, ancestry, clean Git inventory, safe report reads and six conventional report names fail closed. Receipt consumers rederive the binding and reject forged or missing identities.
- Published installer tests now use observed publication identity separately from candidate VERSION. They reject malformed provenance and changed installer bytes and retain digest checks before execution. Installer scripts are unchanged across base..HEAD; README and QUICKSTART are unchanged by the repair.
- No new duplicate external mutation path was found. Manual overrides remain UNVERIFIED until deferred checks run. Conditional L5 consent does not bypass external checks, production consent or the human private-key boundary.
- Low-severity follow-up #73 stays deferred. No new blocker was found in this review.

Exact candidate identity before and after:

- Base: `5d5b45f42f8a9f2bc0303b4d16b5d4e54caad5b9`
- HEAD: `3e59aa153e4eb0c2d1b71e5b55d723d14949ac9b`
- Tree: `08c67e409236086b4e890384071876b464a48073`
- Fingerprint: `70b24e2556958d779dda0131a90368abe7b2f50247223fc35fb4af99853d105a`
- Status: clean.

Scratch: `/home/pall/getzilla-session/security-repaired-scratch/candidate`. Its reviewer-owned non-sticky parent and scratch root have mode `0700`. A local `--no-hardlinks` clone at exact detached HEAD reproduced the candidate tree and fingerprint. Probes ran sequentially on CPUs8-11 with one worker. Capacity was remeasured: 14 physical cores, 28 online logical CPUs, effective cpuset0-27, no finite ancestor quota, successful child-only affinity probe; capacity28.

Fresh executed commands and outcomes:

```text
taskset -c 8-11 env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_review_source tests.test_install_scripts.InstallScriptContractTests tests.test_project_state -q
46 tests; OK in11.943s.

taskset -c 8-11 env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_review_source.ReviewSourceTests.test_consumption_rejects_missing_and_forged_binding -q
Consumer-rederivation mutant: KILLED; three failures for forged tree, commit and digest.
Same command after scratch restoration: 1 test; OK in3.526s.

taskset -c 8-11 env PYTHONDONTWRITEBYTECODE=1 python3 /home/pall/getzilla-session/security-repaired-scratch/race_probe.py
1 test; OK. Changed second source binding refused publication; no review receipt appeared.
```

The 46-test control covers unsafe revisions and paths, ancestry, dirty/staged/untracked states, executable/symlink evidence, report-only admission, forged consumer bindings and installer provenance rejection without Git history.

Limits: no native Windows execution, real concurrent filesystem stress, deployed production validation or external exact-head check. Race checks are bounded observations and do not provide OS-enforced isolation or eliminate every publication window. Policy and delegation prose received static review only. Local review is not merge authority.

reviewed-tree-modified: no

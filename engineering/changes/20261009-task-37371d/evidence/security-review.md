# Security review

Verdict: PASS for local security review. No blocking findings.

- Exact SHA validation and bounded Git helpers reject unsafe revisions.
- Ancestry, clean status, Git modes, safe file reads and six exact report names restrict saved-report admission.
- Receipt consumption rederives source bindings. Missing or forged bindings become evidence gaps.
- Manual overrides retain UNVERIFIED status and cannot replace external checks or human approvals. Conditional L5 consent and the human private-key boundary remain intact.
- No new external mutation path or duplicate external write was found.

Source identity before and after:

- HEAD: `c6bbfa86b3d3177b0b66993ceaf3f092b6e6cbfa`
- Tree: `9950552a6d088e518ea5db688659808ce271e4b7`
- Fingerprint: `7fc6376f1514f3be3cc0cca905b6fe65d9d857c5a7af15dba87cf849dfa4a0ad`
- Git status: clean.

Scratch: `/home/pall/getzilla-session/security-review-scratch/candidate`. Reviewer-owned parent and scratch have mode `0700`; parent is non-sticky. Local clone used `--no-hardlinks` and exact detached HEAD. Its initial tree and fingerprint matched the candidate.

Executed probes, with CPUs `8-11`, one worker:

```text
taskset -c 8-11 env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_review_source tests.test_change_receipts
44 tests; OK.

taskset -c 8-11 env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_review_source
14 tests; OK after scratch restoration.

taskset -c 8-11 env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_review_source.ReviewSourceTests.test_consumption_rejects_missing_and_forged_binding
Consumer rederivation mutant: killed; three assertion failures.

taskset -c 8-11 env PYTHONDONTWRITEBYTECODE=1 python3 /home/pall/getzilla-session/security-review-scratch/race_probe.py
1 test; OK. Changed second source binding refused publication; no review receipt appeared.
```

The first control process overlapped the scratch mutation after importing its modules. The restored 14-test run provides uncontaminated admission evidence.

Limits: no native Windows execution, real concurrent filesystem stress, deployed production validation or external exact-head check. Before/after checks do not provide OS-enforced isolation or eliminate all concurrent publication windows. Local review grants no merge authority.

reviewed-tree-modified: no

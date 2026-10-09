# Security review — denial-rule repair

Verdict: PASS for local security review. No blocking findings. Final local and external gates remain pending; earlier reports are historical.

- The canonical delivery skill now contains all five tool-denial clauses. The Grok, Claude, Gemini and Qwen mirrors retain those clauses. The binding test checks canonical and Grok delivery for denial refusal, one rewrite and exact protected targets. Static review confirms same-objective blocking and fingerprint rules.
- Full base..HEAD review retains exact commit admission, ancestry, clean inventory, six report names in supported namespaces, safe reads and consumer rederivation. Missing-package fallback remains limited to low-risk micro routes; unsafe metadata fails closed.
- Grok generation owns only `.grok/skills`; hooks and agents remain canonical. No new duplicate external mutation path was found. Manual overrides remain UNVERIFIED and conditional L5 grants do not bypass external checks or the human private-key boundary. Low follow-up #73 remains deferred. Source2.2.1 is not published.

Candidate identity before and after:

- Base: `5d5b45f42f8a9f2bc0303b4d16b5d4e54caad5b9`
- HEAD: `1870996cb987dabff915639d2e2104600fa1cd4b`
- Tree: `88f91d423658a56450aab4de70c26110dcfd3eb4`
- Fingerprint: `d205977d7a1b94ff2938fc6972c23581edf5b68b75031ca4c289976c0d635c1f`
- Status: clean.

Scratch: `/home/pall/getzilla-session/security-breaker-scratch/candidate`. Reviewer-owned scratch root and non-sticky parent have mode `0700`. Local clone used `--no-hardlinks` and exact detached HEAD. Initial and restored scratch fingerprints matched the candidate. Capacity was remeasured: physical14, logical28, cpuset0-27, unlimited applicable ancestor quotas, successful child-only affinity probe; capacity28. Probes used CPUs8-11 and one worker, sequentially.

Fresh commands and output:

```text
taskset -c 8-11 env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_review_source tests.test_delivery_sequence -q
23 tests; OK in13.011s.

taskset -c 8-11 env PYTHONDONTWRITEBYTECODE=1 python3 /home/pall/getzilla-session/security-breaker-scratch/mutation_probe.py
Durable guard mutant: KILLED, one assertion failure.
Report-name namespace mutant: KILLED, one assertion failure.
Consumer rederivation mutant: KILLED, three forged-binding failures.
```

The runner restored each scratch file before the next probe and invoked these exact named commands:

```text
taskset -c 8-11 env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_review_source.ReviewSourceTests.test_missing_durable_or_malformed_selected_package_fails_closed -q
taskset -c 8-11 env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_review_source.ReviewSourceTests.test_index_and_analysis_cannot_be_supplied_as_review_report -q
taskset -c 8-11 env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_review_source.ReviewSourceTests.test_consumption_rejects_missing_and_forged_binding -q
```

Restored scratch status was clean and its fingerprint matched. No candidate artifacts were created.

Limits: no native Windows execution, concurrent filesystem stress, production validation or external exact-head check. Policy prose received static review; tests cannot prove agent compliance. No broad unrelated suite or new publication claim was made. Local review is not merge authority.

reviewed-tree-modified: no

# Security review — compatibility candidate

Verdict: PASS for local security review. No blocking findings. Older reports remain historical.

- Missing active-change metadata permits only a low-risk micro route without a change ID. Null, malformed, unsafe or symlink metadata does not become a missing-package fallback. Durable routes still require a valid package.
- Both supported report namespaces retain exactly six conventional names. Commit format, ancestry, clean inventory, safe file reads, Git modes and consumer rederivation remain enforced.
- Grok skill generation owns only `.grok/skills`. Existing parent-conflict checks and descriptor-relative writes apply. Canonical hooks and agents remain outside generated ownership. Controls check mirror repair and retirement without changing those inputs.
- Published installer provenance remains separate from candidate VERSION. No new duplicate external write path was found. Manual overrides remain UNVERIFIED; conditional L5 consent does not replace exact-head checks or human approval boundaries. Source2.2.1 is not a published release. Low follow-up #73 remains deferred.

Exact source identity before and after:

- Base: `5d5b45f42f8a9f2bc0303b4d16b5d4e54caad5b9`
- HEAD: `80215eecb7ecec69cc31a965cbf4d678bee842a3`
- Tree: `39d3f24c62e964081ccd903820e6e7c90ca74ce5`
- Fingerprint: `82e94c0074b5e548b35ea4c6e5f6f182fa7d130f4fcbbbe53448ab6251cc1370`
- Status: clean.

Scratch: `/home/pall/getzilla-session/security-compat-scratch/candidate`. Its reviewer-owned scratch root and non-sticky parent have mode `0700`. Local `--no-hardlinks` clone at exact detached HEAD reproduced the candidate tree and fingerprint. Capacity was remeasured: physical14, online logical28, cpuset0-27, unlimited applicable ancestor quotas, successful child-only affinity probe. Probes ran sequentially on CPUs8-11 with one worker.

Fresh commands and results:

```text
taskset -c 8-11 env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_review_source tests.test_harnesses tests.test_install_scripts.InstallScriptContractTests -q
60 tests; OK in15.907s.

taskset -c 8-11 env PYTHONDONTWRITEBYTECODE=1 python3 /home/pall/getzilla-session/security-compat-scratch/mutation_probe.py
Three sequential critical mutants, restored between probes:
- Durable-package guard removed: KILLED; missing-durable test failed.
- Report name allowlist broadened to index file: KILLED; index/analysis rejection test failed.
- Consumer binding rederivation removed: KILLED; three forged-binding assertions failed.
```

The mutation runner executed these exact named test commands, each with `taskset -c 8-11 env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest` and `-q`:

```text
tests.test_review_source.ReviewSourceTests.test_missing_durable_or_malformed_selected_package_fails_closed
tests.test_review_source.ReviewSourceTests.test_index_and_analysis_cannot_be_supplied_as_review_report
tests.test_review_source.ReviewSourceTests.test_consumption_rejects_missing_and_forged_binding
```

The combined restored command ran the same three names: 3 tests; OK in4.111s. Scratch Git status was clean afterward. Controls also execute micro global-report CLI/consumption, active-package global reports, unsafe metadata, revision/path, dirty-state and report-mode checks.

Limits: no native Windows execution, real concurrent filesystem stress, deployed production validation or external exact-head check. Policy and delegation prose received static review only. Local evidence does not certify publication, production or merge authority.

reviewed-tree-modified: no

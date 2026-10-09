# Release review — repaired PR74 candidate

PASS for conditional source PR delivery. Production remains NO-GO. Merge and publication remain blocked until fresh exact-head gates pass.

Route37371d21accb; base5d5b45f42f8a9f2bc0303b4d16b5d4e54caad5b9. Reviewed the full base..HEAD change and repair delta from c6bbfa86, current package, handoff and repair evidence. Before/after HEAD3e59aa153e4eb0c2d1b71e5b55d723d14949ac9b, tree08c67e409236086b4e890384071876b464a48073, fingerprint70b24e2556958d779dda0131a90368abe7b2f50247223fc35fb4af99853d105a. Git status clean both times. reviewed-tree-modified: no.

- No new release-blocking source finding. Source2.2.1 is an unpublished candidate. Installer tests now bind documented installation to published_release rather than advancing VERSION. They retain digest/check-before-execution checks, reject malformed publication records and changed installer bytes, and include a history-free successor fixture. These are tests/state changes; no external-write path or installer behavior changed.
- Publishedv2.2.0 remains immutable at the base SHA with zero assets. Actual Git diff shows no installer or package bytes changed. Recorded immutable installer hashes remain distinct from candidate version. Future installer changes require new publication provenance.
- Current handoff names PR74 and pending fresh reviews/gates. Existing old reports and artifact smoke are historical only. The 91-test and 68-test repair observations are reported bounded evidence, not this review's execution or native Windows qualification.
- Low documentation findings are deferred to issue73. Frozen reviewing state, manual-override UNVERIFIED wording and conditional L5 retain exact gates and grant requirements. No target deployment authority is inferred.
- Production target/task, installed repaired-source acceptance, runtime error signals and exercised recovery remain unproved. No daemon or unattended production qualification is inferred. Recovery requires a gated forward fix and fresh reviews; legacy PASS receipts are not auto-upgraded.

Executed read-only commands/results:

- git rev-parse HEAD HEAD^{tree}; git status --porcelain=v1; getzilla.util.tree_fingerprint(Path('.').resolve()) with PYTHONDONTWRITEBYTECODE=1: exact identities above, clean before/after.
- git diff --stat c6bbfa86..HEAD; git diff c6bbfa86..HEAD -- tests/test_install_scripts.py tests/test_manifest_package.py tests/test_project_state.py tests/test_structure.py PROJECT_STATE.json; package/evidence reads: repaired publication binding and positive renamed-command assertion inspected.
- git diff --name-only 5d5b45f..HEAD -- scripts/install.sh scripts/install.ps1 packages: no paths.
- gh api repos/Dimkox/Getzilla/branches/main/protection/required_status_checks: required linux/windows, Actions App15368; strictfalse. No protection change.
- gh pr view74 --repo Dimkox/Getzilla --json headRefOid,statusCheckRollup: remote head75ff49d90546f2b89ad20cdc5f9e2a240f573914. Linux/windows FAILURE; GitGuardian SUCCESS. These are old-source results and do not qualify repaired HEAD.
- gh api repos/Dimkox/Getzilla/releases/tags/v2.2.0: target5d5b45f42f8a9f2bc0303b4d16b5d4e54caad5b9; published2026-10-09T01:57:09Z; assets0.

Unexecuted: fresh final full-scope local verifier, repaired exact-head external Linux/Windows checks, native Windows acceptance, fresh repaired artifact smoke and production acceptance/recovery. These are pending gates, not waived checks. Historical artifact75ff smoke is not reused as fresh evidence.

Scratch:none; static read-only release review only. mutation: skipped (non-critical) for repair tests/state and release claims; critical receipt probes remain with code/test/security reviewers. No tests/artifacts generated in candidate.

Conditional release requires persisted fresh reviews, report-only freeze, successful final local gate, exact-head required checks and resolved threads, then exact L5 grants. Tag/publish2.2.1 only from actual merged tested source. Preservev2.2.0.

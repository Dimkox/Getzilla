# Release review — supported-consumer compatibility

PASS for conditional source PR delivery. Production NO-GO. This report does not authorize merge or publication before fresh gates.

Route37371d21accb, base5d5b45f42f8a9f2bc0303b4d16b5d4e54caad5b9. Read the full source change, compatibility delta, current package and implementation evidence. Before/after HEAD80215eecb7ecec69cc31a965cbf4d678bee842a3, tree39d3f24c62e964081ccd903820e6e7c90ca74ce5, fingerprint82e94c0074b5e548b35ea4c6e5f6f182fa7d130f4fcbbbe53448ab6251cc1370. Clean status both times. reviewed-tree-modified: no.

- No new release-blocking finding from this lens. Grok skill copies now come from canonical skills and participate in drift enforcement. Generated ownership adds only .grok/skills, preserving canonical hooks/agents. Installer parity tests cover actual consumers; retirement tests cover preservation.
- Review-source compatibility restores conventional engineering/reviews reports and low-risk micro routes without a package. Durable routes still require valid package metadata. Present malformed metadata fails closed. Exact reviewed source, ancestry, clean candidate, regular report modes, six-name whitelist and rederived receipt binding remain mandatory. These are local evidence controls, not authenticated reviewer identity or external authority.
- Source2.2.1 remains unpublished. Publishedv2.2.0 stays immutable at the base commit, zero assets. Neither installer nor package bytes changed. Recorded published installer provenance remains separate from advancing candidate VERSION.
- Low findings remain deferred to issue73. Manual overrides remain UNVERIFIED until named deferred checks run. Tracked reviewing state stays frozen; conditional L5 still requires exact grants, green exact-head checks, independent review and resolved threads.
- No changed external mutation path was identified. No universal retry/idempotency claim is made. Production target/task, installed repaired-source acceptance, observable runtime failure signals and exercised recovery remain unknown. Native harness execution and historical M8 smoke do not prove unattended production operation.

Executed read-only controls/results:

- git rev-parse HEAD HEAD^{tree}; git status --porcelain=v1; getzilla.util.tree_fingerprint(Path('.').resolve()) with PYTHONDONTWRITEBYTECODE=1: identities above, clean before/after.
- git diff --stat 3e59aa15..HEAD; git diff 3e59aa15..HEAD -- .getzilla/getzilla/review_source.py .getzilla/getzilla/harnesses.py tests/test_installer.py; current package/analysis/implementation reads: narrow generated ownership, report namespace compatibility and consumer regression inspected.
- git diff --name-only 5d5b45f..HEAD -- scripts/install.sh scripts/install.ps1 packages: no paths.
- gh api repos/Dimkox/Getzilla/branches/main/protection/required_status_checks: required linux/windows, Actions App15368; strictfalse. No protection mutation.
- gh pr view74 --repo Dimkox/Getzilla --json headRefOid,statusCheckRollup: remote head9ea7c523304da5a747d3663bf278641a36bf04f7. Linux/windows/GitGuardian SUCCESS on that older head. These do not qualify reviewed80215eec.
- gh api repos/Dimkox/Getzilla/releases/tags/v2.2.0: base target, publication2026-10-09T01:57:09Z, assets0.

Unexecuted: fresh final full-scope local PR verifier, current exact-head Linux/Windows checks, native Windows compatibility qualification, repaired artifact smoke and production acceptance/recovery. Old9ea7 local verifier was cancelled/incomplete; its external success cannot replace fresh checks. Bot threads still need resolution before merge. Reported49 compatibility and33 receipt/identity controls were read, not rerun. Historical75ff artifact smoke is not fresh evidence.

Scratch:none. Static release review only; no tests/artifacts generated in candidate. mutation: skipped (non-critical) for release and skill-copy claims. Critical receipt validation mutation probes remain assigned to code/test/security reviewers.

Persist fresh reports, freeze report-only delta, pass the final local and exact-head external gates, resolve threads and record exact conditional L5 grants. Publish2.2.1 only from actual merged tested source. Preservev2.2.0. Production deployment requires separate exact target/action authority and acceptance evidence.

# Release review

PASS for conditional source PR delivery. NO-GO for production deployment or issue #72 operational completion.

Reviewed route `37371d21accb`, base `5d5b45f42f8a9f2bc0303b4d16b5d4e54caad5b9`, full change package and actual diff.

Before/after identity stayed equal:

- HEAD: `c6bbfa86b3d3177b0b66993ceaf3f092b6e6cbfa`
- Tree: `9950552a6d088e518ea5db688659808ce271e4b7`
- Fingerprint: `7fc6376f1514f3be3cc0cca905b6fe65d9d857c5a7af15dba87cf849dfa4a0ad`
- Git status: clean.
- reviewed-tree-modified: no

Findings and limits:

- Low: `docs/REFERENCE.md:296` still lists `ready → pull request`. This conflicts with the frozen `reviewing` rule. Collect this into the later Low findings issue.
- Source version is `2.2.1` candidate. Published `v2.2.0` remains bound to the unchanged base commit. No package or installer bytes changed.
- Current Getzilla handoff identifies issue #72 and the native harness. Historical deployment records do not prove current operation.
- Manual overrides retain UNVERIFIED status until deferred checks run. Conditional L5 requires exact grants, passing exact-head gates, independent review and resolved threads.
- Legacy review passes deliberately become evidence gaps. Recovery requires fresh review and a gated forward fix.
- No changed external mutation path was found. This review does not establish universal retry safety.
- Target installation, business task, runtime acceptance, alerts and exercised recovery remain unknown. No daemon or production qualification is inferred.

Executed read-only controls:

- `git rev-parse HEAD HEAD^{tree}` and `git status --porcelain=v1`: identities above; clean before/after.
- `getzilla.util.tree_fingerprint(Path('.').resolve())` with bytecode disabled: fingerprint above.
- `gh api repos/Dimkox/Getzilla/branches/main/protection/required_status_checks`: required `linux` and `windows`, App ID `15368`.
- `gh pr list --head readiness/72-production-20261009 --json number,headRefOid,statusCheckRollup`: `[]`. No candidate PR checks were available.
- Release API plus `git rev-parse v2.2.0^{commit}`: published `2026-10-09T01:57:09Z`, zero assets, exact base commit.
- Static Git diff, file reads and searches: README architecture links remain current.

Unexecuted requirements: final qualifying local PR verifier, candidate Linux/Windows CI and Windows execution, production acceptance and recovery. These remain delivery gates. Published-source smoke and M8 evidence were read, not rerun; they prove only their recorded bounded scope.

Scratch: none; no tests or artifacts generated in the candidate. `mutation: skipped (non-critical)` for release documentation claims. Critical receipt mutation review belongs to the selected code/test/security reviewers.

Publish `v2.2.1` only from the actual merged tested commit after all required gates pass. Preserve immutable `v2.2.0`.

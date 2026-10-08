# Requirements — Close hook policy bypasses (secret reads, merge/push/publish spellings, rm -rf /)

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Acceptance criteria

- [x] AC-001: Given a Read or Bash call naming a secret path (root-level or nested, any case, inside or outside the repository, under quoting, `sh -c`, `rev:path`, `@path`, `--opt=path` or a matching glob), the policy denies it.
- [x] AC-002: Given `gh`/`git`/`docker`/`npm` global options or equivalent subcommands, merge/push/publish/release/workflow-dispatch are classified as the same production action and need the same exact grant.
- [x] AC-003: Given `gh api` with any non-GET method spelling or request fields, or `gh pr review`, the policy requires an exact external-write grant.
- [x] AC-004: Given `rm` with any recursive flag spelling or `--no-preserve-root` on `/`, an absolute path, `~`, `$HOME`, `.` or `*`, the policy denies it as destructive.
- [x] AC-005: Ordinary reads, builds, tests and `gh`/`git` read commands stay allowed.

## Failure and edge cases

- Unparseable shell text: secret matching works on raw word fragments; `rm` falls back to a regex; `gh api` falls back to the corrected regex.
- Variables (`cat $F`) are not expanded; `-c alias.*` stays an ambiguous root in the hook resolver.

## Governance context

- Applicable rule IDs: AGENTS.md "Prohibited routine actions", "Local delegated grants".
- Canonical-example deviations and evidence: none.
- Intentional debt created, repaid, or accepted: none.

## Non-functional requirements

- Security: fail closed for any word that names a secret path.
- Reliability: no new dependency.
- Performance: bounded glob expansion.
- Observability: deny reasons name the matched secret word, production action or `rm` policy.

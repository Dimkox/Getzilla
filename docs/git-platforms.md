# Git platforms and the optional Entire adapter

Catalog audit: **2026-10-29**. The executable catalog lives in
[`git_platforms.py`](../.getzilla/getzilla/git_platforms.py); this page explains its boundaries.
Run these commands without provider credentials or network access:

```bash
getzilla git catalog
getzilla git catalog --json
getzilla git inspect --json
```

`inspect` reads the current repository's remote. It preserves a credential-free clone URL,
transport host, logical repository and authoritative forge. Unknown hosts remain generic;
self-hosted software is not guessed from a hostname. An unsupported or credential-bearing
URL is reported without echoing it. A provider identity does not select a CI gate.

## Current matrix

**Implemented** means code and relevant local tests exist. **Local checkout** means an
already-fetched ordinary Git repository can enter the generic local ingestion path; it
does not certify that provider's API. **Experimental** means an optional adapter with
offline protocol tests. **Candidate** means provider-specific integration remains future
work. None of the new catalog entries is presented as hosted end-to-end certification.

| Platform / mode | Current capability | Important boundary |
| --- | --- | --- |
| Local Git, including repositories without remotes | Implemented local input | Fetch and authentication are separate operations |
| Source folder without Git | Implemented adoption input | An input mode, not a Git host |
| GitHub.com public / private | Existing GitHub CI integration | Public Actions and private App-based Trust CI have different setup; pilot PR publishing remains scoped |
| GitHub Enterprise Server / Cloud on ghe.com | Local checkout; candidate | No inheritance of github.com API or Trust CI support |
| Entire native `/et` | Experimental optional transport, repository discovery, Trails and check inspection | No trusted-CI producer verification or automated merge |
| Entire GitHub mirror `/gh` | Experimental optional transport, repository discovery, Trails and check inspection | Entire transport does not prove a branch was published or merged on upstream GitHub |
| Cursor Origin native / mirrored | Local checkout; candidate | Vendor early beta; separate APIs and mirror semantics |
| GitLab.com / Self-Managed / Dedicated | Local checkout; candidate | MR, CI and instance configuration need an adapter |
| Bitbucket Cloud | Local checkout; candidate | Cloud API differs from Data Center |
| Bitbucket Data Center | Local checkout; candidate | Bitbucket Server ended support on 2024-02-15; Data Center remains a separate target |
| Azure Repos Git Services / Server | Local checkout; candidate | Organization/project identity, PR policies and server versions need validation; excludes TFVC |
| Gitea | Local checkout; candidate | Validate the actual instance and API version |
| Forgejo | Local checkout; candidate | Do not assume permanent Gitea API equivalence |
| Codeberg | Local checkout; candidate | Hosted Forgejo with separate service policies |
| AWS CodeCommit | Local checkout; candidate | Reopened to new customers in November 2025; AWS auth and regions need an adapter |
| Gitee | Local checkout; candidate | Provider API, PR and statuses remain unsupported |
| GitCode / AtomGit | Local checkout; candidate | Consolidated names are aliases, not two shipped adapters |
| GitFlic cloud / self-hosted | Local checkout; candidate | Endpoint and version need explicit validation |
| GitVerse | Local checkout; candidate | Provider authentication, review and CI need an adapter |
| SourceHut Git | Local checkout; candidate | Email/patch review needs a different mapping; excludes Mercurial |
| Other SSH/HTTPS Git servers | Local checkout only | Git transport does not imply PR, webhook, CI or merge support |

The JSON contract has `schema_version`, `updated_at` and `platforms`. Every platform has
an ID, status, capability map, API audit date, contract/test version fields, OS scope,
evidence paths and limitations. Capability names are `local_input`, `clone`, `fetch`,
`push`, `visibility`, `review_requests`, `checks`, `webhooks`, `merge`, `lfs`, `submodules`
and `session_evidence`. A missing provider integration is explicitly `unsupported`.
`contract_version` identifies the inspected upstream protocol; `tested_version: null`
means no real provider binary/service version has been certified in hosted tests.

GitHub's existing parser and CI selector remain separate. Listing another provider does
not route it through GitHub APIs, and a visibility override does not establish support.

## Install Entire support explicitly

```bash
getzilla components add extra:entire
getzilla entire --help
```

The adapter is outside the core engine archive and omitted from a lean installation.
The small launcher remains available and explains how to add it. Component installation
uses the existing on-demand mechanism, adds missing files and preserves existing files.
It does not install the Entire CLI, sign in, enable recording, replace hooks or upload
session data. Existing local work, checkpoint refs and Entire settings remain untouched.

Remote operations currently require **POSIX** process-group cleanup. Linux subprocess
and offline protocol tests cover this implementation; macOS hosted behavior is unverified.
Windows remote operations return `unsupported_os`; the offline catalog still works.
The supported protocol is pinned to **Entire CLI 0.12.2**, with `git` and
`git-remote-entire` on PATH. Other CLI versions fail explicitly until their contract is
validated. No real account or disposable Entire repository was used for these tests.

Choose an existing saved context explicitly:

```bash
getzilla entire --context work status
```

Before any authentication request, the adapter reads only the bounded, non-secret
`contexts.json` metadata in `$ENTIRE_CONFIG_DIR` or `~/.config/entire`. It requires the
selected context's API origin to be HTTPS on `entire.io` or a proper `.entire.io`
subdomain. It never reads the token store or keychain directly. `ENTIRE_TOKEN` overrides
saved-context routing in the upstream CLI, so this adapter rejects that mode instead of
forwarding the token to an unverified audience. Entire performs its own saved-context
authentication. A zero CLI exit code with `logged_in:false`, revocation, error or a
mismatched context/server is a refusal.

Telemetry and automatic update prompts are disabled for adapter child processes.
Upstream CLI 0.12.2 can still make an unauthenticated version-check request to
`install.entire.com`, with `api.github.com` as fallback; the available upstream variables
do not disable that check. Getzilla does not send GitHub token environment variables to
the Entire process. Default Git system/global configuration still applies; URL rewrites
are checked and refused before transport operations.
Inherited `GIT_DIR`, `GIT_WORK_TREE`, index/config overrides and other `GIT_*` routing
variables are rejected so grant validation and transport cannot observe different
repositories. Prompt/pager environment settings are the harmless exceptions; prompts
are forced off and the child does not inherit a pager command.

## Native repositories and GitHub mirrors

```text
entire://aws-us-east-2.entire.io/et/project/repository
entire://aws-us-east-2.entire.io/gh/owner/repository
```

The clone host, `/et` versus `/gh`, repository and context remain distinct. An Entire
grant cannot be reused as a GitHub grant. API routing uses the validated `repoId` and
`apiUrl` returned together by repository discovery; an API hostname is never guessed
from the clone hostname. Production `.entire.com` web URLs and staging domains are not
accepted as transport/API aliases.

```bash
# Creates an absent target without checkout or automatic submodule initialization.
getzilla entire --context work clone entire://aws-us-east-2.entire.io/et/project/repository ./new-repository

# Run from the repository Git root, or pass --root /absolute/project before the command.
getzilla entire --context work fetch feature/example
```

Fetch requests one explicit branch, without tags, submodules or forced updates. Clone
does not check out files, so repository smudge filters and checkout hooks are not invoked
by this command. Check out the desired branch through your normal reviewed workflow.
An interrupted clone may leave its own partial target; no automatic deletion follows.

## Scoped branch push

Automatic push accepts only `getzilla/` task branches, one literal commit SHA and an
explicit request ID. It requires an existing production grant bound to the current
repository, route/change, exact local HEAD/tree, TTL and resource:

```text
entire://aws-us-east-2.entire.io/et/project/repository#refs/heads/getzilla/example
```

Materialize a grant only after the user has actually authorized this exact operation:

```bash
getzilla approve production --action git-push-branch \
  --resource 'entire://aws-us-east-2.entire.io/et/project/repository#refs/heads/getzilla/example' \
  --reason 'Existing user authorization for this exact task branch'

getzilla entire --context work push getzilla/example \
  --head FULL_COMMIT_SHA --request-id push-example-001
```

The adapter rechecks the local source and grant before writing, sends only that explicit
SHA-to-branch refspec, never force-pushes, and reads the destination ref back. A successful
mirror push reports `upstream_verified:false`; a matching Entire ref does not prove an
authoritative GitHub update.

**An existing `pre-push` hook blocks automatic push.** Entire's hook can independently
publish queued checkpoint/session refs even when the outer push contains only one
branch. The adapter neither skips nor rewrites your hook. Use the manually reviewed push
workflow for such repositories; the adapter does not decide which session destinations
or custom hook effects the user has approved. Unknown native `canPush` permission also
blocks writes. Mirror permission is enforced by the provider and exact local grant.

## Trails and checks

```bash
getzilla entire --context work trails list
getzilla entire --context work trails show PROJECT_TRAIL_ULID
```

Listing uses bounded pagination. Project Trail numbers and per-repository change numbers
are different: detail/check requests resolve the repository's change by `repositoryId`,
never by substituting the project Trail number. List responses are summaries and need
not contain the `changes` field returned by detail responses.

Create links an already-published branch after a separate exact external-write grant:

```bash
getzilla approve external-write --action external-write \
  --resource 'entire://aws-us-east-2.entire.io/et/project/repository#trails/getzilla/example' \
  --reason 'Existing user authorization to create this Trail'

getzilla entire --context work trails create --branch getzilla/example --base main \
  --head FULL_COMMIT_SHA --title 'Example change' --body 'Review description' \
  --request-id trail-example-001

getzilla entire --context work checks PROJECT_TRAIL_ULID --head FULL_COMMIT_SHA
```

Create always supplies `--repo` and `--branch-action link`, so the upstream CLI cannot
implicitly push the local worktree. It verifies the published HEAD before and after the
request and checks that context-based resolution selects the same processing repository.
`/gh` uses `gh/owner`; `/et` uses `et/project`. A link is not an atomic HEAD comparison-and-swap:
the resulting Trail can continue to track a changing branch.

Checks are a conservative provider snapshot. Unknown, stale, missing, empty or unavailable
checks never produce a passing preflight. Provider success still reports
`trusted_ci_verified:false` and `merge_supported:false`. Upstream `app_name` and eval
scores do not establish a trusted independent CI producer.

**Automated merge returns `unsupported` and performs no write**, including for a GitHub
mirror. A dedicated trusted-CI adapter must bind forge, repository, Trail, base/head,
producer identity and policy before that capability can be enabled. Local grants and
review receipts cannot manufacture that external authority. The unbound upstream
`trail merge` command is not used as a fallback.

## Failure, cancellation and retry

Every subprocess has a wall limit (30 seconds by default; `--timeout` allows up to 300),
a combined 2 MiB stdout/stderr limit before JSON parsing, bounded stdin, and owned process
group cleanup. The adapter does not invoke a shell. Invalid JSON, duplicate keys, schema
drift, unknown permission, foreign origins, service failures and cancellation produce
explicit error codes without printing raw provider output or credentials.

Before a push/create, a durable record reserves the request ID under ignored
`.getzilla/runtime/entire-requests/`. A repeated successful request returns the recorded
result; reusing its ID for different input is rejected. A timeout, interruption, crash or
ambiguous response leaves a reconciliation-required record. **Do not delete the record
or choose a new ID merely to retry:** first inspect the provider's branch/Trail state.
The upstream create idempotency key covers branch linking, not creation of the parent
Trail, so automatic retry could create duplicates. Request-body content is represented
by a digest in the journal; raw CLI stdout/stderr is not logged there.

## Evidence and remaining validation

Offline tests: [registry](../tests/test_git_platforms.py), [protocol/auth](../tests/test_entire_adapter.py),
[grants/writes/retries/checks](../tests/test_entire_authority.py),
[bounded child processes](../tests/test_entire_process.py), [optional packaging](../tests/test_entire_install.py).
The existing GitHub CI, grant lifecycle and launcher suites remain the regression baseline.

Still unverified or unsupported: hosted native/mirror end-to-end scenarios, live credentials,
LFS, submodules, shallow/partial clone combinations, full worktree transport coverage,
webhooks, automated merge, session capture/publication, Windows process-tree cleanup and
provider-specific adapters for catalog candidates. Entire's current mirror guide documents
an LFS limitation; ordinary Git clone success does not establish LFS support. Tracking:
[#230](https://github.com/Dimkox/Getzilla/issues/230).

Primary references: [Entire CLI v0.12.2](https://github.com/entireio/cli/tree/v0.12.2),
[repositories](https://docs.entire.com/guides/repositories/repository),
[mirrors](https://docs.entire.com/guides/repositories/mirrors),
[Git hooks](https://docs.entire.com/guides/configuration/git-hooks),
[project Trail models](https://github.com/entireio/cli/blob/v0.12.2/cmd/entire/cli/api/project_trails.go),
[check provenance fields](https://github.com/entireio/cli/blob/v0.12.2/cmd/entire/cli/api/trail_mergeability_types.go),
[Cursor Origin](https://cursor.com/docs/origin),
[Atlassian Server support](https://www.atlassian.com/licensing/server-end-of-support),
[Bitbucket Data Center exception](https://www.atlassian.com/licensing/data-center-end-of-life),
[CodeCommit history](https://docs.aws.amazon.com/codecommit/latest/userguide/history.html),
[GitCode/AtomGit](https://docs.gitcode.com/en/docs/help/home/aboutus/).

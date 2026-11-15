# Public Getzilla security check operator contract

Draft for independent review, 4 November 2026. Source baseline is PR #318 at `a34aa67a47fcde80ef18d66b0bde4dcf325d8a34`. This document records the approved design and qualification prerequisites. The independent publisher implementation defaults to disabled. Deployment and activation require separate qualification.

## Approved boundary and unresolved configuration

The owner approved keeping live tests in GitHub Actions and using a separate owner-controlled GitHub App to validate exact-SHA results and publish the required security check. PR jobs cannot modify the deployed verifier or obtain its keys. Existing mandatory security families, inclusive 72-hour freshness, six permitted license alternatives with their obligations and Getzilla artifact-use decisions continue to apply.

The first scanner SHA, App ID, installation ID, trusted workflow revision and external checker deployment are still unselected. A human operator registers and installs the App, controls key generation/storage/rotation and authorizes the protection change. Record only public identifiers and reviewed source digests in project evidence. Registration, secret access, deployment, protection edits and private Trust CI activation require their own operational authorization. This draft performs none of them.

## Existing mechanisms to reuse

The new public controller reuses `GitHubClient` transport and the existing App JWT signer. It does not use the private publisher's `ensure_check_run` or installation-wide token method: those helpers do not enforce this public contract. `public_publisher.scoped_client_factory` requests one numeric repository ID with Checks write and Actions, Contents and Pull requests read. The private Trust CI scheduler, worker, holdout, approval and attestation pipeline remain separate. [Repository source](https://github.com/Dimkox/Getzilla/blob/a34aa67a47fcde80ef18d66b0bde4dcf325d8a34/trust-ci/README.md)

The current public workflow pins scanner code, then runs candidate envelope generation and the candidate `linux` aggregator. Those outputs supply observations. Their self-declared assurance, hashes and PASS do not authenticate the execution plan. The approved App must enforce its own trusted plan. [Current workflow](https://github.com/Dimkox/Getzilla/blob/a34aa67a47fcde80ef18d66b0bde4dcf325d8a34/.github/workflows/getzilla.yml#L225)

## Trusted execution and publication

1. Keep the App service and its immutable policy outside the candidate checkout and candidate Actions jobs. Pin reviewed scanner, orchestrator, envelope validator and final admission code. The operator-controlled manifest records repository ID, base branch, App/installation IDs, policy digest, workflow path/revision, allowed events, required jobs and evidence types. Candidate parameters cannot replace these values.
2. Execute live tests in fresh Actions workers under the reviewed trusted orchestration. Candidate source can execute only in the test compartment without App credentials. Scanner source is a separately reviewed pin and candidate input is data. A PR-authored workflow must not be accepted merely because it has the expected name, an Actions App identity or an uploaded JSON manifest. Validate the effective workflow bytes against the reviewed workflow and reject a changed execution plan. When the available Actions API cannot establish that provenance, keep that attempt unqualified until a protected dispatcher supplies it.
3. Fetch run, attempt, workflow, job and artifact metadata through GitHub using the App's own read authority. Bind numeric repository ID, PR number, current head SHA/tree, base SHA, event/merge SHA, run ID/attempt, trusted workflow digest, checker SHA/tree and policy digest. Authenticate webhook delivery, then reread authoritative state. Treat event fields and artifact bodies as untrusted. Bound download size, extracted file count and paths. Validate artifact digests and every required file. Same-source hashes establish integrity after provenance is checked.
4. Reapply all security obligations and per-source freshness with the trusted consumer. Require completed expected jobs and confirmed owned cleanup. Missing, unexpected skipped, cancelled, timed-out, stale, replayed, malformed or contradictory evidence blocks success. Validate the real job graph and command contract, including workflow changes that replace tests with a successful stub. Preserve the required positive and negative controls for each supported evidence family.
5. Immediately before publishing, reread PR head and source identity. An obsolete attempt can report its own failure but cannot satisfy the new head. Publish only to the verified full `head_sha`. Use a distinct proposed context `getzilla-security/verified@<policy-sha12>` and bind the required check to the numeric expected App ID. Record repository, source, policy, workflow, run/attempt and evidence digest in `external_id` or the durable job record. Before reusing a Check Run, verify its App, repository, SHA, name and external ID. Reconcile an ambiguous API outcome before creating another run.
6. An incomplete result remains in progress or completes as failure, cancelled, timed_out or action_required. Reserve success for complete qualifying evidence. Do not publish neutral or skipped for a required incomplete check, because GitHub can admit those conclusions. Minimize installation permissions to the exact repository and necessary Checks write plus read permissions for Contents, Pull requests and Actions. Grant no repository-administration capability to the runtime publisher. [Checks API](https://docs.github.com/en/rest/checks/runs) [Required-check semantics](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)

Privileged workflow events must never execute candidate code with the App key or privileged token. A workflow-run artifact is also untrusted input. Review the workflow event policy during deployment. [GitHub security guidance](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)

## Dark qualification and activation

Start with publication disabled and use synthetic API responses through the existing injected transport. No credentials are required. Complete the following paired controls on the exact reviewed source and retain expected versus observed decisions.

| Control | Required result |
| --- | --- |
| Complete trusted workflow, current source, all required families and cleanup | One success intent bound to the exact head and expected App |
| Candidate aggregator returns success while a required family fails | Refusal |
| Candidate workflow replaces tests or envelope generation with success stubs | Refusal even when GitHub marks its jobs green |
| Same context published by another App or commit-status writer | Cannot satisfy expected-source protection |
| Wrong repository, SHA/tree, run, attempt, workflow or policy | Refusal |
| New PR head appears during validation | No success publication for the replacement head |
| Stale or incomplete feeds, unknown applicability, absent artifact, forged local manifest | Refusal |
| Cleanup unknown, unexpected skip, cancellation or partial parser coverage | Refusal |
| Publication timeout followed by retry | Reconcile the exact App-owned Check Run without duplicate success |
| Configuration absent or publisher disabled | Zero token acquisition and zero API writes |

These rows are qualification requirements, not executed results. Follow them with independent code/security review, the required local gate and exact-head external checks. In a human-authorized canary, first publish an informational source-specific check and verify the App ID in GitHub. Capture protection configuration before changing it. Keep existing `linux` and `windows` requirements and their expected sources. Add the new App-owned context only after positive and refusal controls pass and the operator authorizes activation. The existing full protection helper builds a replacement payload containing one context, so do not apply it directly to this additive migration. Inspect and preserve every existing rule.

## Failure and rollback

Qualify the change on an isolated target. After applying it there, run the read-only snapshot verifier from the repository root. Supply two complete administrator responses from `GET /repos/Dimkox/Getzilla/branches/main/protection`, captured before and after the intended addition. Substitute the approved exact context and positive numeric App ID.

```sh
python trust-ci/scripts/verify_public_check_protection.py before.json after.json \
  --context 'getzilla-security/verified@<policy-sha12>' --app-id '<approved-app-id>'
```

Exit 0 means the snapshots preserve the same repository/branch, `linux`, `windows`, every earlier check and publisher binding, and every other protection setting while adding exactly that App-specific context. Exit 1 refuses malformed input or any policy difference. The verifier reads bounded local files, uses no credentials and performs no network request or write. Only nested documented endpoint links and check ordering are normalized. Unknown fields remain significant. Snapshot authenticity, effective organization rules and current server state require the administrator's independent readback. This check does not activate protection or qualify the scanner.

Disable publication and stop accepting new qualifying work on a suspected authority failure. Invalidate affected successful checks where authorized and preserve evidence. Operator rollback restores the captured protection configuration, retaining existing `linux` and `windows` requirements and previous review/admin rules. An unavailable new security check must not silently become a merge bypass. A human decides whether to keep merges blocked or explicitly restore the previous protection baseline. Revoke or rotate a suspected App key through the human-owned channel, then independently requalify the replacement deployment.

On the read-only inspection, repository rulesets returned an empty list while classic main protection returned 403 to this integration. The actual protection baseline therefore needs an administrator's fresh read before any change. No absence of classic protection is inferred.


## Implemented review scope

The `adaptive_trust_ci.public_admission.evaluate` function accepts host-supplied trust configuration, a current candidate selector, independently signed evidence, the evaluation time, a mandatory operator-owned Git checkout, and a trusted local feed mirror when a feed applies. The verifier reads the exact commit's immutable Git objects, checks the tree and derives the inventory and scanner applicability itself. Symlinks, gitlinks, unsafe paths and sources beyond its 32 MiB aggregate limit block admission. Provider reads use GitHub's API. The caller supplies the trusted Getzilla implementation independently of the candidate. No live publisher is connected.

The operator must supply the complete exact `Authority.required_jobs` graph (at most 100 jobs). Every named job must complete successfully in the selected attempt. Missing, extra, duplicate or skipped jobs block. The initial producer contract is serialized: only the newest run on the pinned producer workflow and branch can qualify, even if a newer run concerns another PR. This sacrifices throughput to prevent old-run replay; parallel producer scheduling needs a separately qualified per-candidate dispatch journal.

`public_publisher.publish` is the host-side publication entry point. Construct `PublisherConfig` and `BoundPublicVerifier` in the protected operator process. Use `scoped_client_factory(config, operator_app_auth)` as the credential broker. The disabled default returns before credential acquisition or provider calls. A separate read-only observer supplies access to the protected runner repository. The publisher App has no merge, administration, status-write or ruleset-bypass permission.

The publisher freezes the complete evidence bundle, reserves one durable publication per exact producer attempt and candidate, checks the App installation and repository, verifies current evidence again before success, and reads back App/head/name/external ID. The broker verifies installation metadata through the JWT-only `GET /app/installations/{id}`. The installation token separately reads `GET /installation/repositories` and must expose exactly the selected repository. A lost creation response permits lookup only; absence of a receipt cannot authorize another POST. Conflicting signed bundles latch a durable refusal for the whole scope, including retries of the first bundle after restart, and demote its previous check to `action_required`. A new protected producer run is required. A detected post-publication race also demotes the check; this is bounded recovery, not an atomic merge-time guarantee. Share one durable journal across replicas. Never reset it on restart or an unknown outcome.

Authenticate raw webhook bytes with `verify_webhook` before parsing and before calling `PublicationJournal.accept_delivery`. A delivery ID alone proves nothing. Events are wakeups: reconstruct the selector and evidence from operator-owned state and provider reads. No HTTP listener, scheduler, public artifact ingestion endpoint or production deployment is enabled by importing these modules. The operator must qualify that wiring and download bounds separately.

The OSV family control validates a real dependency against an isolated snapshot built from synthetic advisory bytes. For that same commit the canonical inventory also requires KEV, EPSS, malicious-package and license checks. Overall admission refuses it even when a signed report marks those families inapplicable. Paired nonempty Git fixtures prove integration preservation, signed tree-substitution refusal and conflict refusal; publisher fixtures prove exact-head publication and refusal paths. These are local protocol controls with synthetic provider responses and temporary test keys, not live GitHub qualification or a clean security scan of Getzilla. Applicable KEV, EPSS, malicious-package, license and image checks, finding dispositions and forks remain outside the qualified scope. Keep those refusals. Actual Getzilla also exceeds the current bounded source materializer; do not activate this prototype for it.

Run the two independent suites on the reviewed #318 base with the trusted Getzilla core on the import path:

```sh
PYTHONPATH=trust-ci/src:.getzilla python -m unittest discover -s trust-ci/tests -p 'test_public*.py'
```

## Final merge and freshness

A GitHub success is attached to a commit. The Checks API does not expose a per-check expiration time. A displayed success may outlive the earliest data source, a rerun, or a change to the target branch. An operator-controlled final merge path must re-read the exact PR, base branch, base/head, latest attempt, file identities and source expiry at final authorization. It must serialize competing attempts, refuse evidence that could expire during the operation, and fail closed when the final observer is unavailable. A scheduled refresh alone cannot enforce the boundary. The owner approved a distinct final merge service on 4 November 2026. The owner signs off each exact candidate, and only the service may execute the resulting merge. A general design approval cannot authorize an individual PR. Do not enable a production requirement on the assumption that writing success also enforces the merge-time limit.

Qualify ordinary same-repository PRs first. Exercise an expired successful status on an unchanged head, a rerun in flight, retargeting at the same base SHA, two PRs using one head, a change to the head after the first API read and an unavailable publisher. Public forks require separate qualification. Keep production disabled until the operator demonstrates the approved service owns the write path and enforces the final decision at the actual update, including service outages. [GitHub Check Runs API](https://docs.github.com/en/rest/checks/runs)

## Final merge protocol

The architecture model assigns the two public admission and merge modules to the existing Trust CI control-plane owner, `NODE-TRUST-CI-API`. This is a source ownership entry. The independent public controller has no registered API route or private scheduler job.

Construct the security adapter inside the independent operator process. Load the following modules from the reviewed, pinned Getzilla installation before providing a candidate repository. Supply the resulting object as `Authority.security_core`. The service refuses admission when this adapter is absent. Its integration test uses this same binding with real Git objects.

```python
from adaptive_trust_ci.public_admission import OperatorSecurityCore
from getzilla import (architecture_diff, ci_admission, expanded_security, known_vulns,
                      security_cli, security_inventory, security_tools, source_paths)

security_core = OperatorSecurityCore(
    git=architecture_diff, security=expanded_security, known_vulns=known_vulns,
    inventory=security_inventory, paths=source_paths, admission=ci_admission,
    report=security_cli, tools=security_tools,
)
```

The protected host pins the human owner ID and public key, the verifier and the source of evidence. A signed approval identifies the repository, PR, target generation, base, head, tested tree, attempt and evidence digest. Retargeting a PR and later restoring its target requires a fresh decision. The integration result written by the service must match the approved merge object and its tested content. Approvals and revocations form one complete ordered record for the PR.

Signed producer binding version 2 adds `integration` with exact `merge_sha`, `tree_sha` and `report_sha256`. The evidence bundle includes the separate expanded report for that integration. The consumer keeps the PR HEAD tree distinct, recomputes `git merge-tree --write-tree base head`, checks the exact ordered parents, and validates both source and integration reports. Conflicts require a new resolved candidate. The final merge coordinator refuses source-only version 1 evidence; it cannot substitute a HEAD scan for the integrated content. The owner-approved merge object must match this tested integration.

The coordinator checks the inputs again before handoff. It refuses an ambiguous history, conflicting evidence, an unqualified source or a time outside the approved interval. Its local per-PR dispatch journal is persistent. A request with unknown outcome must be reconciled from a target-bound receipt before another grant can dispatch. The journal must have exclusive ownership across all active workers; a local file per replica cannot provide that property.

A matching durable terminal `stale`, `expired` or `not-merged` receipt releases only the pending PR fence. The original approval remains consumed after restart. Bare strings, mismatched identities, missing receipts and any still-possible delayed write retain the fence.

The bare-Git tests exercise a real atomic ref update and receipt in a temporary repository. They use a controlled test clock. The public GitHub merge endpoint takes an expected PR head. It offers no atomic condition over the base, latest attempt or expiry. The repository currently has no production adapter satisfying that stronger contract. No live merge is performed by this prototype.

The staged operator ruleset, required App separation and live negative tests are described in [the main update ruleset guide](../trust-ci/scripts/main-update-ruleset.md). The repository owner retains administrative power to change the configuration.

## Tracking

[Getzilla #326](https://github.com/Dimkox/Getzilla/issues/326) and [GZDEV-57](https://ii-tonya.atlassian.net/browse/GZDEV-57) contain the approved decision and production acceptance criteria.

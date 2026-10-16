# Branch lifecycle

`getzilla branches` answers "which branches can go, and why" without deleting anything by default.

## Classification

A branch is **merged** only with evidence bound to the current target tip:

- `ancestor`: its tip is an ancestor of the target (`git merge-base --is-ancestor`);
- `tree_equal`: its tip tree equals the tree of a first-parent target commit (squash or rebase).

Anything else is **unmerged**; a proof for another target commit is **unknown**. Commit dates never
decide merge state, and the target is the policy's `default_branch`, never the newest branch.
The default branch, protected names (`release/*`, `support/*`, the protection list), the `keep`
list and branches with an open pull request are kept. An incomplete listing (`--partial`) makes the
whole inventory unclean and nothing becomes eligible.

## Retention plan (report)

`getzilla branches report --repo DIR --policy policy.json [--pull-requests prs.json]` prints the
inventory and a plan bound to the policy digest and the refs snapshot digest. A merged branch is
eligible 14 days (`retention_days`) after its **confirmed** merge time, taken from a merged pull
request whose head is the same OID. Without a confirmed time the branch is kept. Experimental
branches (`experiment/*`, `exp/*`) past their TTL only raise an owner notice.

Reading the report is a one-off read. Enabling deletion is a policy change (`deletion_enabled`)
that the owner makes separately.

## Guarded delete

`getzilla branches apply ... --plan-id ID --allow-delete` deletes only when the policy enables
deletion, the flag is given, the plan id matches, the policy is unchanged, the target did not move,
and a fresh re-check still finds each ref eligible with its planned OID. Each delete is
`git update-ref -d refs/heads/<name> <expected-oid>`, so a ref moved after the check is not deleted.
The receipt lists deleted refs with their OIDs, skipped refs with reasons, and the refs snapshot
digests before and after.

The command works on a local repository (for example a bare mirror). It does not fetch, push or
call GitHub; pull request state is a file the caller provides. Tests run on temporary bare
repositories only.

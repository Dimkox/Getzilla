# Create a PR from a linked worktree

A session in the canonical checkout can create a PR for its registered Git linked worktree. The worktree must have its own route and a fresh exact external-write grant. A grant from the canonical checkout does not apply.

Use the absolute worktree path as the tool's working directory. Run one literal command:

```sh
gh pr create --repo Dimkox/Getzilla --head fix/my-change --base main --title "Describe the change" --body-file .getzilla/runtime/scratch/pr-body.md
```

An alternative is one literal `cd /absolute/worktree/path && gh pr create ...`. The directory must name the registered worktree exactly. Run other commands in separate calls.

The explicit `--repo` must match the worktree's origin. The explicit `--head` must name that worktree's current branch. The branch must be neither `main` nor `master`, and HEAD must not be detached. GitHub CLI documents that `--head` skips its implicit push and fork behavior: [gh pr create manual](https://cli.github.com/manual/gh_pr_create).

Materialize existing user authorization in that worktree with an exact grant for action `external-write` and resource `gh:dimkox/getzilla pr create`. Use the repository name in lowercase. The normal route, session, HEAD, tree and expiry checks still apply. A source or route change requires a fresh external-write grant. This local grant gives no merge authority.

The bounded command supports `--repo`, `--head`, `--base`, `--title`, `--body`, `--body-file`, `--draft`, `--fill`, `--fill-first`, `--fill-verbose` and `--no-maintainer-edit`. Prefer these long option names. Use either body text or a body file, and keep multiline text in a file. A body file must be a literal path; standard input and attached short `-F` forms are not admitted across roots. Secret-file checks still apply.

Git or GitHub target overrides, duplicate selectors, shell wrappers, command substitutions, unquoted expansions, redirects and compound command chains remain refused. Other GitHub write operations require their normal target session and exact grants. Use a target session for PR-create options outside this bounded form.

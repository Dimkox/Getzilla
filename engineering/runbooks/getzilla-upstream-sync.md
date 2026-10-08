# Syncing Getzilla with its predecessor

Getzilla was renamed from `Dimkox/adaptive-grok-build-pro`. While work still lands there, bring it here as renamed pull requests instead of re-importing.

**Last synced predecessor commit:** `e131556e33f38ffc5e6d81a47875ed69155ff293` (its `main` after PR #247).

## How it works

1. Rename the last synced predecessor tree with the [rename rules](getzilla-rename-rules.md) → commit **A**.
2. Rename the new predecessor tree with the same rules → commit **B**, a child of **A**.
3. Cherry-pick **B** onto a Getzilla branch. Git merges three ways with **A** as the base, so only the predecessor's new changes arrive, already renamed, and Getzilla's own changes (installer migration, guard, Trust CI owner profiles, docs) stay.
4. Keep Getzilla's `LICENSE`; run the identity guard and the usual suites; open a pull request; update **Last synced** above in the same pull request.

The root `README.md` belongs to Getzilla: it is a short plain-language introduction. The rename script moves the predecessor's detailed README to `docs/REFERENCE.md` in both **A** and **B**, so predecessor README changes arrive there and the short README is left alone. A new predecessor test that reads `ROOT / "README.md"` is pointed at `docs/REFERENCE.md` automatically.

## Commands

```bash
set -euo pipefail
LAST=e131556e33f38ffc5e6d81a47875ed69155ff293      # value of "Last synced" above
NEW=$(git ls-remote https://github.com/Dimkox/adaptive-grok-build-pro.git refs/heads/main | cut -f1)
WORK=$(mktemp -d)
git clone -q https://github.com/Dimkox/adaptive-grok-build-pro.git "$WORK/up"
sed -n '/^```python$/,/^```$/p' engineering/runbooks/getzilla-rename-rules.md | sed '1d;$d' > "$WORK/rename.py"

renamed_tree() {   # $1 = predecessor commit; prints a commit holding its renamed tree
  local dir="$WORK/t-$1"
  git worktree add -q --detach "$dir" HEAD
  (
    set -euo pipefail
    cd "$dir"
    git rm -rq .
    git -C "$WORK/up" archive "$1" | tar -x
    git add -A
    git -c user.name=sync -c user.email=sync@localhost commit -qm "verbatim $1"
    python3 "$WORK/rename.py" . >/dev/null
    find .grok-stack factory/src delivery/src scripts .agents .grok -depth -type d -empty -delete 2>/dev/null || true
    git add -A
    git -c user.name=sync -c user.email=sync@localhost commit -qm "renamed $1"
    git rev-parse HEAD
  )
}
A=$(renamed_tree "$LAST")
B=$(renamed_tree "$NEW")
PICK=$(git commit-tree "$B^{tree}" -p "$A" -m "sync: predecessor ${LAST:0:7}..${NEW:0:7}, renamed")

git switch -c "sync/upstream-${NEW:0:7}" origin/main
git cherry-pick --no-commit "$PICK" || true      # resolve any conflicts here
git checkout HEAD -- LICENSE
sed -i "s/$LAST/$NEW/" engineering/runbooks/getzilla-upstream-sync.md
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_getzilla_identity
```

Then run the full suites, commit, push and open the pull request. If the guard flags a new line, either the rename rules need a new case (update [the rules](getzilla-rename-rules.md)) or the line quotes a frozen predecessor record and gets a `predecessor-record` marker.

## When to stop syncing

Syncing is a bridge. Once new work happens in Getzilla directly, freeze the predecessor (archive the repository on GitHub) so the two stop diverging.

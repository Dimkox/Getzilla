# Release state

`RELEASE_STATE.json` is the machine-readable answer to "what is the source, and what was published":

- `source.version` / `source.state`: the version in `VERSION` and whether it is a `source_candidate`
  or `released`. A version in `VERSION` is never a published artifact by itself.
- `published`: the last published release (tag, tag object, commit, tree, artifact digest), or `null`
  when nothing has been published. It is never filled from the source version.

`getzilla.release_state.validate_release_consistency` keeps it equal to `VERSION`, `PROJECT_STATE.json`
and the README release line; the test suite runs it.

## Exact-source release gate

`decide_release` allows the next, separately authorised publish step only when, for the exact commit
and tree being released, every required check concluded `success` (skipped, cancelled, neutral and
pending are not success; a green run of another head does not count), a review is bound to that tree,
nothing changed after the checks, and the tag does not already point at other source. It publishes
nothing and adds no human gate beyond the repository's policy.

## Artifact receipts

`artifact_receipt` measures the artifact built from the decided tree; `record_artifact` stores the
receipt beside the artifact (never inside it, so no file hashes itself) and refuses a different
digest for the same release. `mark_publication` records `published` or `failed` after the separate
publish step; a later metadata commit never rewrites published bytes. Real tags and GitHub releases
need the owner's explicit decision.

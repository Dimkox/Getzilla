# Local verification inherited a private-output umask

During [PR #413](https://github.com/Dimkox/Getzilla/pull/413), the coordinator's auxiliary launcher set umask `077` for private evidence, then passed it to the verification driver and test children. A newly owned Factory staging fixture requested readonly `0444` files but received `0400`; strict release validation correctly refused them.

Five new filesystem-only observations isolated the mode behavior: ordinary `022` produced `0444`; inherited `077` produced `0400`; descriptor chmod restored `0444`; child-only `022` produced `0444`; the parent remained at `077` and still produced `0400`. This probe did not execute Factory or replay an old workload.

Keep private evidence at `077` and set the ordinary test child's umask to `022` at its launch boundary. Separately, Factory now applies its declared readonly data mode through the held descriptor before fsync, so legitimate restrictive callers remain supported. The new staging control covers `002`, `022`, `077` and `027` without changing the caller's mask.

The failed verification report remains failed. This finding does not explain all historical Core exit-124 results, the absent final Core counts, or the separate 53-failure run. Each unresolved cause remains unqualified.

The coordinator also created its fresh Git worktree under inherited `002`. Git status stayed clean while ordinary committed files had physical mode `0664`. A closed HEAD list and exact blob/checkout-byte proof permitted removal of only unwanted group-write from 6,239 files in this new worktree; other worktrees and custom/untracked files were untouched. This does not explain all 51 failures in that later Core run.

Review snapshot creation now supplies `022` only to its Git checkout child. A new two-file Git fixture verifies committed `0644`/`0755` leaves, nested `0755` directories and private `0700` root under caller `002`/`022`/`077`, while retaining custom source modes and caller state. Consumer payload mode preservation and archive policy stay unchanged.

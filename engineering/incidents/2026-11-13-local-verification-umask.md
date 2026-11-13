# Local verification inherited a private-output umask

During [PR #413](https://github.com/Dimkox/Getzilla/pull/413), the coordinator's auxiliary launcher set umask `077` for private evidence, then passed it to the verification driver and test children. A newly owned Factory staging fixture requested readonly `0444` files but received `0400`; strict release validation correctly refused them.

Five new filesystem-only observations isolated the mode behavior: ordinary `022` produced `0444`; inherited `077` produced `0400`; descriptor chmod restored `0444`; child-only `022` produced `0444`; the parent remained at `077` and still produced `0400`. This probe did not execute Factory or replay an old workload.

Keep private evidence at `077` and set the ordinary test child's umask to `022` at its launch boundary. Separately, Factory now applies its declared readonly data mode through the held descriptor before fsync, so legitimate restrictive callers remain supported. The new staging control covers `002`, `022`, `077` and `027` without changing the caller's mask.

The failed verification report remains failed. This finding does not explain all historical Core exit-124 results, the absent final Core counts, or the separate 53-failure run. Each unresolved cause remains unqualified.

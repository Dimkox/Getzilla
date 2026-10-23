# PR 144 continuation

Continue the approved work in PR 144 for issues 138 and 143. Compare the complete candidate to main `01f67873ea17949208f92c83d34d0af38a586779`. The starting head is `f74aa2650aec9731fc4c1239525008af64b3f8c6`.

Repair imported queue return provenance, select security review for architecture nodes that hold secrets, and update cross-platform test fixtures for source-bound review plans. Keep operational approval gates and legacy receipt compatibility. Do not claim measured cost savings from added metrics.

Acceptance: paired queue regressions distinguish ordinary values from returned queues; a baseline secret still selects security review after its removal; restricted data still selects data review; source-bound receipts reject missing and stale plans; focused and full checks pass on the frozen candidate.

One implementation owner writes this branch. Four independent analyses precede repair. Reviews follow committed controls. Run the complete final PR verifier after reviews. The host snapshot allows 26 workers; implementation tests use at most 24. Logs and complete reports remain in local runtime evidence.

The owner's L5 contract authorizes source repair and process decisions. No production mutation or security approval is requested. The controller recorded the local scope disposition as `controller-under-owner-L5` for the existing PR 144 repair. This is not a human-signed approval or permission to skip exact-head CI.

Rollback: revert the repair commit through a pull request. Preserve historical incident archives and published release bytes. This continuation remains UNVERIFIED until current independent review, local verification and exact-head CI pass.

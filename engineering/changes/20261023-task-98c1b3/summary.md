# PR 144 continuation

Continue the approved work in PR 144 for issues 138 and 143. Compare the complete candidate to main `01f67873ea17949208f92c83d34d0af38a586779`. The starting head is `f74aa2650aec9731fc4c1239525008af64b3f8c6`.

Repair imported queue return provenance, select security review for architecture nodes that hold secrets, and update cross-platform test fixtures for source-bound review plans. Keep operational approval gates and legacy receipt compatibility. Do not claim measured cost savings from added metrics.

Acceptance: paired queue regressions distinguish ordinary values from returned queues; a baseline secret still selects security review after its removal; restricted data still selects data review; source-bound receipts reject missing and stale plans; focused and full checks pass on the frozen candidate.

The first independent review wave failed. Repairs preserve configured baseline and candidate review floors, order helper-return dependencies, share one nested-analysis budget, and reuse patch inventories inside each source analysis. Counter-based regressions cover a 40-function chain, repeated imports, cycles and shadowing. Complete failed reports remain historical runtime evidence.

Observation mistake: tests ran while source edits continued. Installer byte comparisons and cloned HEAD then observed different candidates. Freeze the source before broad observations; the mixed-source run is FAIL and cannot prove the current candidate.

The qualifying local PR gate on `3e67e1b7cdebf9037e90ab5c45a4334adb3e16c9` failed. Core tests, coverage, Factory tests, disposable PostgreSQL and scanners passed on that historical source, but background-job fitness exceeded its existing 32-module limit in `tests/test_verification_scope.py` and `tests/test_verifier_recovery.py`; governance then remained blocked. Keep that overall FAIL as historical evidence.

The repair separates method-local return demand and each imported member. Wave-three reviews rejected scalar-helper pruning: runtime dispatch and import rebinding can return queues despite the inspected helper body. Remove that proof completely. Preserve actual call effects and conservative container, shadowing and rebinding analysis.

The controller approved a measured resource calibration: 48 modules, 2 MiB source, 400,000 AST nodes and 4,096 shared work units per importer and side. The scope consumer needs 35 modules; both 48 and 64 admitted the same closure. With root source included, the repaired scope probe used 1,329,130 bytes, 222,202 AST nodes and 358 logical work units in 22.36 seconds (observed peak RSS 121,340 KiB). Recovery used 915,629 bytes, 149,134 nodes and 211 work units in 11.30 seconds (96,268 KiB RSS). These observations are not a RAM guarantee. Retain depth eight and per-file limits. Charge cached transitive sources, declaration shortcuts and summary preparation. Cache warmth and importer order must not reduce logical charges. Exhaustion stays unsupported with analysis_limit_exceeded and no fabricated queue trigger. Preserve the comparison base and checked paths.

Mistake: static helper syntax did not prove runtime binding. Subclass dispatch, arbitrary receivers, import rebinding and inherited attribute dispatch defeated that proof. Keep the reviewer cases as regressions. Process mistake: send_message did not restart a completed writer; use followup_task for idle work. Record these isolated incidents here because the shared mistakes index admits recurring lessons only. Preserve earlier failed gates and reviews as historical FAIL. Validate the complete inventory on the repaired committed head before fresh reviews and the next qualifying gate.

One implementation owner writes this branch. Four independent analyses precede repair. Reviews follow committed controls. Run the complete final PR verifier after reviews. The host snapshot allows 26 workers; implementation tests use at most 24. Logs and complete reports remain in local runtime evidence.

The owner's L5 contract authorizes source repair and process decisions. No production mutation or security approval is requested. The controller recorded the local scope disposition as `controller-under-owner-L5` for the existing PR 144 repair. This is not a human-signed approval or permission to skip exact-head CI.

Rollback: revert the repair commit through a pull request. Preserve historical incident archives and published release bytes. This continuation remains UNVERIFIED until current independent review, local verification and exact-head CI pass.

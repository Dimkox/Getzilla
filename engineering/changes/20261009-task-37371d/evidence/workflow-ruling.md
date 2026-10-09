# Frozen-state delivery ruling

Current source control conflict: getzilla-delivery says move tracked state.json to ready after final verification, but the reviewed-source contract admits only saved review reports between reviewed and frozen commits and any subsequent source/HEAD change invalidates receipts. change.transition writes tracked state/history; it does not validate PASS evidence on ready. Pre-marking ready before checks is not truthful.

Bounded ruling for this task: official lifecycle reaches reviewing before the reviewer candidate commit. Freeze tracked package state there. Actual local completion is determined by the final qualifying verifier, exact-source independent review receipts and getzilla_status zero gaps, then exact-head external PR gates. Keep final outcome in ignored bound receipts and GitHub task/PR, not by mutating state.json after freeze. No test/review is skipped, no fake ready/PASS is created, no file is excluded from the fingerprint.

prepare_deploy is a command printer requiring ready/released; it is not merge authority. Actual L5 repository merge/tag/release uses exact conditional standing owner consent and exact local grants only after relevant real checks/reviews/threads are satisfied. Production deployment remains separate. State-machine/helper redesign is a follow-up, not bundled runtime behavior.

Architect inspection: util.tree_fingerprint includes GitHEAD and changed-file bytes; _fingerprint_noise does not exclude package state; transition ready writes state and history, only approved transition has human-gate enforcement; getzilla_status validates evidence independently of ready. Read-only source observation, not independent code review or fresh PASS.

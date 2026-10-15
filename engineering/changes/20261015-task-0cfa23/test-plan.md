# Test plan — GZ-HOOK-ROOT-001

All shell command probes are synthetic hook inputs. No probe executes its payload or creates a real grant.

- RED: `taskset -c 0-5 python3 -m unittest tests.test_hook_shell_quoting -v` ran six initial methods and produced 13 failing subcases. It reproduced the exact gh/jq false denial, quoted and escaped operator failures, and lost word provenance.
- New focused tests cover literal data, code arguments, malformed and dynamic input, explicit worktrees, sensitive root conflicts, normal grant denial, source identity and log redaction. `taskset -c 0-2 python3 -m unittest tests.test_hook_shell_quoting -q` passed all nine tests in 3.309 s.
- Existing guards: `taskset -c 3-5 python3 -m unittest tests.test_hooks tests.test_harness_hook_payloads tests.test_pre_tool_circuit_breaker tests.test_policy_parser_gaps tests.test_policy_hardening tests.test_policy_bypasses tests.test_policy_shell_targets tests.test_harnesses -q` passed 184 tests in 53.086 s.
- Generator: `python3 scripts/getzilla_harness.py --write` completed with no generated diff.
- `python3 -m ruff check .getzilla/getzilla/_policy_legacy.py .getzilla/getzilla/shell_targets.py .grok/hooks/_lib.py .grok/hooks/pre_tool_use.py tests/test_hook_shell_quoting.py` passed. `git diff --check` passed.
- Bounded committed-HEAD observation: `taskset -c 0-5 python3 scripts/getzilla_verify.py --mode fast --no-record --test tests.test_quality_gates --budget 180`. Run after commit; this is not a verification receipt or scope admission.
- Independent code and test reviews follow the clean committed candidate. Critical parser checks need reviewer-owned scratch mutation probes. The coordinator persists complete reports, freezes again and runs the single final PR gate. That gate is not run during implementation.

Inventory is executable policy/hook/test source plus package evidence. The final selector must retain full PR scope; no focused-profile claim is made. Exact initial base/HEAD was `7cf4f65dd2ba9bb1390dc84c6185ba0f104255c8`; initial staged and unstaged product inventories were empty, and only this draft package was untracked. Final identity and committed-HEAD observation are returned to the coordinator.

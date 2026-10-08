# Test plan — Harden pre-tool hook policy against remaining authority, remove, secret-read and external-write bypasses

## Risk-based scenarios

| Priority | Scenario | Evidence |
| --- | --- | --- |
| high | git-core helper binary push is blocked | tests/test_policy_hardening.py::GitPushSpellingTests |
| high | abbreviated and Windows recursive removes blocked | tests/test_policy_hardening.py::RecursiveRemoveTests |
| high | quoted/expanded and recursive-reader secret reads blocked | tests/test_policy_hardening.py::SecretReadTests |
| high | interpreter text stays allowed | tests/test_policy_hardening.py::SecretReadTests::test_words_that_are_data_not_paths_stay_allowed |
| medium | bounded analysis fails closed | tests/test_policy_hardening.py::BoundedAnalysisTests |
| medium | gh/curl external writes require a grant | tests/test_policy_hardening.py::ExternalWriteTests |
| low | alternative publish/push clients classified | tests/test_policy_hardening.py::PublishSpellingTests |

## Automated checks

Focused: tests/test_policy_hardening.py and the existing policy/hook suites (test_policy, test_policy_bypasses, test_hooks, test_harness_hook_payloads, test_policy_shell_targets, test_protected_write, test_protected_write_hook, test_pre_tool_circuit_breaker, test_human_gates, test_harnesses); ruff; bandit -c bandit.yaml. Full: scripts/getzilla_verify.py --mode pr.

## Manual checks

Mutation probes (M10 quoted .env, M14 npm unknown-option publish, M17 --no-preserve-root) run in a private 0700 copy confirm the regression tests kill each mutant.

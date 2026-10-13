Recommendation: PASS for the bounded source repair at34bee4d. This is not an all-database PASS, deployment approval or final gate.

- Security: no blocking finding in the actual base-to-HEAD diff. Native cmd reaches existing command, size, root and policy checks. Invalid types/conflicts deny. The new denial helper retains DENY when root, fingerprint or ledger recording fails. Repeated invalid calls enter the exact/objective ledger. Ledger evidence stores hashes and generic reasons rather than raw command text.
- Security: generated launchers select the nearest marked project and preserve explicit valid project-env precedence. Hook-only planted subdirectories cannot replace the project. Nested installed consumers use their own hook code and route/denial state. The marker and environment are trusted workflow inputs, not an OS-enforced or cryptographic boundary.
- Security: build-system.requires now enters exact-pin inventory with provenance and rejects malformed requirement arrays. Factory/delivery setuptools84.0.0 replaces affected75.8.0. Trust CI84.0.0 stays unchanged. Consent metadata requires exact grants and conditional exact-head merge checks; it creates no signed security approval or deployed trust-policy authority. Release2.2.2 metadata introduces no external mutation.
- Double writes: none added for external systems. New writes are local denial-ledger observations under the existing lock. No command payload, production operation, image build or code upload ran in this review.
- Tests:46focused tests passed in21.391s. The independent marker probe passed. All8critical mutants were killed after expanding the build-only probe. Candidate identity remained unchanged.

Reviewed source: /home/pall/projects/getzilla/.getzilla/runtime/worktrees/fix-codex-cmd-20261011
Route43786cadd549 permits security_reviewer.
Comparison base540c12f93e798c2f483455a5086ab0018ac3216e.
HEAD before/after34bee4d1f10125e4e44e9835fc931595ff9f03a2.
Git tree before/afterf95ae47fca84b309b2386815b65c7008beb53fdf.
Fingerprint before/aftera7e378d0df851e1ff64c78fca8e6c6225eb4073ff4431ea01d5e9f6ed071eb9f.
Inventory before/after: clean, no staged/unstaged/untracked changes.
reviewed-tree-modified: no

Scratch: controller runtime reviews/20261012-codex/security-34bee4d/snapshot, outside candidate. Trusted non-sticky parent and reviewer directory mode0700. No-hardlink clone reproduced the exact clean candidate. TMPDIR points to private sibling scratch; PYTHONDONTWRITEBYTECODE=1. No candidate test artifacts or writes. Allocation CPUs12-17, at most4test workers; actual mutation tests run sequentially and provider reads use2workers.

Fresh checks and exact commands (relative paths below are under canonical /home/pall/projects/getzilla/.getzilla/runtime/reviews/20261012-codex):
1. From snapshot: taskset -c 12-17 python3 -B -m unittest tests.test_harness_hook_payloads tests.test_pre_tool_circuit_breaker tests.test_known_vulns -q. Result46tests, OK. baseline.log preserves output.
2. taskset -c 12-17 python3 -B security-34bee4d/marker-probe.py. Result: Hook-only child ignored; native DENY emitted. The command text is only a hook fixture, never executed.
3. taskset -c 12-17 python3 -B security-34bee4d/probes.py. Complete mutant bytes, exact child command arrays and failure output: mutation-results.json; summary probes.log. Each unittest child uses taskset -c 12-17 python3 -B -m unittest <test> -q in the snapshot.

- mapping: KILLED; test command taskset -c 12-17 python3 -B -m unittest tests.test_harness_hook_payloads.HarnessHookPayloadTests.test_normalization_preserves_input_and_does_not_invent_alias_contracts -q. Assertion failures were observed; no timeout.
- type: KILLED; test command taskset -c 12-17 python3 -B -m unittest tests.test_harness_hook_payloads.HarnessHookPayloadTests.test_codex_conflicting_and_malformed_commands_are_denied -q. Assertion failures were observed; no timeout.
- conflict: KILLED; test command taskset -c 12-17 python3 -B -m unittest tests.test_harness_hook_payloads.HarnessHookPayloadTests.test_codex_conflicting_and_malformed_commands_are_denied -q. Assertion failures were observed; no timeout.
- denial_exception: KILLED; test command taskset -c 12-17 python3 -B -m unittest tests.test_pre_tool_circuit_breaker.DenialCircuitBreakerTest.test_validation_denial_survives_root_and_ledger_failures -q. Assertion failures were observed; no timeout.
- ledger: KILLED; test command taskset -c 12-17 python3 -B -m unittest tests.test_pre_tool_circuit_breaker.DenialCircuitBreakerTest.test_native_validation_denials_record_exact_and_objective_retries -q. Assertion failures were observed; no timeout.
- nearest: KILLED; test command taskset -c 12-17 python3 -B -m unittest tests.test_harness_hook_payloads.GeneratedHookCommandTests.test_nested_real_worktree_uses_its_own_route_and_denial_state -q. Assertion failures were observed; no timeout.
- marker: KILLED; test command taskset -c 12-17 python3 -B /home/pall/projects/getzilla/.getzilla/runtime/reviews/20261012-codex/security-34bee4d/marker-probe.py. Assertion failures were observed; no timeout.
- build_inventory: SURVIVED; test command taskset -c 12-17 python3 -B -m unittest tests.test_known_vulns.CollectTests.test_build_system_exact_pins_keep_manifest_provenance -q. Initial provenance fixture repeated its backend pin in runtime dependencies, masking removal. Expanded build-only/current-inventory commands killed this same mutant with2failures; expanded-build-mutation.json preserves full commands/output.

Probe claims: mappingcmd, type guard, alias conflicts, denial retained under root/ledger/fingerprint exceptions, repeat-ledger participation, nearest nested source, installed marker and build-only inventory. Mutants restored only in scratch. No unresolved survivor within these8claims. The build mutant's initial survival is disclosed, not counted as fresh success.

Fresh vulnerability checks bound to this HEAD:
Scanner now38manifest rows/27unique exact versions, including all3setuptools84.0.0 build pins. Union with historical resolved Trust CI/runner graph gives46exact versions. Fresh OSV querybatch HTTP200,46results, zero hits, no pagination tokens. Direct authenticated GitHub queries reviewed/unreviewed/malware with pagination return zero records. All46Snyk PUBLIC exact-version pages HTTP200, no SNYK-PYTHON advisory-ID references. Public HTML matching is limited and is not a paid Snyk engine scan. Script/requests/results/HTML are security-34bee4d/fresh-advisories.py and fresh-advisory-results.json. Command: python3 -B security-34bee4d/fresh-advisories.py.

Historical/reused scope is explicit: transitive-resolution/ resolved the40-package graph at main540c12f, uv0.11.12, Python3.12.3/Linuxx86_64. Fresh hashes confirm TrustCIpyproject and runnerDockerfile inputs match reviewed34bee4d. That graph is reused input for new queries, not a newly resolved/deployed SBOM. Earlier provider-coverage.md uses original47-version inventory including affected75.8.0 and original26Snykpages; its CVEList/CISA/NVD/GitLab/paid-access observations remain historical within that scope. Fresh46page observations above extend public Snyk coverage for the current union. No old review PASS substitutes for these fresh code probes.

Residual risk and unexecuted claims: unchanged broad outer/import fail-open remains outside the bounded repair. Policy evasions across all shell grammars, emit-sink failures, all oversized/deep JSON inputs, arbitrary malicious installed projects and host-level isolation were not exhaustively tested. Ledger unavailable states retain DENY but cannot establish repeat counts. Private paid feeds, full NVD exact-CPE mapping, image/OS layers, wheel-bundled libraries, other platforms/Python versions, dynamic build requirements and actual deployment state remain unscanned. Other harness behavior is covered only by selected focused fixtures; no full platform matrix. No final full PR or external Trust CI gate was run by this reviewer. Final frozen-source gates and exact operational grants remain required.

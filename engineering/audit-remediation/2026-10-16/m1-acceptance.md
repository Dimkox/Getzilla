# M1 — Zero-Git MVP acceptance evidence (2026-10-16)

Branch `feat/audit-remediation-20261016` (base `c2bf95d`, audit snapshot tree `9f20ca2`).

| Gate item | Evidence |
|---|---|
| Original unchanged | `test_inventory_is_read_only`, `test_plan_is_read_only`, `test_original_has_no_git_and_is_unchanged`, `test_clean_python_source_end_to_end` (before/after tree incl. modes) |
| Admitted scan pass before persistence | `test_no_snapshot_before_scan_pass`, `test_changed_secret_bytes_never_written_even_temporarily`, `test_approved_path_replacement_is_stale` |
| Secrets absent from snapshot, Git objects, state, output | `test_secret_absent_from_snapshot_git_logs_and_index`, `test_unapproved_file_not_in_any_created_object`, `test_partial_git_objects_do_not_contain_excluded_bytes` |
| Provenance / tree / managed layer match | `test_root_and_managed_commits_distinct`, `test_source_to_git_link_verifies_without_self_reference`, `test_tampered_managed_or_source_file_fails` |
| Race / recovery | `test_crash_after_each_transition_can_resume_or_abort` (7 stages), `test_final_target_race_fails_no_replace`, `test_two_writers_do_not_both_publish`, `test_tampered_state_cannot_delete_foreign_path` |
| Installer boundary kept | `tests/test_installer_absent_boundary.py`, `test_materialize_existing_guard_survives_adoption` |
| No network, no client execution | `test_no_network_during_any_ingest_stage`, `test_no_client_process_exec`, `test_js_folder_adopts_without_running_npm` |
| Linux (claw, Python 3.12, 26 workers) | Zero-Git suites 115 passed, 4 skipped (Windows-only cases); full suite 1776 passed, 6 skipped |
| Native Windows (Windows Sandbox, Python 3.13, 8 workers) | Zero-Git suites 120 passed, 5 skipped (Linux/POSIX-only cases); found and fixed: read-only Git objects blocked abort/resume |

Not claimed: the imported application works (`project_health_status=not_run`); an atomic filesystem
snapshot (mode is `quiesced_two_pass`); absence of every secret (built-in rule set, `rules_digest`).

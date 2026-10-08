# TR-1 tests-only repair report

Date: 2026-10-07 UTC. Route `b1693e9cb114`; change `20261007-task-b1693e`.

## Exact scope and commit

Starting HEAD: `61861f819f7a2803261f752c5a5b61a90ac221d0`.
Repair commit: `9e78d893e0aaf1e894d726af85fc52c81dd056bf` (`Bind responsive landing sources to photo identity and format`).
Committed file: `tests/test_getzilla_landing.py` only, 8 insertions and 2 deletions.

The existing photograph srcset loop now checks every candidate filename against that picture's frozen expected identity, the candidate's declared width descriptor, and the extension corresponding to AVIF/WebP MIME or the JPEG img fallback. Existing local-file, dimensions, provenance and media checks remain. There is no new test module, dependency or product edit.

Product HTML SHA-256 remains exactly `185ffa66df11bce9becf04d3e15f180c1c908d596cf5f5d4170f001f36676a62`. HTML, template, analytics, image/font assets and product docs were not edited. Root's evolving workflow state was observed as unstaged but not staged or committed. No full gate or external write occurred.

## Reproduced mutation and verification

Private scratch: `/workspace/scratch/d8e33c67341b/getzilla-srcset-repair-0z72eeve`; owner-created non-symlink temporary directory, permissions 0700. Copied only the page contour and the test module/package initializer. The original candidate was never mutated.

Applied the review's exact wrong-photo mutation to index and template in scratch: replaced the first picture's entire AVIF source with the second picture's valid AVIF source. Both template parity and valid existing assets remained intact.

Command for every test observation: `python3 -B -m unittest tests.test_getzilla_landing -v`, 20-second subprocess timeout.

1. Before repair, mutant survived: exit 0, 14 tests, `OK` (0.076s).
2. After copying the repaired test into the same mutant, it was killed: exit 1, 14 tests, `FAILED (failures=1)` (0.067s). Only `test_local_photos_keep_provenance_dimensions_and_loading` failed for the intended identity mismatch: expected first photo `photo-1685716851721-7e1419f2db18`, actual donor `photo-1521737711867-e3b97375f902`, 360px AVIF. Assertion compares intended source binding before opening the asset.
3. Pristine candidate with repaired test: exit 0, 14 tests, `OK` (0.084s), no skips.
4. Changed-file lint: `/workspace/scratch/d8e33c67341b/getzilla-test-venv/bin/ruff check --no-cache tests/test_getzilla_landing.py`; exit 0, `All checks passed!`.
5. `git diff --check` passed. Commit inventory verifies only the authorized test file.

Full outputs are retained in the private directory:

- `before.txt` — surviving pre-repair mutant.
- `after.txt` — killed post-repair mutant, including exact assertion.
- `pristine.txt` — all 14 pristine tests pass.
- `ruff.txt` — changed-file lint pass.

Probe implementation: `/workspace/scratch/d8e33c67341b/audit-live/run-repair-probe.py`; metadata: `/workspace/scratch/d8e33c67341b/audit-live/srcset-repair-private.json`.

Ready for root's fresh bounded committed observation and affected independent test review. Source review's existing product findings concern unchanged HTML/assets; this repair creates no final gate or merge authorization.

## Exact retained outputs

### Before repair

```text
test_canonical_social_and_factual_schema (tests.test_getzilla_landing.GetzillaLandingTests.test_canonical_social_and_factual_schema) ... ok
test_controls_execute_click_and_keyboard_contract (tests.test_getzilla_landing.GetzillaLandingTests.test_controls_execute_click_and_keyboard_contract) ... ok
test_crawl_files_have_only_canonical_root (tests.test_getzilla_landing.GetzillaLandingTests.test_crawl_files_have_only_canonical_root) ... ok
test_current_pricing_and_request_link_retained (tests.test_getzilla_landing.GetzillaLandingTests.test_current_pricing_and_request_link_retained) ... ok
test_deployment_inventory_and_rollback (tests.test_getzilla_landing.GetzillaLandingTests.test_deployment_inventory_and_rollback) ... ok
test_existing_main_copy_and_photo_alts_are_frozen (tests.test_getzilla_landing.GetzillaLandingTests.test_existing_main_copy_and_photo_alts_are_frozen) ... ok
test_heading_ids_fragments_and_no_js_accessibility (tests.test_getzilla_landing.GetzillaLandingTests.test_heading_ids_fragments_and_no_js_accessibility) ... ok
test_local_fonts_and_licenses (tests.test_getzilla_landing.GetzillaLandingTests.test_local_fonts_and_licenses) ... ok
test_local_photos_keep_provenance_dimensions_and_loading (tests.test_getzilla_landing.GetzillaLandingTests.test_local_photos_keep_provenance_dimensions_and_loading) ... ok
test_normal_text_contrast_in_repaired_contexts (tests.test_getzilla_landing.GetzillaLandingTests.test_normal_text_contrast_in_repaired_contexts) ... ok
test_real_favicon_and_share_image (tests.test_getzilla_landing.GetzillaLandingTests.test_real_favicon_and_share_image) ... ok
test_resource_references_are_local_and_have_real_media_signatures (tests.test_getzilla_landing.GetzillaLandingTests.test_resource_references_are_local_and_have_real_media_signatures) ... ok
test_template_reproduces_production_bytes (tests.test_getzilla_landing.GetzillaLandingTests.test_template_reproduces_production_bytes) ... ok
test_tracking_bytes_location_and_reference_snippets (tests.test_getzilla_landing.GetzillaLandingTests.test_tracking_bytes_location_and_reference_snippets) ... ok

----------------------------------------------------------------------
Ran 14 tests in 0.076s

OK
```

### After repair, mutated copy

```text
test_canonical_social_and_factual_schema (tests.test_getzilla_landing.GetzillaLandingTests.test_canonical_social_and_factual_schema) ... ok
test_controls_execute_click_and_keyboard_contract (tests.test_getzilla_landing.GetzillaLandingTests.test_controls_execute_click_and_keyboard_contract) ... ok
test_crawl_files_have_only_canonical_root (tests.test_getzilla_landing.GetzillaLandingTests.test_crawl_files_have_only_canonical_root) ... ok
test_current_pricing_and_request_link_retained (tests.test_getzilla_landing.GetzillaLandingTests.test_current_pricing_and_request_link_retained) ... ok
test_deployment_inventory_and_rollback (tests.test_getzilla_landing.GetzillaLandingTests.test_deployment_inventory_and_rollback) ... ok
test_existing_main_copy_and_photo_alts_are_frozen (tests.test_getzilla_landing.GetzillaLandingTests.test_existing_main_copy_and_photo_alts_are_frozen) ... ok
test_heading_ids_fragments_and_no_js_accessibility (tests.test_getzilla_landing.GetzillaLandingTests.test_heading_ids_fragments_and_no_js_accessibility) ... ok
test_local_fonts_and_licenses (tests.test_getzilla_landing.GetzillaLandingTests.test_local_fonts_and_licenses) ... ok
test_local_photos_keep_provenance_dimensions_and_loading (tests.test_getzilla_landing.GetzillaLandingTests.test_local_photos_keep_provenance_dimensions_and_loading) ... FAIL
test_normal_text_contrast_in_repaired_contexts (tests.test_getzilla_landing.GetzillaLandingTests.test_normal_text_contrast_in_repaired_contexts) ... ok
test_real_favicon_and_share_image (tests.test_getzilla_landing.GetzillaLandingTests.test_real_favicon_and_share_image) ... ok
test_resource_references_are_local_and_have_real_media_signatures (tests.test_getzilla_landing.GetzillaLandingTests.test_resource_references_are_local_and_have_real_media_signatures) ... ok
test_template_reproduces_production_bytes (tests.test_getzilla_landing.GetzillaLandingTests.test_template_reproduces_production_bytes) ... ok
test_tracking_bytes_location_and_reference_snippets (tests.test_getzilla_landing.GetzillaLandingTests.test_tracking_bytes_location_and_reference_snippets) ... ok

======================================================================
FAIL: test_local_photos_keep_provenance_dimensions_and_loading (tests.test_getzilla_landing.GetzillaLandingTests.test_local_photos_keep_provenance_dimensions_and_loading)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/workspace/scratch/d8e33c67341b/getzilla-srcset-repair-0z72eeve/tests/test_getzilla_landing.py", line 165, in test_local_photos_keep_provenance_dimensions_and_loading
    self.assertRegex(
AssertionError: Regex didn't match: '^/assets/images/photo\\-1685716851721\\-7e1419f2db18-360-[0-9a-f]{12}\\.avif$' not found in '/assets/images/photo-1521737711867-e3b97375f902-360-276541ffc39e.avif'

----------------------------------------------------------------------
Ran 14 tests in 0.067s

FAILED (failures=1)
```

### Pristine repaired candidate

```text
test_canonical_social_and_factual_schema (tests.test_getzilla_landing.GetzillaLandingTests.test_canonical_social_and_factual_schema) ... ok
test_controls_execute_click_and_keyboard_contract (tests.test_getzilla_landing.GetzillaLandingTests.test_controls_execute_click_and_keyboard_contract) ... ok
test_crawl_files_have_only_canonical_root (tests.test_getzilla_landing.GetzillaLandingTests.test_crawl_files_have_only_canonical_root) ... ok
test_current_pricing_and_request_link_retained (tests.test_getzilla_landing.GetzillaLandingTests.test_current_pricing_and_request_link_retained) ... ok
test_deployment_inventory_and_rollback (tests.test_getzilla_landing.GetzillaLandingTests.test_deployment_inventory_and_rollback) ... ok
test_existing_main_copy_and_photo_alts_are_frozen (tests.test_getzilla_landing.GetzillaLandingTests.test_existing_main_copy_and_photo_alts_are_frozen) ... ok
test_heading_ids_fragments_and_no_js_accessibility (tests.test_getzilla_landing.GetzillaLandingTests.test_heading_ids_fragments_and_no_js_accessibility) ... ok
test_local_fonts_and_licenses (tests.test_getzilla_landing.GetzillaLandingTests.test_local_fonts_and_licenses) ... ok
test_local_photos_keep_provenance_dimensions_and_loading (tests.test_getzilla_landing.GetzillaLandingTests.test_local_photos_keep_provenance_dimensions_and_loading) ... ok
test_normal_text_contrast_in_repaired_contexts (tests.test_getzilla_landing.GetzillaLandingTests.test_normal_text_contrast_in_repaired_contexts) ... ok
test_real_favicon_and_share_image (tests.test_getzilla_landing.GetzillaLandingTests.test_real_favicon_and_share_image) ... ok
test_resource_references_are_local_and_have_real_media_signatures (tests.test_getzilla_landing.GetzillaLandingTests.test_resource_references_are_local_and_have_real_media_signatures) ... ok
test_template_reproduces_production_bytes (tests.test_getzilla_landing.GetzillaLandingTests.test_template_reproduces_production_bytes) ... ok
test_tracking_bytes_location_and_reference_snippets (tests.test_getzilla_landing.GetzillaLandingTests.test_tracking_bytes_location_and_reference_snippets) ... ok

----------------------------------------------------------------------
Ran 14 tests in 0.084s

OK
```

### Changed-file lint

```text
All checks passed!
```

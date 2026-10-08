# Approved migration-introduction branding repair

Starting HEAD: `04bd89da67048f633e5160a3888ac2b0018aa3cf`.
Repair commit: `b1a6fbb1d7521ee1a4dc126765324671e87952b6`.

The full gate's sole failure was inherited predecessor-name migration copy. Read-only exact-HEAD snapshot reproduction identified `index.html:729` and `template/index.template.html:729`; the same complete paragraph exists byte-for-byte at base `b7aa0a55f3236c578d4365f3f0e58ce5962cf319`, line 644. Diagnosis and complete assertion: `/workspace/scratch/d8e33c67341b/audit-live/identity-diagnosis.md`.

Coordinator explicitly narrowed the prior strict copy-preservation choice for this genuine existing branding defect. Changed only `Used adaptive-grok-build-pro before?` to `Upgrading an existing installation?` in both HTML files. The rest of the migration paragraph and all offer/Pricing/visuals remain unchanged. Analytics bytes/order/location remain frozen; existing tests confirm this. No marker, identity test, exclusion or gate change.

Updated the existing main-copy hash oracle with an explicit comment explaining this approved exception. Independently proved the new candidate normalized main copy equals original baseline main copy with exactly this one phrase substitution—no additional visible-text delta.

| Evidence | SHA-256 |
| --- | --- |
| Original normalized main copy | `a3d2060727a295dd57806ecb5ce630d28593d8b6f8dc8ce79529a01035ea4b07` |
| New normalized main copy | `70c6bf2a4e097bc61d2460d6bd9db772abb2f9fcb45000940ad003891bb394c9` |
| New index.html bytes | `92e2aa7999065e75b21f76809db46db0095029114e7a553e83093f95fe288604` |

Commit contains only `index.html`, `template/index.template.html`, and `tests/test_getzilla_landing.py`. No asset/doc/factory change or external operation.

## Bounded validation

`python3 -B -m unittest tests.test_getzilla_identity.GetzillaIdentityTests.test_no_predecessor_product_names_in_live_files tests.test_getzilla_landing -v`: all 15 tests pass without skips (named identity test plus existing 14 landing tests). Frozen analytics, template parity, strict copy and media checks pass.

Changed-file Ruff (`.../getzilla-test-venv/bin/ruff check --no-cache tests/test_getzilla_landing.py`): exit 0, `All checks passed!`.

`git diff --check b7aa0a55f3236c578d4365f3f0e58ce5962cf319`: exit 0, no output.

No new broad tests/browser/Lighthouse or full gate was run. Ready for root's scope/evidence/source binding refresh, archive rebuild and final gate.

## Full test output

```text
test_no_predecessor_product_names_in_live_files (tests.test_getzilla_identity.GetzillaIdentityTests.test_no_predecessor_product_names_in_live_files) ... ok
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
Ran 15 tests in 0.456s

OK
```

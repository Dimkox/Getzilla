# License normalization repair report

Starting HEAD: `92ee05edb2ff8c5fd9e8a626ad1a9d6f3122128c`.
Repair commit: `80a3e72cd3fab9f6c9c4872b4bd40b895bd42e5e`.

The coordinator authorized a bounded exception to the initial byte-identical license choice because the base-to-candidate whitespace gate flagged an upstream trailing space. Removed only the trailing ASCII space (`0x20`) after `embedded,` on line 21 of `assets/fonts/OFL.txt`. Every license/copyright word, line and other byte is preserved. No Git attributes, whitespace gate or factory setting was changed.

| License version | Bytes | SHA-256 |
| --- | ---: | --- |
| Original download | 4384 | `071195d8806e226faeee60259c28ca67b458227af5195a73f5cfcab06e3003bc` |
| Distributed, one trailing space removed | 4383 | `7805ccc507e6dc0c0796f1afa4f03ad413a9d302a30a24f8dbeb1aeef07a6c17` |

Exact byte delta: −1 byte. ASSETS.md retains both source and distributed provenance; README and SERVER-SETUP now accurately describe preserved license text with this whitespace normalization.

Only these owned files were committed:

```text
side-projects/getzilla-landing/ASSETS.md
side-projects/getzilla-landing/README.md
side-projects/getzilla-landing/SERVER-SETUP.md
side-projects/getzilla-landing/assets/fonts/OFL.txt
```

HTML, template, analytics, WOFF2 files and photographs are unchanged. Current HTML SHA-256 remains `185ffa66df11bce9becf04d3e15f180c1c908d596cf5f5d4170f001f36676a62`.

## Validation

`python3 -B -m unittest tests.test_getzilla_landing -v`: all 14 tests pass, no skips. Full output: `/workspace/scratch/d8e33c67341b/audit-live/license-tests.txt`.

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
Ran 14 tests in 0.102s

OK
```

`git diff --check b7aa0a55f3236c578d4365f3f0e58ce5962cf319`: exit 0, no output, with the repair applied and again after commit. Root's workflow metadata was not edited. No new tests, full gate or external write occurred. Ready for root's archive/metadata refresh and final gate.

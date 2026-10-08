# Identity gate diagnosis (read-only)

Exact HEAD: `04bd89da67048f633e5160a3888ac2b0018aa3cf`. Candidate remained untouched.

Named test was reproduced against a private `git archive` snapshot of exact HEAD: `/workspace/scratch/d8e33c67341b/getzilla-identity-diagnosis-17olgsd5`, permissions 0700. Command: `python3 -B -m unittest tests.test_getzilla_identity.GetzillaIdentityTests.test_no_predecessor_product_names_in_live_files -v`. Exit 1, one test failed. Full assertion below identifies only two product offenders; no workflow evidence offender.

Offenders:

- `side-projects/getzilla-landing/index.html:729`: predecessor product literal in migration note.
- `side-projects/getzilla-landing/template/index.template.html:729`: same note.

Exact existing line:

```html
<p class="note">Used adaptive-grok-build-pro before? Run the same <code>--plan</code> on your project. It keeps your own settings and lists every old file next to its Getzilla replacement.</p>
```

Both lines already existed byte-for-byte at base `b7aa0a55f3236c578d4365f3f0e58ce5962cf319`, line 644 in each HTML file. The defect is inherited, not introduced by this patch. The identity test scans tracked live text; engineering/changes records are already historical prefixes. Current frozen-main-copy test correctly retained this existing line, which is why the branding gate and the initial strict copy-preservation requirement conflict at this one sentence.

## Proposed exact minimal repair

Replace only `Used adaptive-grok-build-pro before?` with `Upgrading an existing installation?` in index and template. Keep the rest of the migration paragraph unchanged. This preserves the plan command, retained-settings assurance and migration advice while making the live page use current branding. It leaves the H1, offer/Pricing, typography, geometry and all analytics unchanged. No marker, identity test/exclusion or gate changes are needed.

Update only the intentional normalized-main-copy oracle in `tests/test_getzilla_landing.py` from `a3d2060727a295dd57806ecb5ce630d28593d8b6f8dc8ce79529a01035ea4b07` to `70c6bf2a4e097bc61d2460d6bd9db772abb2f9fcb45000940ad003891bb394c9`. That hash was computed from the current source with exactly this phrase replacement and no other change; it does not broadly bless arbitrary candidate copy.

Proposed product HTML SHA-256 would become `92e2aa7999065e75b21f76809db46db0095029114e7a553e83093f95fe288604`. Source file edit is pending coordinator's release/authorization. Source review, browser source binding and upload archive would need a truthful refresh after this intended one-phrase delta.

Recommended bounded validation after authorized repair: all 14 landing tests plus this exact identity test, changed-file Ruff for the test, base-to-candidate whitespace check, frozen analytics/template parity. Then root controls review metadata/freeze and the final gate.

## Actual complete assertion

```text
test_no_predecessor_product_names_in_live_files (tests.test_getzilla_identity.GetzillaIdentityTests.test_no_predecessor_product_names_in_live_files) ... FAIL

======================================================================
FAIL: test_no_predecessor_product_names_in_live_files (tests.test_getzilla_identity.GetzillaIdentityTests.test_no_predecessor_product_names_in_live_files)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/workspace/scratch/d8e33c67341b/getzilla-identity-diagnosis-17olgsd5/tests/test_getzilla_identity.py", line 129, in test_no_predecessor_product_names_in_live_files
    self.assertEqual(offenders, [], "predecessor identity found:\n" + "\n".join(offenders[:50]))
AssertionError: Lists differ: ['side-projects/getzilla-landing/index.htm[119 chars]pro'] != []

First list contains 2 additional elements.
First extra element 0:
'side-projects/getzilla-landing/index.html:729: adaptive-grok-build-pro'

+ []
- ['side-projects/getzilla-landing/index.html:729: adaptive-grok-build-pro',
-  'side-projects/getzilla-landing/template/index.template.html:729: '
-  'adaptive-grok-build-pro'] : predecessor identity found:
side-projects/getzilla-landing/index.html:729: adaptive-grok-build-pro
side-projects/getzilla-landing/template/index.template.html:729: adaptive-grok-build-pro

----------------------------------------------------------------------
Ran 1 test in 0.667s

FAILED (failures=1)
```

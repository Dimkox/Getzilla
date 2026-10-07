# Independent code-review supplement — migration question identity repair

## Verdict

**PASS for this narrow affected delta.** The current production HTML and template equal the previously frozen files with exactly the authorized single question replacement. The strict normalized-copy oracle equals original base main copy with only that substitution. Analytics remain byte-identical, and the unchanged named identity guard plus all 14 existing landing tests pass. No new finding or repair is requested.

The complete initial source review, TR-1 follow-up and OFL normalization supplement remain historical evidence with their original identities and limitations. Their unchanged product findings are not repeated or represented as fresh browser/media tests here. The original claim of fully unchanged main copy is now qualified by this disclosed question. The prior full-gate failure remains a failure; this bounded supplement does not relabel it or qualify the final candidate.

This report is source-review evidence, not merge authority. Any later remote commit metadata is outside this exact reviewed identity. The coordinator must independently establish equal source tree, adopt the actual remote HEAD and execute the required final local and applicable external exact-head gates.

## Identity and isolation

| Field | Before and after review |
| --- | --- |
| Route / change | `b1693e9cb114` / `20261007-task-b1693e` |
| Candidate / branch | `/workspace/scratch/d8e33c67341b/getzilla-seo` / `codex/getzilla-seo-v111` |
| Original base | `b7aa0a55f3236c578d4365f3f0e58ce5962cf319` |
| Prior frozen comparison HEAD | `04bd89da67048f633e5160a3888ac2b0018aa3cf` |
| Reviewed HEAD | `ef7574324876d9859d6ef6265929af5fa34263b4` |
| Reviewed Git tree | `fa2307871107d5b4f357c3f24a2b73da3abedb53` |
| `getzilla.util.tree_fingerprint` | `0eccd154a7871fefc5338047197f0bc74d16fd357295cc987944be30f747c4c9` |
| `git status --porcelain=v1` | Empty before and after: no staged, unstaged or untracked changes |
| Private parent | `/workspace/scratch/d8e33c67341b/code-review-identity-sck77mxz` |
| Exact-HEAD archive snapshot | `/workspace/scratch/d8e33c67341b/code-review-identity-sck77mxz/candidate` |
| Parent safety | Reviewer-created `0700`; verified non-sticky |

reviewed-tree-modified: no

Resource observations were recorded before inspection: nine online CPUs, affinity and effective cpuset `0-8`, cgroup v2 quota `800000 100000` (eight CPU equivalents). No widening was applicable. Work used one lightweight Python process with the existing bounded Node child. Snapshot creation used `git archive ef7574324876d9859d6ef6265929af5fa34263b4`, extracted only under the private parent. Inspected HTML/template snapshot bytes were compared directly with exact `git show HEAD:<path>` bytes. Tests and generated artifacts remained outside the candidate, with Python `-B`. There is no OS-enforced isolation claim.

## Reviewed change and disposition

Read the complete `evidence/identity-diagnosis.md`, `identity-repair-report.md`, current archive metadata, affected source diff, implementation-brief exception, review-resolution exception and outside `bounded-observation-identity.txt`.

The first full gate at `04bd89d...` identified the inherited predecessor-name question in both live HTML files. Its complete failure remains documented. The coordinator explicitly narrowed the earlier copy-preservation choice for this one question while leaving the user's analytics invariant absolute. At `index.html:729` and the corresponding template line, only:

```text
Used adaptive-grok-build-pro before?
```

becomes:

```text
Upgrading an existing installation?
```

The remaining migration advice, command, retained-settings assurance and all offer/Pricing text stay unchanged. `tests/test_getzilla_landing.py:209–211` documents and updates only the strict main-copy hash; the existing test still freezes the full normalized text. README discloses the question change. `tests/test_getzilla_identity.py` is independently byte-equal to the prior candidate; no identity guard/exclusion/marker, scope selector or gate was modified.

The closed product delta derived from `git diff --name-only 04bd89da67048f633e5160a3888ac2b0018aa3cf..HEAD`, excluding only the active workflow package, is exactly README, production HTML, template HTML and `tests/test_getzilla_landing.py`. No asset, font, analytics-reference, hosting or factory file changed.

## Fresh executed evidence

### Full HTML byte comparisons

Old bytes were obtained with `git show 04bd89da67048f633e5160a3888ac2b0018aa3cf:<path>` for each HTML file. Assertions required exactly one old-question occurrence and:

```python
assert prior.count(old_question) == 1
assert prior.replace(old_question, new_question, 1) == current
```

Both assertions pass for both complete files. Production changes from 60,861 to 60,860 bytes; template changes from 60,903 to 60,902 bytes. No other byte differs.

| Measured item | Result |
| --- | --- |
| Current production SHA-256 | `92e2aa7999065e75b21f76809db46db0095029114e7a553e83093f95fe288604` |
| Current template SHA-256 | `4b2579caa1cfeedd877ade80e34f5cbffec9450348f798678d8d4a8e25dff71b` |
| Original-base normalized main copy with exactly the question substitution | Directly equal to current normalized main copy |
| Independent resulting normalized-copy SHA-256 | `70c6bf2a4e097bc61d2460d6bd9db772abb2f9fcb45000940ad003891bb394c9`, equal to the updated oracle |

The copy comparison reads the original base via `git show b7aa0a55f3236c578d4365f3f0e58ce5962cf319:side-projects/getzilla-landing/index.html`, extracts `<main>` text with `HTMLParser`, collapses whitespace, applies only the question substitution, then compares to the current normalized text. Thus the oracle is checked against the approved baseline transformation rather than merely trusted because the test passes.

### Analytics

Independent regex extraction and byte equality against the original base confirm:

- Head block: 1,014 bytes; SHA-256 `c45825f2f9b0117307fe0fbf5c875ef0b9ab15d19e3cfd481045ef91c47fdb04`.
- First noscript block: 130 bytes; SHA-256 `3576068d6e4ac30fc0bc8b3cffe297bec5180da34462409ab106ec00d2f4e679`.

The existing landing tests also recheck their location, reference snippets and template parity. The whole-file sole-substitution proof leaves no scope for a simultaneous script/order/attribute change.

### Only the assigned existing tests

Executed in the private snapshot with a 40-second timeout:

```text
python3 -B -m unittest tests.test_getzilla_identity.GetzillaIdentityTests.test_no_predecessor_product_names_in_live_files tests.test_getzilla_landing -v
Ran 15 tests in 0.727s
OK
exit=0; no skips
```

Resolved interpreter: `/opt/codex/runtimes/codex-primary-runtime/dependencies/python/bin/python3`. This is exactly the named existing identity test and the existing 14-test landing module; no other test suite was run. Complete output is in private `tests.txt`; executed commands, byte checks and outputs are in `checks.json`.

The coordinator's supplied committed observation reads `PASS python-named-smoke`, exit 0 in 0.553 seconds, stable source, `scope=not-run`, `receipt=not_recorded`. It remains bounded observation, not the final gate.

## Accounting and limitations

Current archive metadata records 80 public files, 3,466,692 uncompressed bytes, archive SHA-256 `a165931e036ae512364ecfae65b2c4544e4e2520d3fc6c7fc259847ce019aef6`, and the exact newly measured production-page hash above. The one-byte HTML reduction is consistent with the recorded public-size reduction. The coordinator reports every archive entry was compared; this reviewer read the metadata but did not repeat ZIP verification.

No new tests or mutants, broad mutation campaign, media decoding, browser/Nu/Lighthouse work, fresh original-download retrieval, full gate, remote API operation, push, merge or deployment was performed. Direct complete-byte and baseline-copy comparisons are the relevant fault checks for this assigned small repair; no mutation score is claimed. The newly recorded local browser/Nu observation is coordinator evidence, not a run performed by this reviewer. Earlier wider browser/lab measurements remain bound to the earlier page, differing by this disclosed question.

All earlier limitations concerning other browsers/assistive technologies, actual hosting/MIME/cache behavior, production backup/readback, vendor dashboards, ranking/field metrics and CI/merge authority continue to apply. No credentials or subagents were used. Final HEAD/status/fingerprint match their initial values. Persist this supplement with the complete previous reports, then qualify the actual final candidate through the required gates.

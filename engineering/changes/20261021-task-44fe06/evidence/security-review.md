PASS for the Core source. No new Medium or High finding remains. Six known Low findings stay deferred to issue 122.

Reviewed the full comparison diff and surrounding code. The audit now requires opt-in from captured committed bytes. CI rejects null or skipped EU reports. The untracked Git reader honors ordinary global/system ignore rules while pinning Git directory and worktree. It strips other inherited Git overrides, disables replacements and fsmonitor, and bounds time and output. Strict capture checks decision inputs separately, so ignore rules cannot admit them. No duplicate external mutations were found.

Fresh evidence used the exact private snapshot under `/home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/security-wave3`. The trusted parent and reviewer directory had mode `0700`. Tests used a private temporary directory there.

| Command | Observed result |
|---|---|
| `taskset -c 16 python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/security-wave3/probe_security.py optin` | Enabled control: exit 0. Committed-disabled control: exit 2. The prior capture race was rejected because compliance.json differed from committed input. Same HEAD and clean final fixture status. Real reads; no evaluator result mock. |
| `taskset -c 18-21 python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/security-wave3/run_boundary_tests.py` | 5 passed, 9 subtests passed in 1.95 seconds. Covers null/skip refusal, global/system ignore parity, Git directory/index/object/inline-config redirection, ignored decision-input rejection, timeout/output limits and malformed path inventories. |

The test helper runs `pytest -q -n 4 -p no:cacheprovider --tb=short tests/test_eu_audit_attestation.py -k 'null_or_skipped or global_and_system or global_excludes_cannot or global_ignore_cannot or inventory_is_bounded'` in the snapshot. Its initial env-prefixed invocation was denied for ambiguous command root. The one rewrite through this explicit private helper ran successfully. No hook changed.

Probe SHA-256: `cc2f43b910c3234eba663a8f3aab0f88ab42eaf2c66b7ff33c9278b6e8987dd2`. Test-helper SHA-256: `b9f7d0898b847db325b77ab0032efca1d9b03b57a5f5cc84c68b862dd2143964`.

Historical evidence only: wave 2 tested Windows refusal, exclusive retry and real Node forced timeout on HEAD `61827791b7f49a5ad340a62f07756888a03964a3`, tree `96612a25a2dca3ed8e306f622e82ed2c8b3cbecf`. Those product files remain byte-identical. These controls were not rerun and are not fresh passes. Native Windows, real C2PA signing and real signed-V2 integration remain unexecuted here. The verifier executable and public key remain operator trust inputs. Code/test reviewers own source mutation probes; this review added none. No full gate ran. This is not human security approval or merge authority.

Route: `44fe064efbab`. Candidate: `/home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-phase2`.

Candidate and scratch snapshot identities matched before and after:

- Base: `287e64f99b01db44cb6eeeb10f307ccda6f91c1d`.
- HEAD: `cf18a79cf1e97a4100e9999be7ce212e3f258974`.
- Tree: `c815f538aa54997519674497ec3776dccd199a9d`.
- Fingerprint: `a6f96921f402d3b375a369079bc1e2be676ff8db37b07b54b15ef1041b525fdf`.
- Staged, unstaged and untracked inventories: empty before and after.
- Comparison inventory: 49 added/modified paths. Exact private inventory: `security-wave3/inventory.tsv`, SHA-256 `f02aef2876ab16832678c4c9936cfcbcfbb9cb68303ca6c302933fd6e25c53de`.

reviewed-tree-modified: no

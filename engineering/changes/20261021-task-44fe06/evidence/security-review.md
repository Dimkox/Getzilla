FAIL. One Medium finding remains. The three wave 1 findings are repaired.

- **Medium — live opt-in check can disagree with captured source.** `scripts/getzilla_audit_bundle.py:106` checks the live configuration before capturing committed inputs. A concurrent file change can satisfy that check while the captured configuration remains disabled. `_compliance()` then skips EU evaluation at line 290, and `ci_check()` returns PASS at line 315. The private probe returned `decision=pass` with `compliance.eu_ai_act=null` for a committed opt-out. HEAD and final Git status stayed unchanged. Require enabled opt-in from the captured committed bytes. Add a regression that rejects this capture race and any skipped CI audit result. This finding requires concurrent local file mutation; it does not establish an attack against an immutable deployed runner.

Reviewed the full comparison diff and surrounding audit, filesystem, evaluator, adapter, contract and test code. No duplicate external writes were found. Verifier arguments and environment remain restricted. V1 remains separate from V2 authority. Known Low test gaps remain deferred to issue 122.

Fresh private probes used `/home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/security-wave2/probe_security.py`. Its SHA-256 is `d35490d0a30879cc1654cdd47e2c6d678328466c6a02ed4d9fcd676be3b22d23`. The trusted parent and reviewer directory had mode `0700`. The snapshot reproduced the complete clean candidate.

Each command used `taskset -c <CPU> python3 -B <private-helper> <mode>`:

| CPU / mode | Claim and observed result |
|---|---|
| `12 inputs` | Valid installed fixture first returned exit 0 / PASS. Changes and deletions hidden by skip-worktree were rejected with exit 2 for all five data inputs and one committed executable. Ignored rules and provider maps were also rejected. Restored fixture returned exit 0 / PASS with clean status. |
| `13 optin` | Enabled control returned exit 0. Committed-disabled control returned exit 2. Deterministic file swaps around real reads returned PASS with null EU compliance and clean final status. No evaluator result was mocked. Finding reproduced. |
| `14 platform` | Windows and missing descriptor API simulations refused before any mkdir/open creation call. Native POSIX creation passed. Repeated creation failed without changing bytes. |
| `15 node` | The unmodified Node adapter stopped a real stubborn child after 30.09 seconds. It returned exit 0 with `c2patool timeout`, no marked bytes and unchanged source. Cleanup completed. A later process check found no fixture processes. |

No source mutants were added. Code and test reviewers own the required mutation probes. Captured rules/provider use, fixed HEAD/base/date, sanitized Git and fingerprint construction were inspected. Their separate mutation results are not claimed here. No full gate ran. Real signed-V2 integration, native Windows execution and real C2PA signing remain unexecuted. The verifier executable and public key remain operator trust inputs. This review gives no production or merge authority.

Route: `44fe064efbab`. Candidate: `/home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-phase2`.

Candidate and scratch snapshot identities matched before and after:

- Comparison base: `287e64f99b01db44cb6eeeb10f307ccda6f91c1d`.
- HEAD: `61827791b7f49a5ad340a62f07756888a03964a3`.
- Tree: `96612a25a2dca3ed8e306f622e82ed2c8b3cbecf`.
- Fingerprint: `53a32ef677284d79a7de11b13b81176fce0e520d485d247c522883f21cb5c733`.
- Staged, unstaged and untracked inventories: empty before and after.
- Comparison inventory: 49 paths, added or modified only. Exact inventory: private `security-wave2/inventory.tsv`, SHA-256 `f02aef2876ab16832678c4c9936cfcbcfbb9cb68303ca6c302933fd6e25c53de`.

reviewed-tree-modified: no

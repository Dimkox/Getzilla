**PASS — independent Core wave 4 security review.** No new High or Medium finding. The six Low items in issue #122 remain nonblocking. This review adds no finding.

- Scope: security, duplicate external writes and tests. Reviewed the full base-to-HEAD diff and relevant surrounding code. Route `44fe064efbab` permits `security_reviewer`. No candidate code or receipt was written.
- Candidate: `/home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-phase2`. Base: `f9f02dd53ba9f6e69d51ae5322df0c96e3d41b02`.
- Before and after, candidate and private snapshot both had HEAD `ccfe4a404c33003ede0cf0ef42c0faf91f9ce67d`, tree `889358dc9453cf77df73ec23dd0ed7f10f6c1229`, fingerprint `24262cfdb7ad5afd747b4ad924f32ecfff9271336b97fdf7fa3744cda03c34c8`, and empty staged, unstaged and untracked inventories. Base-to-HEAD inventory: 55 added or modified paths. The exact `git diff --name-status` output is `security-wave4/changed-paths.tsv`, SHA256 `60ef5052cd97836da5dc8d6814276b38d8940dacbc5c94ba2dd1d27be5323527`.
- Private scratch: `/home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/security-wave4`. Its parent, own directory and exact snapshot are non-symlink directories with mode `0700`. CPU allocation was 16–21, with at most six concurrent processes. Source identity used the parent's `source_identity.py` before and after. `security-wave4/final-evidence.json` records the final identity and inventory checks.

Fresh commands and results:

```text
taskset -c 16 python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/security-wave4/probe_security.py optin
taskset -c 17 python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/security-wave4/probe_existing_verifier.py
taskset -c 18-19 python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/security-wave4/run_verifier_tests.py
python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/security-wave4/capture_final_evidence.py
```

- Capture race: valid installed-consumer control passed with all required committed inputs; committed opt-out returned exit 2. The transient opt-in was rejected because `compliance.json differs from committed audit input`. The fixture HEAD stayed fixed and its final status was clean. This is a valid baseline before tampering.
- Verifier boundary: trusted external fixture passed. Exact argv and external cwd matched. Supplied Python, shell, Node and loader settings were absent from the child environment. An existing project executable and an external symlink to it were both rejected before execution; the invocation marker was absent.
- Verifier subprocess test: `1 passed in 1.23s`. It exercised successful execution, nonzero exit, output overflow and timeout. These fixture verifiers do not establish cryptographic validity.
- Final identity capture passed. Helper SHA256 values, in command order excluding the identity helper: `cc2f43b910c3234eba663a8f3aab0f88ab42eaf2c66b7ff33c9278b6e8987dd2`, `734fadaae44777cf30db89c358b7d1e73f96020cfcd741d7ea8ab9fc2196029e`, `e86511720a266cd72ccd4552cfc80ccd2478cbe893f80b50a598400c71baad61`.

Static review found no new bypass. Captured committed opt-in, decision inputs and executable inputs remain mandatory. Fixed source identity and V2 command identity remain enforced. V1 stays unchanged. The audit, evaluator, scaffold and transparency templates match wave 3 HEAD `cf18a79cf1e97a4100e9999be7ce212e3f258974`. The new CLI guard refuses absent compliance before scaffold creation. Optional install paths preserve that boundary. Descriptor-based exclusive creation still refuses duplicate local writes. No new external mutation path exists. Test changes isolate fixture imports and retain covered denial plus explicit deadline and entry-limit controls.

Limits: code and test reviewers own the required source-mutation probes; this reviewer ran boundary controls and a scheduled capture race, not source mutants. Install and timing executions belong to those reviewers and are not claimed here. Windows refusal and real Node timeout results remain historical at wave 2 HEAD `61827791b7f49a5ad340a62f07756888a03964a3`; see `core-wave2-security-review.md`. Native Windows, real C2PA, real signed V2 integration and the full local gate were not run here. The pinned-venv objective remains NOT_RUN; host jsonschema is 4.10.3, while the new test pin is 4.26.0. No install retry was made. This is review evidence only, not merge authority.

reviewed-tree-modified: no

FAIL. Repair these three Medium findings.

- **Unchecked audit inputs — `scripts/getzilla_audit_bundle.py:55`.** `_committed_inputs()` omits `diff-risk-rules.json`. Changing this ignored file changed the real CI audit from BLOCK to PASS. HEAD and Git status stayed unchanged. `cost-providers.json` is another unchecked decision input by inspection. Bind all decision inputs to committed bytes. Add negative tests.
- **Windows scaffold path race — `.getzilla/getzilla/compliance_scaffold.py:74`.** Windows filesystem helpers retain paths, not directory descriptors. The scaffold omits the required identity checks. Swapping a parent after opening it caused an outside-project write and returned success. The probe emulated Windows helpers on Linux; native Windows remains untested.
- **Node timeout does not force termination — `.getzilla/templates/eu-ai-act/transparency/typescript/aiTransparency.ts:37`.** `spawnSync()` uses its default termination signal. A fixture tool that ignored that signal kept the adapter blocked beyond 33 seconds. Enforce bounded termination and test the real subprocess path. Current timeout tests mock this behavior.

The private scratch parent and reviewer directory had mode `0700`. The snapshot matched the complete clean candidate.

Probe commands used this prefix:

`taskset -c <CPUs> python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/security/probe_security.py <mode>`

| CPUs / mode | Observed result |
|---|---|
| `12-13 rules` | Original rules: exit 1, BLOCK. Changed ignored rules: exit 0, PASS. Same HEAD; empty Git status. |
| `14 windows` | Scaffold returned success; outside-project file created. Windows helper emulation only. |
| `15 node` | Outer timeout fired after 33.04 seconds. Input remained intact. The guard killed the process group and reaped the runner. A later process check found no fixture processes. |

The initial rules fixture lacked a dependency. The corrected fixture produced the result above. No source mutants were added. Code and test reviewers own the required mutation probes.

Static inspection found no duplicate external mutations. Exclusive scaffold creation prevents ordinary retry overwrites. Verifier execution uses fixed arguments, a restricted environment, output limits and process cleanup. Real signed-v2 integration, native Windows behavior and real C2PA signing remain unexecuted. The executable and public key remain operator trust inputs.

Candidate and scratch snapshot identities matched before and after:

- Base: `e158ddc7263a55f5308944c5a426eb1e9f1a4327`
- HEAD: `5e8b8734739c7f59f6c3af56b82dedc02fb1dcc5`
- Tree: `71beaeabf6e15d70a800333dced87e69f3ee33c5`
- Fingerprint: `d1a0a5184b8f6fd1852d0265b5f95004261e71bce72d7a9aa7da761a31ec214f`
- Git status: clean before and after.

reviewed-tree-modified: no

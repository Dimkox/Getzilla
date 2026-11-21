# Queue analysis repair reassessment — 2026-10-21

Prefer a measured finite-capacity correction to the current demand slicer. The frozen analyzer resolves the native graph with 64 modules and depth 16, while preserving every other limit and its existing analysis semantics. The earlier diagnosis that a resolver rewrite was necessary was too strong. This reassessment provides new measurement, not a replacement for the failed gate or a passing repair review.

The source under observation is Getzilla `4cf2abf21753e61383e3d89be593e0fb815afc7f`, comparison base `e158ddc7263a55f5308944c5a426eb1e9f1a4327`. No candidate code was edited. CPU affinity was 4–5. Temporary architecture materialization used private non-Git `/tmp/gz-arch-DLpzab`.

## Measured alternative

The first diagnostic run retained the original resolver and used finite in-process budgets of 128 modules, depth 32, 16,384 statements and 32,768 values/alias work. Instrumentation observed at most 42 modules/depth 5 for the verifier and 50 modules/depth 13 for the test. The interpreter's high-water marks were only 906 alias work, 775 values and 1,199 statements. Both target sources returned `no_queue` in 7.15 seconds. The extra interpreter capacity was not needed.

A second complete architecture-fitness probe changed only `MAX_QUEUE_ADAPTER_MODULES` from 32 to 64 and `MAX_QUEUE_ADAPTER_DEPTH` from 8 to 16 in memory. All original interpreter, loop, dependency-work and AST bounds remained. It returned fitness PASS in 11.108 seconds, with pre/post risk still red, no risk triggers and no generated required scopes. A further probe of `architecture_fitness.py` itself returned `no_queue` for both base and head in 4.075 seconds. This checks that the intended constants file does not already reveal another queue-analysis failure when inspected as changed source.

These observations support bounded headroom around measured work. They do not justify arbitrary future increases or a loop that raises limits until PASS. The source repair should change only the two supported capacities, document their measured rationale, and retain hard failure beyond the new bounds. Add 65-module and depth-17 negative controls, plus exact-boundary cases and tests using injected smaller budgets. Run the existing hidden/dynamic queue controls without removing assertions. Neither route risk nor rule severity should change.

The small capacity repair preserves the current algorithm's semantics. It cannot be described as proving that the current analyzer detects every possible import-time effect. A newly identified coverage concern below must remain explicit and be assessed separately.

## Import-time soundness

Importing a module executes its initialization even when the caller uses only a safe export. An import can execute package `__init__.py`, another otherwise-unused import, a helper called at module level, function defaults/decorators, class bodies/bases, metaclass work or `__init_subclass__`. Pruning unrelated function bodies is valid only after proving they are outside both the demanded value-provenance closure and this executed-effect closure.

Exact falsifying control: the consumer imports and calls `facade.selected`, which returns a constant. `facade` also imports `side_effect`, using either `import side_effect` or `from side_effect import value`. `side_effect` creates a queue and submits a job at module level. The analyzer must detect that effect or return unsupported, even though `selected` has no queue-derived return value. Repeat with the submission in a helper invoked at module level, a decorator/default, a class base/body and package initialization. A plain unused function containing that operation is a distinct control; its body need not execute on import.

The writer's current prototype fails both direct/from-import versions: it returns `not_applicable`. The retained RED log records two failures. The prototype therefore must not be committed as a sound repair. Preserving initializer AST alone is insufficient: module-initialization effects need a separate propagation channel from queue-derived exports. Replacing called helper bodies with `Pass` and recording only which exported names might return a queue can lose the helper's side effect. A module that has effects must not become safe because the selected export is absent from its queue-derived export set.

A correct slicer would require side-specific, bounded package/import-effect closure; demanded export/value closure; scope-aware helper and alias summaries; cache separation for effects and demanded values; conservative dynamic/cycle behavior; and resource charging across both closures. That is a larger security-sensitive semantic change than two measured capacity constants. A token/name dependency summary alone is not a substitute for proving side effects.

The writer's read-only inventory found 26 unconditional local module-level imports from the frozen verifier, excluding conditional and function-local imports. This is a lower bound below 32. It does not prove that the complete effect closure necessarily exceeds the old budget, nor that a sound slicer is impossible. The measured 50-module/depth-13 workload comes from the existing conservative resolver. Avoid claiming an intrinsic 32-module impossibility from the lower-bound inventory.

The writer also ran the exact falsifier against restored, unchanged `4cf2abf` production code. It failed with two assertion failures and zero errors, confirming a pre-existing coverage gap. The retained log is `getzilla-gate-import-effects-baseline-confirmed.log`. Capacity tuning cannot claim to fix that concern. Preserve the result and scope its repair explicitly; do not silently convert it into accepted evidence merely because native fitness passes.

## Evidence and completion boundary

Files under canonical `completion/`:

| Artifact | SHA-256 |
|---|---|
| `getzilla-gate-architecture-capacity-probe.json` | `982161af594efe905b8f96a81bfba8fdd6091fe2c172ce22d11acd20d807dc34` |
| `getzilla-gate-architecture-capacity64-fitness.json` | `36e98634d2cc8db33ee58810bf40fe9689556e5db8967f7f198bc9647aae3242` |
| `getzilla-gate-demand-import-effects-red.log` — writer's prototype control | `6fbee9ec54ef37bb5d6f3d38246918072869a1d35aec9d17ef14fb55a47ee5ef` |
| `getzilla-gate-import-effects-baseline-confirmed.log` — unchanged baseline control | `f41ced92955af069f15d52e055ef7dc9a53b8493a80cade4b97ce05e71bae517` |
| `getzilla-gate-import-closure.json` — writer's lower-bound inventory | `8fbf6e70311528b30ab9610c2670d4f8ad9a393589a4966bdc443bdb03eb6884` |

`getzilla-gate-architecture-capacity64-self.json` records the additional base/head self-analysis probe. All capacity observations are marked probe-only and use unchanged committed source with explicit in-process diagnostic overrides. They are not final verification receipts. The chosen repair must receive focused controls, fresh independent whole-diff reviews, a new frozen candidate and the full qualifying gate. Preserve the original failures, the abandoned slicer evidence and the earlier architecture diagnosis with their original identities.

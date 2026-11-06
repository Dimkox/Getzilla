# Finite queue-analysis policy calibration

The fixed module budget is64 unique source paths, including the importer,
declarations and transitive cache footprints. A65th source refuses analysis.
This is an engineering resource policy. It does not establish queue identity,
prove a callable safe or permit a result from an uninspected source.

The earlier accepted calibration `eb72ad12203679d4da23fee4dde621bd68cef928`
changed32 to48 for a measured35-module closure. The November5 calibration uses
the complete verifier demand from frozen public source
`2f7d187709eb6aaed350acebc43ecf0f603f5968`, compared with accepted
`352d62450afea5821346a99cf47ebe8565717d42`.

An owned exact-source copy used the existing observer with a private in-memory
engineering budget. These are **nonqualifying observations**, not a final gate,
scanner result or acceptance of either source. The original48-module refusal
remains a failure; it is not relabelled as a pass.

| Observation |48, cold|64, cold|64, warm|
|---|---:|---:|---:|
| Outcome |module limit refusal|complete, not_queue|complete, not_queue|
| Unique source paths |48 admitted|53|53|
| Source bytes |1,757,656|1,848,937|1,848,937|
| AST nodes |289,851|317,738|317,738|
| Logical work |450|489|489|
| Actual work |1,798|2,067|161|
| Analysis wall seconds |26.058|31.091|1.526|
| Analysis CPU seconds |25.567|30.513|1.517|
| Child peak RSS, KiB |192,564|221,500|224,480|

Cold and warm runs have identical source path/digest/size/node sets and logical
charges. Their source iteration order can differ. Peak RSS includes loading and
observer bookkeeping; the byte budget is not a peak-memory guarantee. Each
observer child had a120-second wall bound and1GiB address-space ceiling. These
measurements do not promise the same cost for every admitted graph or host.

Only `MAX_QUEUE_ADAPTER_MODULES` changes. The2MiB aggregate source limit,
400,000 aggregate AST nodes,4,096 shared logical-work units,200,000 individual
AST nodes, adapter depth8 and64 source roots remain. Exact source identities,
cache charging, side separation, conservative demand resolution and proof
rules remain. No candidate/environment override or alternate service exists.
The changed code remains bound by the existing exact-source review identities.

The regression uses real64/65-source Git fixtures, counting the importer, with
a queue-bearing source inspected after the former48-source frontier. It checks
both import orders, reexports, cold analysis and warm/cache replay. Separate
real-source fixtures exhaust bytes, aggregate AST and individual AST budgets;
the work, depth and source-root refusals remain required. A graph within64 can
still refuse under another limit or fail its queue proof.

This prerequisite does not close issues138 or316. The empirical process-cost
targets and complete strict scanner/native coverage remain separate mandatory
work. Existing scanner/accounting candidates and their historical failures are
unchanged. No scanner, provider, model, authentication or deployment ran for
this calibration.

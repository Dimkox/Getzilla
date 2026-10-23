# Tasks and dependencies

- Completed: startup discovery; 14 physical cores, 28 logical CPUs, 26 verified workers after reserve.
- Completed: fetch main and isolate fix/pr127-validation-20261023.
- Completed: four read-only analyses in parallel, one CPU each.
- Active: one integration_implementer owns product source and tests. Coordinator owns workflow records. No overlapping writers.
- Next: bounded controls, clean source commit, smoke.
- Next: code/test/security review wave; each uses private scratch and at most eight test workers.
- Next: persist reports, freeze, final full local gate and external exact-head CI.
- Next: receipts, thread resolution and conditional L5 exact-grant merge.

Agent slots: one controller plus twelve children; route analysis cap ten. Test-process limit is separate. Final verification may use all 26 CPUs after other checks finish. Implementation and review are ordered because reviews require a stable source.

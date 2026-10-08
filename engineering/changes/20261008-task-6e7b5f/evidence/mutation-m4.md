# Mutation check for M4 (#41)

The mutant changes `.getzilla/getzilla/queue_provenance.py:216` from
`return _unbounded_sequence(_aggregate(current))` to `return _unbounded_sequence(NON_QUEUE)`.

| Tree | `test_sequence_widening_keeps_pre_loop_queue_in_its_summary` |
|---|---|
| shipped (origin/main 851499c) | 1 passed, 12 subtests passed |
| M4 applied | 12 failed |

The mutation was applied in this worktree only, and the file was restored from a copy afterwards. `git status` confirmed that only the test file changed.

Under M4, the `concatenation`/`index` case reported `uncertain=False` with no enqueue signal. That is a genuine false pass that the old `uncertain or signal` assertions could not catch.

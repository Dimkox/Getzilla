# Same-process public study composition

These are the current production ports. This document grants no execution
permission. The operator must use the exact registered candidate and current
owner session. Missing admission, source custody, runtime enforcement or review
facts must stop the sequence. Do not regenerate IDs or retry the holdout.

Keep one operator process alive through both operations and the review handoff.
Opaque A, conditions, INSPECT operation, native result and B references cannot
cross JSON, pickle, a new Python process or an independently rebuilt object.
The ordinary `execute` CLI remains unavailable; it cannot recover those objects.

After the parent has supplied the concrete protected registration paths, the
composition uses these calls in this order:

```python
from getzilla.state import bind_session
from getzilla.retrieval.public_review_witness import witness_public_reviews
from getzilla.retrieval.research_use_conditions import require_public_research_use
from getzilla.retrieval.public_study_operation import register_public_study_operation
from getzilla.retrieval.public_study_inspection import witness_public_inspection
from getzilla.retrieval.study_driver import run_fixed_study
from getzilla.retrieval.study_supervisor import check_study_inspection_result

bind_session(current_owner_session)
a = witness_public_reviews(root, phase_a_registration)
conditions = require_public_research_use(root, conditions_registration)
inspect_op = register_public_study_operation(
    root, 'inspect_public_artifacts', inspect_registration, a, conditions)
inspection = run_fixed_study(inspect_op)
observed = check_study_inspection_result(inspection.inspection_result, inspect_op)
```

The conditions reference must describe the exact extracted-software-held state,
not acquired archives. INSPECT itself proves the actual owned resource before
native imports. Its result must report succeeded execution, confirmed cleanup,
native-completed and a real resource readback. An incomplete or failed result
cannot qualify B. An exception or absent result must remain unavailable.

At this point keep `a`, `conditions`, `inspect_op` and
`inspection.inspection_result` in that same process. Give independent reviewers
the immutable `observed.report_relative_path`, its exact SHA/size and the
same-folder mapping/native-facts artifacts from `inspection.artifacts`.
Reviewers publish through the existing agent report/delivery owners. The B
registration has kind `operator-public-inspection/v1`, schema_version1, an exact
`manifest` path/bytes/SHA reference and `reviews` publications. Each publication
contains annotation, reports, delivery and delivery_assurance. The existing B
owner reads those exact retained bytes and checks independent coverage of
tokenizers, windows, graphs, runtime, codec and resources. A report dict or a
coordinator's own positive statement is not that publication.

Once those actual independent deliveries exist, resume the kept-alive process:

```python
b = witness_public_inspection(
    root, phase_b_registration, a, inspect_op, inspection.inspection_result)
rank_op = register_public_study_operation(
    root, 'rank_public_study', rank_registration, a, conditions, b)
ranking = run_fixed_study(rank_op)
```

The rank registration must bind the witnessed contracts and exact current
exports. Every RANK preparation step still requires B; there is no lexical-only
bypass. The existing stable holdout label and CAS prevent a second attempt with
changed registration, principal or task in the same workspace. Failed and
unknown attempts do not release that claim.

The entire scientific sequence, including review waiting, must fit the original
14,400-second experiment deadline. The owner must derive the original deadline
from the genuine inspection result and existing execution record, then restrict
RANK to that deadline. A fresh RANK execution timeout alone does not establish
this condition. Until that cross-operation owner port is present, the full
sequence is unavailable; a caller-supplied timestamp cannot fill the gap.
Two-second source and query deadlines remain independent and cannot be renewed
by review completion, heartbeat, process replacement or a longer job ceiling.

Finally release held conditions with `close_public_research_use(conditions)` and
clear the session with `bind_session(None)`. Do not close conditions before the
last current-owner check. Process exit destroys opaque references; it does not
authorize a new attempt or convert retained output bytes into a result reference.

# Continuation journal rejected current Unix deadlines

Independent code and security reviews of candidate `cbcff1806ff7fa2a1848ac818cddf32fa0344423` found that `create_chain` used the request-count limit of 1,000,000,000 to validate absolute Unix seconds. Current dates exceed that limit, so valid chains failed with `invalid_task_budget`. Tests froze time at 1000 and did not expose the defect. No live adapter or dispatch was enabled.

The repair gives timestamps a separate finite bound and retains the existing attempt/request limits. A regression uses the current UTC epoch, checks successful creation and expiry, and rejects invalid timestamp types and overflow. Validate time domains with realistic epochs as well as small deterministic fixtures; count and timestamp bounds are different contracts.

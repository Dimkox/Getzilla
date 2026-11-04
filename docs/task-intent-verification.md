# Human intent and required verification

The existing canonical task, change package, verification report and receipt remain the sources of
state. Questions add bounded task data; a required plan adds a field to the existing verification
report. Neither creates another task ledger, orchestrator or authority grant.

## Record a question before affected implementation

The route's optional `intent_state` has schema version 1. The pre-existing classification string
`intent` keeps its original meaning. A question has a stable ID, text, source reference, exact
requirement targets and affected repository paths. Targets are typed objective, acceptance,
invariant or forbidden-outcome IDs, `original`, or an exact pending amendment ID. Paths are exact
relative paths or directory prefixes ending in `/`; an empty list means unknown impact.

Use `scripts/getzilla_route.py --intent REQUEST.json --json` with a repository-relative request.
The closed request contains:

```json
{
  "version": 1,
  "operation_id": "ask-count-1",
  "route_id": "CURRENT_ROUTE_ID",
  "logical_task_id": "CURRENT_LOGICAL_TASK_ID",
  "authority_epoch": 0,
  "context_revision": 0,
  "state_revision": 0,
  "operation": {
    "kind": "ask",
    "question": {
      "id": "Q-COUNT",
      "question": "Does the count include inactive rows?",
      "targets": ["AC-001"],
      "paths": ["src/count.py"],
      "source_ref": "human-request:count"
    }
  }
}
```

Read current identity and revisions from `scripts/getzilla_route.py --show --json`; the values
above are placeholders. Requests require the actual owned native session. An exact operation retry
is idempotent; an ID reused with other contents is refused. A stale revision or authority epoch
cannot overwrite a later decision. Questions survive handoff and restart. The maximum is 32
questions, 128 operations and 128 KiB; reaching a bound refuses new data instead of deleting history.

An `answer` operation contains `id` and an `answer` object with `text`, `source_kind: "human"`,
`source_ref`, `principal`, `event_id` (a stable ID or null), and `target_digest`. The digest is produced
by `getzilla.task_intent.target_digest(root, route, question)` over the affected requirement contents,
question text and paths. The initial `opened_digest` is usable while those inputs remain unchanged.
An unrelated requirement change preserves the answer; an affected change makes it stale and asks
for a human resolution of the current version. Repository text is not accepted as `source_kind`.

A `withdraw` operation uses the same human-answer fields and current digest with
`allow_missing=True`; it records why the question no longer applies, including removal of its
requirement. It preserves history. Restoring or changing the target invalidates that withdrawal.
Local provenance records do not authenticate a person's identity or replace native permissions,
human approval gates, independent review, or final acceptance evidence.

Draft specifications can capture questions using structural validation. Acceptance still uses the
existing strict specification gate, including rejection of unresolved `UNKNOWN` fields.

## Keep independent work available

The native pre-tool policy refuses an affected structured edit or recognized shell write while its
question is unanswered or stale. It also checks a writer that started before the question appeared.
Reads, analysis, test commands and clarification records remain available. Existing permission and
protected-path checks still apply. This is a native hook policy using the existing target parser;
it is not an operating-system sandbox for arbitrary programs.

Pending amendments are also checked before product writes. Unknown impact blocks product writes
until scope is synchronized. An exact pending-ID question with explicit paths and requirement IDs
can preserve provably independent work. Rejected input with unknown impact remains blocking.
Technical runtime evidence and the active package's question documents are not treated as product
implementation merely because they are writes.

Writer registration and the transition to `implementing` accept repeatable `--requirement ID`
arguments. Omitting them means the entire task. Only explicit existing independent IDs narrow the
scope; no new permission is granted. Verification and completion still check the whole task.

Routes without intent data retain their existing context binding. Routes with it use context
binding version 2 and include the intent digest. Old receipts stay readable, but cannot qualify a
newer task context. The completion continuation fingerprint includes changed human decisions.

## One plan from selection through completion

`getzilla.verification_plan.current_required_plan` derives a schema-version-1 `required_plan`
before dispatch. It binds Git head/tree and measured tree fingerprint, comparison bases, task and
criteria context, changed-file inventory, risk, delivery lane, profiles, applicability and producer
policy bytes. Installed producer bytes are bound even for a consumer without an embedded runtime.

Each obligation names a check, related requirements, required or not-applicable status, applicability
evidence, exact expected test references and frozen security-source projections. The compiler owns
this list; missing tools, unavailable data and unknown inventory do not remove obligations.
Recorded results bind to this invocation's plan and check ID after their actual producer returns.

The native quality gate and receipt consumer both derive the current plan again. They refuse
omissions, duplicate results, unknown/unexecuted statuses, changed source/policy/criteria, missing
individual test execution, wrong security family, source-projection changes and a source that no
longer passes the current reader's schema/hash/coverage/freshness checks. All required checks must
pass. A skip qualifies only when the current source-derived plan explicitly declares it inapplicable.
Unavailable sources stay required and blocked. Historical PASS without a plan is not current
qualification; rerun verification instead of upgrading a receipt in place.

Security obligations use the existing OSV check and six separate expanded families. Source readers
revalidate the approved inclusive 72-hour age limit when evidence is consumed. Local source hashes
and timestamps provide integrity and coverage observations; independent qualification remains at
the protected external CI/provider boundary.

## Existing test and stack selectors

Native requirement tests use `relative/test_file.py`, `relative/test_file.py::Class`, or
`relative/test_file.py::Class::test_method`. The runner discovers the actual file from the candidate,
checks its source origin, deduplicates selected test cases and records individual outcomes. Zero
tests, missing methods, skipped tests, expected failures and failed/error outcomes cannot prove a
required behavior. A same-named external Python package cannot satisfy a candidate test reference.

Configured verification-tool criteria keep their existing adapters. Exact references already
covered by those configured checks are not sent to the native unittest runner. Their reports must
prove the configured individual tests; an aggregate count does not substitute for them.

Node scripts, lockfile installation and TypeScript checks, installed Composer tools and Pilot tests
use the same selectors as their existing producers. A project without native Python discovery
inputs has an explicit source-derived skip, so Node/Composer verification does not pretend to run a
Python suite.

Rust, .NET, PowerShell, Go and Java/Kotlin runners declare planned check IDs before installing tools.
Their planner registration is tied to the actual runner function. Untouched stacks carry explicit
applicability evidence. A dynamic adapter without a declaration is `required-plan-incomplete`.
After execution, omitted or duplicated planned checks become failures; a toolchain blocker remains
an explicit not-run cause for every affected planned check. An aggregate successful result cannot
hide a missing command. Custom adapters must register a corresponding planner in `stacks.PLANNERS`.

## Delivery modes

Light tasks still need no change package. Fast mode qualifies delivery only for a freshly measured
light diff under the existing 50-code-line and sensitive-path rules. Mandatory applicable security
checks and actual criteria remain required. Full tasks require a qualifying PR/release run.

The focused static-landing command without recording remains a diagnostic. A recorded focused run
uses the required plan and applicable security checks. Typed tests outside its selected contract
require a wider verification mode; they are not silently ignored or silently expanded into a full
suite. Existing documentation/state exclusions remain explicit plan entries.

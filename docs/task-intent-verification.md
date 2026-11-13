# Human task intent

The existing canonical task, change package, verification report and receipt remain the sources of
state. Questions add bounded task data. They do not create another task ledger, orchestrator or
authority grant. Native verification also records the source-bound plan described below.

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

## Required verification

Before dispatch, native verification records one required plan: exact task and specification,
commit/tree/comparison bases, working-source fingerprint, full inventory, risk, selected profile,
policy source hashes and stable producer/prerequisite IDs. Registered stack planners must belong
to the actual runner. Compilation does not install tools or execute checks. Missing prerequisites
and undispatched required checks stay unverified. Genuine optional applicability needs a bound
source reason. A missing manifest for an explicit frontend profile is a refusal.

A typed `test` reference selects the corresponding source-owned unittest class or method. The
bounded criterion driver records unique case identities and closed outcomes. Imported, replaced,
missing, duplicate, skipped and expected-failure cases cannot borrow an aggregate Core PASS.
This proves execution identity, not test meaning. Agreed outcomes, independent review and required
critical negative or mutation controls still determine adequacy.

An existing typed `attestation` value `check:tool:public-api` can declare a required producer ID
(`tool:public-api` in this example). This is only a declaration pointer. It is not an external
attestation and grants no authority. The current adapter registry must declare that producer and
return its bound result. Missing configuration, an unowned ID, absent results and malformed or
duplicate pointers cannot qualify. No text keywords infer requirements. A declaration does not
schedule every expensive check or block unrelated authorized work.

The report retains all seven existing security families and complete structured findings. The
text view can show at most 200 vulnerability rows. QG and receipt consumption independently
rederive the current plan, source policy and data-source proof after report hydration. They need
an aware clock and trusted source validator. Source age is inclusive from zero to 259200 seconds;
future or older sources refuse. Creating a new report cannot renew acquisition time. Policy
hashes read the actual known loader's Python source bytes, including compressed installations;
an unavailable source never becomes an accepted null hash. These are local integrity observations.

Historical receipts remain readable. A receipt without a current required plan cannot qualify
today's work. Source, artifact, install/update and platform evidence remain distinct. Actual
UI/API/NFR measurements, independent publisher/App verdicts, recovery and operator acceptance
remain with their existing owners and later delivery phases. This source contract does not close
the original parent requirements or authorize production, private-key or provider actions.

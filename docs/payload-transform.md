# Payload transformation boundary

The pure helper is an offline, standard-library transform foundation. Its DTOs
do not authorize a source or send data. The optional Factory profiles below add
a concrete retained-byte transform to the existing authenticated local UDS path;
they do not qualify other native clients or transports.
`getzilla.payload_transform.inspect_native` returns `native_access_unavailable`
without iterating its input. Factory `ResultBroker.inspect` retains its existing
`runtime_wiring_missing` behavior. Existing path-read guards remain separate.

## One engine, two installed layouts

Edit `.getzilla/getzilla/_payload_engine.py`. The existing fixed-source command
`python3 scripts/getzilla_harness.py --repository-all --write` generates the
byte-identical `factory/src/getzilla_factory/_payload_engine.py`. Never maintain
the Factory mirror by hand. Drift/identity tests must pass before delivery.
The full-source generator uses the existing ownership/CAS transaction; it refuses
foreign output. A Core-only selected hook installation does not create Factory
files. A keep declaration cannot select a divergent Factory engine or silently
omit it. Existing installer directory inventory includes both source layouts.

Factory wrappers retain V1/V2 envelopes, strict JSON duplicate-key handling,
known-secret rules, typed errors and offline buffering. They import their own
generated engine. Core imports no Factory or database driver; standalone Factory
imports no whole Core. The native profile uses the same detectors with stricter
intermediate size bounds. It can conservatively refuse an intermediate expansion
that the legacy final-size-only policy would accept. Legacy behavior is preserved.

## Closed offline contract

`TransformPolicy` is frozen and versioned. It names a fixed `Purpose`, permitted
data classes, text/JSON mode, closed field rules and finite limits. A field path
is a bounded tuple of literal object keys. Actions are `keep`, `drop`, and
`redact_pii`; no expressions, callbacks, dynamic regex, wildcard paths or imports
are accepted. Overlapping/duplicate paths and sensitive output key names refuse.

JSON projection starts from an empty object. Unrequested fields are omitted.
Required missing fields and wrong primitive types refuse the whole result.
`redact_pii` replaces the selected field value with `[REDACTED]`; this is an
explicit schema-field action, not a complete detector for arbitrary free text.
Retained public/internal text uses the existing deterministic known-secret
redactor. Personal-class inputs cannot retain arbitrary text fields. Text mode
is limited to public-class inputs. Secret/unknown/unclassified sources refuse.

`SourceFact` carries the full namespaced source key, version, content and
representation hashes, transform version and class. These are offline factual
inputs, not verified source authority. `transform_candidate` preserves the
complete ordered input tuple, including sources whose fields were dropped or
redacted. It never labels a personal source public. Construction of a policy,
SourceFact, CandidateResult or checksum grants no permission.

Results contain immutable exact bytes, the complete source tuple and an identity
of the exact policy configuration. `payload_sha256` and `policy_sha256` are
consistency facts, not permits. The safe metadata view contains only fixed
state/reason, `qualification=algorithm_only` and `dispatch_permitted=false`.
It omits payloads, source keys/counts/hashes and exception details. Invalid error
DTOs cannot inject arbitrary diagnostic text.

Strict UTF-8, NFC/control rules, finite JSON values, duplicate-key refusal and
aggregate structure limits apply even to fields later dropped. Buffer copying,
native redactor intermediate expansion and encoded JSON output have bounds
before growth. Output is withheld until the whole result passes; failure never
returns a prefix. Cancellation propagates to the owner instead of becoming
successful output. One absolute deadline is checked across collection and
processing, including after slow iteration and policy identity construction.
It intersects the supplied original deadline with a two-second maximum from
entry. It never extends an earlier caller deadline or starts a fresh budget at
each processing stage.
An arbitrary blocked Python iterator cannot be preempted by this pure function;
the actual owned reader must provide bounded reads. Python buffer release is
not guaranteed memory erasure.

Hard ceilings are 256KiB input/output, 1000 aggregate records/chunks, 32 depth,
128 field rules and 128 complete source dependencies. Smaller policy limits win.
These are algorithm limits, not native performance qualification. Actual heap,
latency, token overhead and false-positive/negative denominators remain unmeasured.
The transform makes no model call or token/currency estimate.

## Registration contract for the existing150 owner

The trusted native150 host must select a fixed transform and purpose from its
actual registered computation/response, not from user/hook JSON. It obtains class
and full lineage from the actual current source owner, holds immutable captured
bytes, and calls the pure transform outside authority/task/source locks. It
retains the transformed buffer behind its own prepared-response reference with
the exact policy identity. It must retain its original captured dependency tuple;
offline DTOs do not replace that authority. Its registered consumer must verify
and send the retained exact bytes. A checksum alone cannot establish that.

Current source, permission, purpose, policy revision, actual audience, original
task/fence/stop and deadline need checks at read/preparation/admission/dispatch.
Use150's participating task/source/outbox cut and156/225's existing stop/unknown
outcome reconciliation. Do not add an ACL, credential source, grant hierarchy,
decision/attempt ledger, arbitrary sink callback or semantic declassification.
No disk, DB, network, model or arbitrary callback runs under the source mutex.
Revocation uses the actual durable-current publication cut. Previously admitted
effects can finish late; issued model bytes cannot be recalled or erased.

Missing/unqualified host, current lineage, transform or actual registered
pre-sink channel means unavailable before source acquisition. The fixed Factory
profiles below reuse the existing150 bridge; they do not add a permission issuer. Core remains optional and needs no DB. Ordinary local observations
keep their disclosed local grade and gain no protected fields or authority.

## Opt-in Factory local UDS profiles

Trusted parent code can select `AccessReleaseService(..., payload_profile=NAME)`
or `build_app(..., access_payload_profile=NAME)`. This is not a request field.
Default `None` preserves existing150 behavior and does not claim151 filtering.
Unknown profile names refuse. Ordinary standalone Factory startup imports no Core;
these optional profiles explicitly require Core's canonical transform engine.

The actual `LocalSourceAdapter` registration adds `classification`: `public`,
`internal`, `personal`, `secret` or `unknown`. Missing class means unknown. Class
is bound to the owner's full source key, version and pinned raw hash. It is not
accepted from a query, response, model label or public `SourceFact` as authority.
Unknown/secret or profile-incompatible classes refuse before any source read.
Current source authority, actual private-file custody and audience checks remain
mandatory. No class or omitted field declassifies its complete original lineage.

| Fixed profile | Allowed source classes | Retained output |
| --- | --- | --- |
| `factory.local-summary151/v1` | public, internal, personal | Canonical `records` array. Each source needs integer `record_count` in0..1000 and boolean `success`. Optional `contact_name` and `email` become `[REDACTED]`; instructions and all unrequested fields are dropped. No arbitrary personal text is retained. |
| `factory.local-public-context151/v1` | public only | Canonical `documents` array of `{content, untrusted_data:true}`. Known secrets, bounded email patterns and North American phone patterns are masked. This is not universal PII detection; internal/personal sources cannot use this profile. |

Both use the fixed `registered_tool_response` purpose. Text in public context
stays untrusted data; its wrapper alone is not OS or model injection isolation.
Source bytes cannot select tools, audience, profile, purpose or dispatch code.
The summary profile deletes instruction fields. Other clients, attachments,
provider requests and unrestricted context assembly remain unqualified.

The existing `FactoryNativeAccessHost` retains the original captured cut. The
service retains immutable transformed bytes, complete original SourceFacts,
class and exact policy identity behind its private prepared response. The same
`ResultBroker(access-local-text/v1)` and registered `UdsResultHandoffClient`
remain in use. Its existing binding stores a class/policy/lineage stamp; no ACL,
queue, grant hierarchy, attempt journal or arbitrary sink callback is added.
Preparation, release, claim and final dispatch verify original source/current
purpose/policy, registered destination identity, envelope scope/hash and exact
retained UTF-8 bytes. Transform work runs outside SQL and SOURCE locks and uses
the original task/deadline/output budget. Unknown outcomes never repost.

The supported sink is the existing authenticated local UDS result channel.
A provider adapter must implement its own real admission at that registered
sink. A DTO, transform result, digest, envelope label or passing fixture cannot
enable `openai_model_request` or authorize an external model call. The default
`inspect_native` and unknown provider transports remain unavailable. No paid
model call or ZDR claim is introduced. The existing bounded prepared cache and
Python buffer behavior are not a memory-erasure guarantee.

## Native acceptance still required

All six clients need actual trusted-parent integration: Grok, Qwen, Claude, Codex,
Gemini and Copilot. Existing generated PreToolUse/PostToolUse (Gemini
BeforeTool/AfterTool, Copilot preToolUse/postToolUse) are hook support, not proof of
final byte replacement. A post-event observation cannot undo already visible
data. Unsupported output/model hooks must yield an unavailable protected row.

Required real paths include full assembled model context; direct read/search/git
and shell stdout/stderr; registered MCP/tool arguments and results; attachments;
model/tool/child output; compact/resume/cache; file/report/export destinations.
Untrusted source instructions stay data. They cannot select tools, purpose,
audience, policy or registration. The actual host must mediate filesystem,
environment, network, child and response channels; a delimiter or Python type
does not enforce OS isolation.162 owns source/citation facts,159 owns custody and
observations,150 owns authority/outbox, and156 owns launch/stop/recovery.

Broader151/inherited148 acceptance remains separate: safe input and output filtering,
source-to-audience permission and derived lineage, PII/secrets, current revocation,
injection isolation, safe logs/errors/retention, native OS/client qualification,
adversarial regressions and measured false positives/latency/tokens. No Zero Data
Retention claim is made without actual contractual evidence. Public fixture,
compressed import, hook render and source checkpoint tests do not complete that
scope. Rollback keeps the affected protected channel unavailable; it does not
restore an unsafe fallback or replay an unknown delivery.

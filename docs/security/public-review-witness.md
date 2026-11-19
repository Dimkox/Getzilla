# Operator-witnessed public review inputs

`witness-public-reviews` is an explicit action by the current canonical task
owner. Its assurance is `operator-witnessed-public-only`. The automated
coordinator states that it directly observed the listed actual external
collaboration deliveries and independence. This is not an authenticated native
bridge, human security approval, private-data permission or model admission.
Unknown native generation stays null. Report metadata remains factual; old
parent context is not rewritten as current context.

The optional `retrieval-research` module stays disabled by default. The source
CLI action is:

```sh
python3 scripts/getzilla_retrieval_experiment.py witness-public-reviews \
  --session CURRENT_EXISTING_OWNER_SESSION \
  --registration .getzilla/runtime/owned-public-review/registration.json
```

The command must run in the actual project root. It requires current task
ownership, selected module, actual Git source identity, current policy and
protected context. It captures that current context separately from retained
older review observations. Default status and execution still load no models,
start no workers and grant no ranking. Phase B and native-auto Phase A/B stay
unavailable. `DraftAudit.require_rankable` keeps its existing refusal.

## Frozen request

Version1 registration requires these fields:

- `schema_version`:1; `kind`: `operator-public-reviews/v1`.
- `dataset`, `predecessor`, `public_sources`: private owned runtime directories.
- `config`: exact `{path,sha256,bytes}` reference.
- `author`: actual source facts `{agent_task,native_session_id}`.
- `groups`: initial, second and query review publications.
- `dispositions`, `no_answer_resolutions`: exact file references.
- Optional `query_revision`: exactly `original_query_report` and
  `language_supplement` references, only for the pinned rejected-v3 to reviewed-v4
  sixteen mixed-text corrections. Both original and fresh reports are retained.
- Optional `adjudications`: at most sixteen publications, each with exact
  `annotation`, `reports` and `delivery` references to actual third-source facts.

All input/report paths are relative private runtime paths with safe ownership,
regular single-link files and private modes. Stage new owned copies of actual
bytes; retain originals. The action does not chmod historical inputs. A file
reference has exactly `path`, `sha256`, `bytes`. The four dataset files are
`function-universes.json`, `partition.json`, `queries.json`, `full-qrels.json`.
The production wrapper hardcodes the original two public catalog hashes,
commits, function universe/order, partition/development-English pins, original
v3 predecessor hashes and experiment-config hash. JSON cannot select a profile,
callback, issuer or test composition.

Each publication group has exactly `role`, `original`, `annotations`, `reports`,
`delivery`, `delivery_identity`, `supplement`. Role is initial/second/query.
Second-source groups for the pinned query revision also require
`query_equivalence`, a list of exact `{annotation, delivery}` references from
that original second reviewer, covering every changed variant and its original
source slice. Unknown or changed meaning/label impact refuses admission.
`original` is the immutable original annotation reference. `annotations` has
one to four bounded schema-valid producer publications. `reports` contains one
to four original report/disposition references. `delivery` binds retained actual
tool-message bytes. `delivery_identity` retains actual task/session/generation
facts matching the annotations. These facts do not authenticate themselves;
the current owner's explicit action witnesses them. `supplement` is null for
an unchanged original or binds the genuine producer compact/slice lineage.

Parsed JSON remains8MiB/file and16MiB per original publication group. Oversize
originals are retained in custody, never overlimit JSON input. ONLY the exact
original large-A (b1e124…,12,774,653B) and large-C (2eb8d3…,8,591,594B)
producer identities have a separate explicit current-owner fingerprint action.
It reads and hashes the original body in its own bounded observation, then
records the producer identity, raw hash/length, supplement hash and physical
custody in the existing observation-only receipt store. Subsequent group
consumption checks that receipt's current source/context and original custody,
reads only genuine compact/shard bytes plus manifests/reports/deliveries, and
proves the logical reconstruction. Its manifest explicitly marks
`separate-operator-producer-fingerprint`; it never claims the consuming group
hashed those original bytes. Unknown producer cases or custody changes refuse.
 A group
has at most four shards; the preflight has at most16 groups,128MiB cumulative
read work and30 seconds with cooperative scientific-loop checkpoints. These
are factual preflight bounds. The original fixed four-candidate-file audit
retains its separate sixteen-MiB aggregate; report publication groups cannot
shard or replace those candidate files. They do not extend the unchanged128-document/
8MiB/two-second native source cuts or the production Factory profile. Actual
producer equivalence is explicitly operator-witnessed; no supplement boolean
alone grants admission.

## Scientific conditions

Initial and distinct second source reviews must cover every fixed cell with
matching function/span/file evidence. No cell may remain unjudged. Every final
cell must equal the independently source-reviewed final decision. Every
initial-to-second difference requires an exact coordinator disposition. Missing,
duplicate, reordered, self-reviewed, unresolved or cross-dataset evidence
refuses. Author eligibility/reviewer flags cannot replace these predicates.

Retain original v3 qrels and actual report bytes. Function, partition, query,
source and config identities stay unchanged; only the explicitly derived final
qrels change. The final qrels must equal the source-reviewed dispositions.
Do not rewrite first reports to claim that they read later final bytes.

A disposition file is `{dispositions:[...]}`. Each row has `corpus`, `task_id`,
`function_id`, `first`, `second`, `final`, `initial_report_digest`,
`second_report_digest`, `reason`. The report digests here are canonical parsed
annotation digests from `retrieval.contracts.digest`; the publication also
binds exact original and supplement byte hashes. They are distinct identities.

Query review covers every frozen variant, grouping and holdout novelty.
EN/RU factors must be `not_applicable`; mixed factors must be independently
supported `natural_identifier_mixed`. Weak, unresolved, unknown or contradictory
mixed factors refuse. The original query report is never relabeled. Limited
no-answer observations require complete first/second full-universe source
coverage, all final cells nonrelevant and an explicit per-cluster resolution.
That file is `{resolutions:[...]}`; rows have `task_id`, `query_report_digest`,
`decision: confirmed-no-answer-from-complete-source-reviews`, `reason`.
Remaining ambiguity or a genuine stratum failure refuses.

## Publication and use

The action publishes only an `observed` factual record in the existing protected
receipt store. Ordinary required verification/review kinds are unchanged;
witness kinds cannot satisfy merge checks, and their reader/writer reject PASS.
An opaque public-reviewed-input reference is issued only after the real owner
action and all predicates pass. Imported JSON, generic receipt reads, a reviewer
name, a historical seal or a test reference cannot mint production authority.
Exact replay is idempotent; conflicts refuse. Every consumption rechecks current
root/context/policy/source and all report/data byte identities. Changes invalidate
it. The reference retains reviewed-data facts, never source/model permission.

No actual full-corpus witness is claimed by unit tests. Their complete tiny
profile runs the same owner/publication/validation path but the production
wrapper and consumer reject that test profile. The real action remains
unavailable until actual complete review and scientific predicates are ready.

## Separate producer fingerprint action

Before the complete review witness, the current owner may explicitly run:

```sh
python3 scripts/getzilla_retrieval_experiment.py observe-public-producer \
  --session "$GETZILLA_SESSION_ID" \
  --registration .getzilla/runtime/owned-public-review/producer-a.json
```

The closed JSON request is `{schema_version:1,
kind:"operator-public-producer-reference/v1", original, producer_identity,
supplement}`. `original` and `supplement` are exact `{path,sha256,bytes}`
references. `producer_identity` is exactly `{agent_task,native_session_id,
native_generation:null}` with the genuinely observed original producer identity.
Only the two fixed raw hash/length pairs above are accepted. The action states
that the AUTOMATED COORDINATOR directly observed external producer delivery;
it does not attest native cryptographic delivery or scientific correctness.
Repeat the same action for C. Identical observations are idempotent; changed
custody, identities or supplement references conflict. An amended context or
source needs fresh observations; old source facts are retained honestly.
These original-body fingerprint reads receive no report-group or candidate
input byte credit and mint no reviewed-input reference. Full witness predicates
still verify the actual bounded lossless supplements and all scientific facts.

The current actual first large-B publication has 204,102 JSON value/container
nodes and therefore refuses the unchanged 200,000-node physical-document bound.
The original producer must publish a genuine bounded lossless supplement before
that actual group can qualify. No actual public witness or PhaseB reference has
been issued by this source slice. `reviewed_public_dataset(A)` returns the four
current parsed public data documents and factual hashes after consuming A;
these data objects confer no source, model, execution or output permission.

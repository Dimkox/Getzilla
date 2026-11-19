# Native access boundary

`getzilla.native_access` is the dependency-neutral interface for a trusted parent
which owns current identity, source and response admission. Ordinary Core imports
neither Factory nor PostgreSQL. `NativeAccessBroker()` has no host and refuses
before source IO. Installing Core does not enable protected access.

Only trusted application composition uses `_compose(NativeAccessHost)`. It binds
an actual authenticated native request and existing workflow resource to a
`NativeReadHandle`. SID, UID, roles, task text, manifests and saved checkpoints do
not authenticate that request. Private constructors and Python type checks are
programming checks, not a boundary against malicious same-process code. The
parent must be outside the worker write domain. No callback, class, path, URL,
connection or audience can be registered through query data.

`RegisteredQuery(reader_id, scope_ids, parameters)` snapshots bounded builtin JSON
parameters. Each fixed host reader validates its own closed request schema and
resolves registered source scopes. The broker admits at most eight request
handles, each with one immutable query and a two-second absolute lifetime; lower
caller or task deadlines win and never reset. Captured cuts contain at most128
unique source dependencies and8MiB total. One registered journal may use that
whole budget; each source intersects the remaining aggregate rather than splitting
its identity. Registered profiles enforce their stricter file/window ceilings.
Backend IO must
honor the same deadline; checking elapsed time after return cannot make arbitrary
filesystem/host IO interruptible. These are admission limits, not a performance
qualification.

`load_authorized_cut` checks current host and workflow state before and after the
read. It validates immutable representation hashes and keeps original and
transformed provenance separate. `OwnedSourceCut` is a process-local reference.
The host's current check must also revalidate already used source bytes, versions,
transforms and custody on cached read/preparation reuse; policy revision alone is
insufficient.
It is not a permit. Its bytes may be consumed only by the trusted registered
pipeline. Already read bytes cannot be erased by a later permission change.

`prepare_owned_response` accepts the owned cut, a registered computation and an
actual registered response channel. The host owns the transform and exact output
bytes; the entire input dependency union must remain attached. A plain reducer
result or saved JSON cannot supply that provenance. Unknown/missing lineage or
unqualified production transform refuses. Offline sanitizer tests do not qualify
a production151 boundary.

`admit_response` claims the prepared reference once before calling the host's
actual task/source/response admission. Errors or lost replies cannot cause an
automatic repeat. Existing operation IDs/dispositions remain authoritative. The
host must recheck current rights at the real admission and dispatch cuts; an
earlier successful check is not a reusable allow. Already-admitted effects may
finish after revocation, with actual or unknown outcomes retained. No DB/file/
network/model/caller callback runs under the source-permission fence.

Resume requires a fresh authenticated native request, and child delegation must
narrow the current parent under the same host. Their default implementation is
unavailable. No handle/cut/prepared reference is restored from JSON or pickle.

## Optional Factory bridge

`getzilla_factory.native_access.FactoryNativeAccessHost` is imported only by an
explicit trusted parent that already includes Core and Factory. Ordinary server
startup does not enable it. `FactoryTaskBinding` carries a real LeaseGrant and
execution packet reference; it is factual data, not authentication. Only the
actual current `AccessSession` and existing durable proposal-context check can
bind a request.

The initial fixed reader and computation are `factory.source-text/v1`. Scope
locators come from `factory_source_scope(full_source_key)` over the existing
server-owned LocalSourceAdapter, including every namespace component. Unknown
scopes/parameters/computations/responses refuse. Fixed optional payload151
profiles and the separate retrieval162 reader now compose with this same owner.
They are disabled by default; installing the bridge does not select a profile.
See [Factory retrieval](factory-retrieval.md) for its exact supported channel,
current-authority checks and remaining durable-retention limitation.

The bridge reuses the same source producer. Cached cuts and prepared responses
recheck the actual registered reader, byte/hash/version and current custody, not
only the permission revision. Native-prepared entries also repeat source checks
before release and before the existing dispatcher claim. Those reads occur
outside SQL/task/SOURCE locks, followed by the existing fresh task/source queue
cut. This does not make arbitrary filesystem changes atomic with external effects
or replace159's storage resource. Source, task and transformation changes refuse
the old cut; no second permission or attempt store is created.

This initial Factory profile has one source-result stage per existing checked
task/run/attempt/fence/packet. Rebinding keeps that stage's operation identifier,
payload/target and original deadline. A changed preparation conflicts. Admission
intersects that original deadline with the current request deadline; source
refresh, SQL bounds, queue admission and dispatch use the same smaller value.
A dispatch whose commit returns after that deadline refuses before transport;
this is not a hard real-time bound on database IO or already admitted effects.
Expired and consumed native preparations remain in the same bounded cache for
the service lifetime. Its64 total/16 per-principal limit includes those entries;
capacity saturation refuses new preparation rather than renewing old intent.
These entries retain their bounded owned buffers; they are not a durable permit
or a replacement for result/outbox replay checks after restart. Existing
result-admission idempotency and the unique outbox envelope remain the durable
replay fences, including after restart; an unknown outcome is not a new intent.
General Core225 operations and multiple162/200 computation stages still need
their real parent/operation binding and151 transform. A Factory run UUID is not
silently relabelled a Core logical task or customer identity.

This interface is an intermediate implementation, not a real Core consumer or
OS sandbox.162 retrieval,200 report and159 protected read/export must wire their
actual sole-owner entry points to the same frozen interface. The actual parent,
source/response,151 transform, file/search/shell/git/MCP/child/checkpoint and
filesystem/credential/connection profiles remain required. Ordinary local
report/export observations retain their existing disclosed grade. Full150 and
its six additions remain open. The previous committed83 cohort timingFAIL is
preserved with unknown cause; these unit controls do not clear it.

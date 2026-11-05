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
unique source dependencies,1MiB per representation and8MiB total. Backend IO must
honor the same deadline; checking elapsed time after return cannot make arbitrary
filesystem/host IO interruptible. These are admission limits, not a performance
qualification.

`load_authorized_cut` checks current host and workflow state before and after the
read. It validates immutable representation hashes and keeps original and
transformed provenance separate. `OwnedSourceCut` is a process-local reference;
it is not a permit. Its bytes may be consumed only by the trusted registered
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

This interface is an intermediate implementation, not a real Core consumer or
OS sandbox.162 retrieval,200 report and159 protected read/export must wire their
actual sole-owner entry points to the same frozen interface. The actual parent,
source/response,151 transform, file/search/shell/git/MCP/child/checkpoint and
filesystem/credential/connection profiles remain required. Ordinary local
report/export observations retain their existing disclosed grade. Full150 and
its six additions remain open. The previous committed83 cohort timingFAIL is
preserved with unknown cause; these unit controls do not clear it.

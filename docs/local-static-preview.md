# Optional local static preview

`getzilla_delivery.local_preview.NativeLocalPreview` is a separate, opt-in
Delivery adapter for **Linux x86-64 on Claw**. It runs the real trusted static
server in an owned child. It does not change the dry-run Delivery controller.
It has no default registration, authentication, background worker or network
activity. Import and construct with `enabled=False` to keep it disabled.

The profile is **private local AF_UNIX**, not public hosting. Web/API, worker,
database, user-code execution, arbitrary stacks, production parity and load-test
qualification are unsupported. No cloud provider or paid resource is used.

## Native use

Use the installed native `getzilla` package and the Delivery package together.
Bind the actual harness session through `GETZILLA_SESSION_ID`. Route the task
through the normal native workflow first. Then, from trusted host code:

```python
from pathlib import Path
from getzilla_delivery.local_preview import NativeLocalPreview

adapter = NativeLocalPreview(Path('/absolute/owned/project'), enabled=True)
files = {'index.html': b'<h1>Preview</h1>', 'style.css': b'h1{color:navy}'}
manifest = adapter.manifest(files, generation=1, key='current-artifact')
handle = adapter.create(manifest, files)
status, body = handle.request('/index.html')
assert status == 200 and body == files['index.html']
result = handle.revoke()
adapter.close()
```

A browser URL is not created. The host reads the local socket through the handle.
The filesystem socket is `0600` under an owner-only `0700` directory. Peer UID,
exact manifest binding and the current canonical task owner/epoch/context are
checked before bytes are released. The local OS account is the tenancy boundary;
this is not isolation between hostile sessions running as that same account,
enterprise identity, or a filesystem jail. Group-writable ancestors are allowed;
the private directory descriptor stays held, and source/project identity remains
bound. Callers must not share the owner account with untrusted processes.

## Binding and state

The closed manifest binds local tenant/project/repository, native logical task,
route run, actual owner, authority epoch, context revision, source HEAD/tree,
artifact hashes, trusted server code, declarative limits, generation, request key,
TTL and the existing task budget reference. Static inputs have no executable build,
external dependency or dataset; their explicit empty identities are validated.
Artifact paths are literal bounded members; no request path becomes a disk path,
command, template, import or program. Static script execution and external browser
subresources are blocked by the response CSP.

The repository-wide project lease covers linked worktrees too. One environment
can run at a time. Same-key/same-manifest replay returns the existing operation
without launching again or extending its deadline. A different manifest under
that key conflicts. Old generations cannot replace the current one. Interrupted
creation remains unknown when resource ownership cannot be proved; it is never
blindly repeated. New generations require the prior environment to be destroyed.

`ready` reports a loaded exact artifact and local transport. Functional verification
and human acceptance remain separate `not_run` observations until the caller's
actual scenario/normal evidence proves them. A real request is not an acceptance
receipt. Manifest changes invalidate old evidence. This adapter grants no merge,
publication, external action or production authority.

## Finite profile

- TTL: 60 seconds by default; integer 1–300 seconds. Monotonic time starts before
  launch. A child enforces expiry without the caller, and retries do not reset it.
- One child/environment per repository project; one request is processed at a time.
- Artifact: at most 64 files, 256 KiB per file and 2 MiB total. Inputs remain in
  memory; no untrusted artifact file is written or executed.
- At most 256 connections and 8 MiB of response bodies. Headers are also finite
  through the connection limit. Requests are capped at 1 KiB and 250 ms I/O.
- Child limits: 2 CPU seconds, 128 MiB address space, 32 descriptors, 16 KiB per
  evidence file, no core dump. stdout/stderr are discarded. These are enforced
  ceilings, not claims about CPU/RSS use or performance.
- Three seconds to send/start the trusted child, bounded by the original TTL;
  two seconds to confirm requested shutdown. No queued admission or paid retry.
- Zero spend; no paid adapter is admitted. The native task supplies the budget
  reference; this local profile does not create another money/grants ledger.

The child inherits only stdin, `/dev/null` output, its held directory and project
lease. Its environment contains no inherited credentials. A Linux seccomp filter
blocks IP socket creation, and real startup probes require both IPv4 and IPv6 to
return permission denied. Only AF_UNIX sockets can be created through the native
socket syscall. This narrow filter is not a general hostile-code sandbox.

## Revocation, cleanup and retained evidence

Expiry, canonical authority change, quota exhaustion or shutdown stop admission,
close the socket and remove only that exact owned socket inode. A child reports
`destroying` after socket removal. The observer reports `destroyed` only after
observing process termination. `process_reaped` is true only when this host owns
and has waited for that Popen child. An observer never sends a signal to a PID
loaded from metadata.

`handle.reconcile()` checks boot/start process identity and takes the original
project lease before removing a killed child's exact socket. A substituted file
or unknown process/lease leaves cleanup unconfirmed. Unique neighboring files are
preserved. No broad directory cleanup occurs. Unknown, shared or user-owned data
is never deleted to make a retry pass.

The project stores one private bounded state projection in
`.getzilla/runtime/previews/state.json`; subsequent generations replace this
projection. Locks and state remain after resource cleanup. Save the returned
manifest/outcomes with the current native package's existing evidence lifecycle
before replacement; the projection is not a permanent acceptance journal or a
new grants store. Disabling a newly constructed adapter does not hide or delete
an existing environment. Revoke/close it under its original owner first; its
finite TTL still applies if that owner disappears.

## Qualification scope

The real-child tests cover exact HTML/assets, missing/traversal paths, private and
unbound requests, malformed/oversized traffic, foreign tenant, owner handoff,
request quota, slow-client TTL, restart replay, linked-worktree quota, generation
fencing, verified process limits, IP-denial probes, killed-child reconciliation
and preservation of neighboring data. A separate real Claw smoke records the
exact source and manifest, request result, revoke, expiry and process cleanup in
runtime evidence. These results qualify only this local static profile. Public
hosting, other OS backends and production acceptance remain unqualified.

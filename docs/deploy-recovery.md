# Deployment recovery: public local workflow

`getzilla deploy recovery` connects the existing V1 preflight to a shared recovery
session and a working, fixed public fixture. It does not execute an operator,
read a credential file, contact DEV or grant deployment authority. Existing
`deploy preflight` and GitHub release preparation keep their contracts.

Create an explicitly empty directory that you own with mode0700. Use its absolute
path below. Initialization refuses a nonempty directory before creating files.

```sh
python3 scripts/getzilla_deploy.py recovery --root /owned/empty-public-fixture --action init --json
python3 scripts/getzilla_deploy.py recovery --root /owned/empty-public-fixture --action inspect --json
python3 scripts/getzilla_deploy.py recovery --root /owned/empty-public-fixture --action apply --json
python3 scripts/getzilla_deploy.py recovery --root /owned/empty-public-fixture --action recover --json
python3 scripts/getzilla_deploy.py recovery --root /owned/empty-public-fixture --action rollback --json
```

The fixture contains fixed inert operator text, two public payloads, a fictional
selector reference and public registration metadata. That placeholder is never
imported or executed; no credential file exists or is opened. These inputs do not
change an existing project's policy or establish customer identity. A normal
project without the exact fixture profile returns `PROFILE_UNAVAILABLE`.

The real CLI and Core consumer validate the fixed inputs, run the existing
bounded preflight, acquire the common lease, record intent before the local
effect, and independently read the target through another descriptor. Recover
and rollback use that durable history and current target identity/hash. Repeated
completion or rollback performs no second content write. The separate original
public payload remains available.

The fixture updates a retained owned inode. It **does not promise atomic pathname
replacement or all-or-nothing reader visibility**. A partial write, foreign target
replacement, unknown outcome or unsafe journal stops dependent mutation and
preserves state for inspection. This local effect profile does not qualify the
Pulse operator's replacement or remote effects.

## Shared exclusion and preserved ownership

`RecoverySession` uses an opt-in persistent `.release.lock` directory with an
immutable protocol marker, zero-byte kernel-lease file and append-only journal.
Marker root/lease/journal identities must match the opened objects. Same-path
replacement, including identical journal bytes on another inode, is refused.
All I/O is relative to retained directory descriptors using the existing
`BoundRoot` and `fsx` primitives.

The directory is never removed. Legacy mkdir clients remain excluded while it
exists, even after the current new client closes. All participating operators
must therefore migrate together. This is a deliberate availability tradeoff,
not a silent change to an existing deployment lock. An existing legacy/partial
directory without the marker returns `LEGACY_OWNER_UNKNOWN`; neither age, PID,
parent death nor a declaration authorizes deleting it.

New participants use the same retained nonblocking kernel lease. An owned child
can retain a duplicate of that same lease. Closing the creator's descriptors
does not unlock the child's open-file description. A remaining holder produces
`LEASE_BUSY`. Kernel exclusion is not evidence that a remote operation finished:
an explicit unknown outcome remains unknown despite matching target bytes.

The metadata library grants no credential or target-write authority. Its
consistency hashes, random generation and UID checks are not authenticated
customer identity, an OS sandbox or an operational permission. Real adapters
must preserve the common protocol, exact existing policy admission and their
own independently verified target semantics.

## Durable bounds and diagnostics

Journal frames contain closed hashes, stages, counters and generation IDs; no
payload, selector, raw exception, stdout or stderr is recorded. Each frame chains
to its predecessor. The limits are32 frames,2048 bytes per frame and65536 bytes
in total, with at most two effect and two rollback attempts. No automatic
compaction, truncation, counter reset or retention cleanup occurs. An incomplete
tail is preserved and refused. The caller owns the fixture directory and its
retention; this command performs no pathname deletion or GC cleanup.

A ten-second monotonic work cap is captured at entry and intersected with the
consumer's existing deadline. It is not renewed after validation or between
stages. Checks bracket bounded local I/O; they cannot interrupt a stalled kernel
call. The current native fixture profile requires POSIX descriptor/locking
support. Windows returns `MODE_UNSUPPORTED` before opening the root; it is not
qualified by a simulated refusal test on another platform.

Reports conform to
[`deploy-recovery-report-v1.schema.json`](../schemas/deploy-recovery-report-v1.schema.json).
They separate package/registration, fixture admission, recovery and local effect
from real connection/delivery. `operational_grant`, `dispatch_permitted` and
`dev_verified` are always false; real connection/delivery are always
`not_attempted`. A successful fixture exit is not DEV readiness. Fixed reasons
and next conditions never diagnose a password or server from a local refusal.

## Real delivery remains a separate qualification

Issue300 retains all nine upstream acceptance criteria. A real DEV adapter,
exact consumer/artifact/revision/selector/target admission, coordinated migration
of every shared-lock participant, whole-operation exit/outcome proof, real
publication/rollback semantics and independent target/function readback remain
mandatory. Snapshot repinning or this fixture's registration adds none of those
permissions. Preserve an unknown legacy lock; establish the actual common
exclusion and complete operation state before proposing its bounded migration.

The existing denial ledger and operation-scoped circuit breaker are unchanged.
This command does not clear a denial, retry a forbidden secret read, change a
consumer allowlist or create an approval. Independent permitted local work can
continue. Unknown target/journal/outcome conditions block the dependent effect
without being relabelled as failed authentication or a completed deployment.

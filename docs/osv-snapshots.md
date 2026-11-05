# Qualified offline OSV snapshots

The native OSV checker consumes a configured `GETZILLA_OSV_DB` directory without
network access. Each requested ecosystem needs a complete, validated snapshot.
An old `<ecosystem>/all.zip`, its modification time, or a copy of that ZIP cannot
establish acquisition, freshness or coverage.

## Acquisition and layout

An explicit `scripts/getzilla_vulns.py --download-db DIR` operation uses the
fixed official public OSV bucket and the seven native ecosystem names. A
qualified transport result records the requested URL, successful status, final
HTTPS origin and complete bounded body. Raw bytes returned by a legacy mirror
callback are refused. Public synthetic tests use explicit fake transports and
clocks; those fixtures do not attest to a real download.

Each ecosystem's authoritative `snapshot.json` binds the fixed source URL,
SHA-256, exact payload size, acquisition time and rederived archive coverage.
Objects live at `.snapshots/sha256/<digest>`. An `all.zip` export remains for
compatibility and is never an authoritative fallback. Copying a complete
qualified snapshot preserves its original verified acquisition time.

The inclusive valid age is zero through 259200 seconds (72 hours). Unknown,
future or older acquisition times refuse. Actual reads and pointer publication
sample the clock again after substantial work; querying multiple ecosystems
also confirms their held metadata and clocks together at its final boundary.
Explicit test clocks retain their supplied instant.

Publication stages and verifies an immutable object before switching one
manifest pointer. A definite failure before that switch preserves the old
pointer and bytes. A durable pending marker fences the switch: failed
durability or readback after a possible switch leaves `commit_unknown` or an
unavailable source. Consumers refuse that state. There is no two-file atomic
rollback claim. Do not delete a pending marker to make a source pass; it needs
checked reconciliation or a separately controlled clean acquisition target.
A safe compatibility-export failure may accompany a confirmed committed
pointer and is reported as a warning.

Acquisition metadata is unsigned local evidence. It does not independently
authenticate a publisher, runner or approval, and it grants no write authority.
The store requires exclusively controlled ancestry and content.

## Coverage and inventory

Every ZIP member is checked, including records that do not match the current
package or are withdrawn. Empty archives, duplicate identifiers or members,
corrupt bodies, inconsistent coverage, invalid aliases and unsupported affected
range forms refuse. OSV schema-valid absent or null aliases mean no aliases;
malformed lists and invalid identifiers are not trimmed or dropped. Diagnostics
identify offending members and records by hashes rather than raw values.
Named npm evidence may include a separate package-less Git supplement.
Qualified Packagist catalogs retain their registry identity; ambiguous default
registry matching is refused.

The strict scan inventory counts physical directory entries before sorting and
uses explicit policy exclusions, rather than treating Git ignore rules as
evidence that an input cannot matter. It binds policy and selected manifest
bytes, mode and file identity. Unresolved requirements, unreadable inputs,
unsupported source forms or an incomplete manifest/lock relationship refuse
before an empty-dependency skip. Supported exact-pin forms include requirements,
pyproject/build requirements, supported Python and npm JSON locks, Go modules,
Gradle locks, Composer locks, and the separately bounded Cargo resolver.
Formats without a qualified complete resolver remain explicitly incomplete;
this change does not qualify every dependency format or package registry.
An actually object-free root may supply structural non-applicability proof.

The native verifier retains the actual source report. The CLI rechecks it before
emission. Every newly written modern verification PASS receipt requires current
root-derived inventory/source proof, including callers that omit details or
mode fields. Receipt publication checks before and after its write, and receipt
consumption rechecks current configured inputs, exact source identities and age.
Report-selected filesystem paths and caller-supplied JSON do not select a
trusted source. Other receipt kinds and failed receipts retain their semantics.
Legacy receipt reading does not establish fresh required source evidence.

## Qualified package queries

Explicit `--online --db DIR` acquires an inventory-bound query snapshot from
the official OSV API, then uses the same read-only consumer. It sends normalized
package names and exact versions; it does not send source files or credentials.
The selected store retains the transcript and root-relative inventory binding.
Missing an explicit store refuses before acquisition. A bare command with
`GETZILLA_OSV_DB=DIR GETZILLA_OSV_ONLINE=1` reads the existing query snapshot;
the environment variable alone never triggers a refresh. Scans, the verifier
and receipt consumption also read only. Without the query selector the store
is read as per-ecosystem catalogs; a report cannot select a fallback source.

The fixed `osv-query:native` source uses `queries/native/snapshot.json` and the
same immutable objects, publisher lock, pending-marker outcome and descriptor
guards as catalogs. Its closed ZIP transcript preserves every exact request
and response, method/URL/status/body hash, all per-object cursor chains and
all returned details. Only fixed POST querybatch and GET validated advisory IDs
at api.osv.dev are allowed, with no redirects. Missing results, unfinished or
repeated cursors, inconsistent IDs/full modified timestamps, malformed aliases,
unsupported consumed ranges or an over-cap detail census refuse the complete
refresh. No advisory placeholder is substituted after the existing300-detail
limit. Query-positive IDs remain findings after validation, even if a local
comparator would return false; ordinary explicit acceptance policy still applies.

Complete negative replies for every submitted object can legitimately have
zero details. That is query coverage, distinct from an empty global ZIP. Only
actually queried records are consumed; unrelated malformed global catalog
records are neither dropped nor repaired. A malformed queried advisory still
refuses. The source does not claim a globally atomic OSV service snapshot.

Source scope binds exact objects, input paths/content hashes/modes and policy
semantics/raw bytes. Its portable digest excludes only machine-local inode
custody; every consumer independently derives fresh local physical custody.
Copying a source to an otherwise identical offline checkout can work, while a
different policy, dependency, declaration or input mode refuses. Acquisition
uses the earliest request clock, not completion time, and copies keep that time.
Current policy/inventory, held store identity and the cooperative deadline are
rechecked at pointer publication. Current configured source and proof are
rechecked at actual final report/receipt write and get, including spills.

The query profile bounds4096 objects,500 per batch,32 pages per object,
128 page requests,300 unique details,1MiB request/metadata,16MiB per response and
64MiB aggregate raw bodies. Central-directory bounds precede member allocation;
remaining response bytes precede transport reads. One cooperative180s deadline
spans acquisition, validation and pre-pointer publication, with socket timeouts
of at most10s or the remaining budget. These do not preempt OS name resolution
or CPU execution; observed deadline overruns cannot publish a fresh result.
No retries or arbitrary caller-provided endpoints are introduced.

The low-level `query_online` observation helper retains its original API and
does not qualify its responses as a transcript. Existing native updater catalog
operations stay separate. Retained inactive expanded-profile consumers are not
activated by this source kind, and their closed source descriptors are unchanged.

## Bounds and platforms

Transport permits at most three redirects, ten seconds for a blocking operation
and a cooperative total download budget of 90 seconds, with a 1 GiB body cap.
Archive guards bound the central directory to 128 MiB, members to one million,
each member to 16 MiB and expanded bytes to 4 GiB. A store operation has a
cumulative read budget, checked against file size before reading. Inventory is
bounded to 100000 entries, depth 64, 4096 inputs, 32 MiB of input bytes and a
1 MiB proof. Parsing is bounded by these sizes; it has no preemptive CPU-time
guarantee. An external refresh deadline does not turn an uncertain publication
into an unchanged-old-pointer assertion.

Store I/O requires POSIX directory descriptors, no-follow opens, single-link
regular files and safe current-user/root ownership and write modes throughout
physical ancestry. Shared writable non-sticky ancestors refuse. Windows store
I/O has an explicit unavailable result and remains unqualified. These checks
cannot isolate a hostile process with the same UID or root privileges.

## Migration and remaining qualification

Existing legacy mirrors intentionally refuse. A future separately authorized
official acquisition must use this same producer/publication path, all actually
required ecosystems and a safe dedicated target; copying old bytes or touching
their timestamps is insufficient. No real acquisition was performed during
this source change. The previously inspected public OSV advisory with a
comma-containing alias still makes a whole affected feed incomplete; a fresh
ZIP is not assumed to repair it. Records must not be silently removed or
normalized. Exact-package acquisition would require a separately specified
whole-inventory coverage contract.

Full native refresh/consumer integration, current platform checks, real public feed
qualification, independent authority, and final local/external gates remain
required. Original EPSS prediction-date and other-feed obligations remain open;
retained inactive helper APIs do not activate or qualify KEV, EPSS, Trivy or an
expanded security profile. Source implementation alone closes neither #314
nor #326 or their dependent acceptance criteria.
